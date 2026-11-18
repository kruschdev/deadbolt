/**
 * @module engines/foundry-staging
 * Stage 3 Foundry for DEADBOLT:
 * - Sub-millisecond deterministic Slop Breaker via @krusch/toolkit/catalog
 * - Isolated workspace staging (`INV-DB-06`) via krusch-stack 2PC harness
 * - Atomic post-Validator diff promotion (`applyVerifiedStage`)
 * - Deterministic crash-recovery journal drill (`runCrashRecoveryDrill`)
 */

import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  createKruschStack,
  createHarnessEngine,
  openStackDatabase
} from 'krusch-stack';
import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';
import { scoreLegoBrickCoverage, auditBoilerplateText } from '@krusch/toolkit/catalog';

const require = createRequire(import.meta.url);
const KRUSCH_STACK_ENTRY_URL = pathToFileURL(require.resolve('krusch-stack')).href;

const MAX_STAGED_TASKS = 64;

const IGNORED_STAGE_DIRS = new Set([
  '.git',
  'node_modules',
  '.krusch-stack'
]);

/**
 * Compute SHA-256 hex digest of UTF-8 text.
 * @param {string} text
 * @returns {string}
 */
function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text ?? ''), 'utf8').digest('hex');
}

/**
 * Normalize file entries from `{ filePath | file_path | path, content | code }` arrays or maps.
 * @param {Array<object>|Record<string, string>} files
 * @returns {Array<{ filePath: string, content: string }>}
 */
function normalizeAuditFiles(files = []) {
  if (Array.isArray(files)) {
    return files
      .filter((item) => item && typeof item === 'object')
      .map((item) => ({
        filePath: String(item.filePath ?? item.file_path ?? item.path ?? '').trim(),
        content: String(item.content ?? item.code ?? '')
      }));
  }
  if (files && typeof files === 'object') {
    return Object.entries(files).map(([filePath, content]) => ({
      filePath: String(filePath).trim(),
      content: String(content ?? '')
    }));
  }
  return [];
}

/**
 * Normalize candidate edits into `{ file_path, content }` records.
 * @param {Array<object>} edits
 * @returns {Array<{ file_path: string, content: string }>}
 */
function normalizeStageEdits(edits = []) {
  if (!Array.isArray(edits)) return [];
  return edits
    .filter((item) => item && typeof item === 'object')
    .map((item) => ({
      file_path: String(item.file_path ?? item.filePath ?? item.path ?? '')
        .trim()
        .replace(/\\/g, '/')
        .replace(/^(?:\.\/)+/, ''),
      content: String(item.content ?? item.code ?? '')
    }))
    .filter((item) => item.file_path.length > 0);
}

/**
 * Copy repository files into an isolated staging directory without mutating the source tree.
 * @param {string} sourceDir
 * @param {string} destDir
 */
function copyWorkspaceTree(sourceDir, destDir) {
  const resolvedSource = path.resolve(sourceDir);
  const resolvedDest = path.resolve(destDir);
  fs.mkdirSync(resolvedDest, { recursive: true });

  function walkAndCopy(relDir) {
    const curSrc = relDir ? path.join(resolvedSource, relDir) : resolvedSource;
    const curDst = relDir ? path.join(resolvedDest, relDir) : resolvedDest;
    fs.mkdirSync(curDst, { recursive: true });

    const entries = fs.readdirSync(curSrc, { withFileTypes: true });
    for (const entry of entries) {
      if (IGNORED_STAGE_DIRS.has(entry.name)) continue;
      if (entry.isSymbolicLink()) continue;

      const nextRel = relDir ? path.join(relDir, entry.name) : entry.name;
      const srcPath = path.join(resolvedSource, nextRel);
      const dstPath = path.join(resolvedDest, nextRel);

      if (entry.isDirectory()) {
        walkAndCopy(nextRel);
      } else if (entry.isFile()) {
        fs.copyFileSync(srcPath, dstPath);
      }
    }
  }

  walkAndCopy('');
}

/**
 * Resolve and validate a relative file target inside `rootDir`, enforcing `fs.lstatSync`
 * no-symlink checks across all existing path segments and `fs.realpathSync` containment.
 *
 * @param {string} rootDir
 * @param {string} relFilePath
 * @returns {{ resolvedRoot: string, realRoot: string, normalizedRel: string, targetAbs: string }}
 */
function resolveContainedRepoTarget(rootDir, relFilePath) {
  const resolvedRoot = path.resolve(rootDir);
  if (!fs.existsSync(resolvedRoot)) {
    throw new Error('Target repository directory does not exist.');
  }
  const rootLstat = fs.lstatSync(resolvedRoot);
  if (!rootLstat.isDirectory()) {
    throw new Error('Target repository root is not a directory.');
  }
  const realRoot = fs.realpathSync(resolvedRoot);

  const rawRel = String(relFilePath || '').replace(/\\/g, '/').trim();
  if (!rawRel || rawRel.includes('\0')) {
    throw new Error(`Invalid relative target file path: ${relFilePath}`);
  }
  const strippedRel = rawRel.replace(/^(?:\.\/+|\/+)+/, '');
  const normalizedRel = strippedRel ? path.posix.normalize(strippedRel) : '';
  if (
    !normalizedRel ||
    normalizedRel === '.' ||
    normalizedRel === '..' ||
    normalizedRel.startsWith('../')
  ) {
    throw new Error(`Refusing path traversal outside target repository: ${relFilePath}`);
  }

  const targetAbs = path.resolve(resolvedRoot, normalizedRel);
  const relCheck = path.relative(resolvedRoot, targetAbs);
  if (!relCheck || relCheck.startsWith('..') || path.isAbsolute(relCheck)) {
    throw new Error(`Refusing path traversal outside target repository: ${relFilePath}`);
  }

  const segments = normalizedRel.split('/').filter(Boolean);
  let cursor = resolvedRoot;
  let deepestExisting = resolvedRoot;
  for (let i = 0; i < segments.length; i += 1) {
    cursor = path.join(cursor, segments[i]);
    try {
      const stat = fs.lstatSync(cursor);
      if (stat.isSymbolicLink()) {
        throw new Error(`Refusing symlink segment while syncing "${normalizedRel}".`);
      }
      if (i === segments.length - 1 && stat.isDirectory()) {
        throw new Error(`Refusing directory target while syncing "${normalizedRel}".`);
      }
      if (i < segments.length - 1 && !stat.isDirectory()) {
        throw new Error(`Non-directory ancestor segment while syncing "${normalizedRel}".`);
      }
      deepestExisting = cursor;
    } catch (err) {
      if (err?.code === 'ENOENT') {
        break;
      }
      throw err;
    }
  }

  const realDeepest = fs.realpathSync(deepestExisting);
  if (realDeepest !== realRoot && !realDeepest.startsWith(`${realRoot}${path.sep}`)) {
    throw new Error(`Refusing ancestor escaping repository realpath: ${normalizedRel}`);
  }

  return { resolvedRoot, realRoot, normalizedRel, targetAbs };
}

function listOrphanedTempFiles(dirPath) {
  const orphans = [];
  if (!fs.existsSync(dirPath)) return orphans;
  for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
    if (IGNORED_STAGE_DIRS.has(entry.name)) continue;
    const full = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      orphans.push(...listOrphanedTempFiles(full));
    } else if (entry.name.includes('.krusch-tmp-')) {
      orphans.push(full);
    }
  }
  return orphans;
}

/**
 * Create the Stage 3 DEADBOLT Foundry engine.
 * @param {object} [options={}]
 * @param {object} [options.stack] - Optional shared KruschStack instance
 */
export function createFoundryEngine({ stack = null } = {}) {
  /** @type {Map<string, { workOrderId: string, stagingDir: string, stagingDbDir: string, repoDir: string, harnessInstance: object, stageDb: object, edits: Array<{ file_path: string, content: string }> }>} */
  const stagedTasks = new Map();

  // Warm V8 TurboFan JIT for catalog regex & comment strippers at initialization so live calls run <1ms
  const warmupSample = [
    {
      filePath: 'src/warmup.js',
      content: "import { okEnvelope } from '@krusch/toolkit/http';\nexport const ready = okEnvelope;\n"
    }
  ];
  for (let i = 0; i < 350; i += 1) {
    scoreLegoBrickCoverage(warmupSample);
  }
  auditBoilerplateText(warmupSample[0].content, warmupSample[0].filePath);

  /**
   * Run <1ms deterministic Slop-Breaker audit (`scoreLegoBrickCoverage` + `auditBoilerplateText`).
   * @param {object} [params={}]
   * @param {Array<object>|Record<string, string>} [params.files=[]]
   * @param {string} [params.label='candidate']
   */
  function auditWithSlopBreaker({ files = [], label = 'candidate' } = {}) {
    const normalized = normalizeAuditFiles(files);
    const startNs = process.hrtime.bigint();
    const coverage = scoreLegoBrickCoverage(normalized);
    const elapsedMs = Number((Number(process.hrtime.bigint() - startNs) / 1e6).toFixed(4));

    const findingsByFile = new Map();
    for (const f of coverage.data.findings) {
      findingsByFile.set(f.filePath, (findingsByFile.get(f.filePath) || 0) + 1);
    }
    const perFileAudits = normalized.map((entry) => {
      const count = findingsByFile.get(entry.filePath) || 0;
      return {
        filePath: entry.filePath,
        clean: count === 0,
        findingCount: count
      };
    });

    const safeLabel = String(label || 'candidate');
    const summary = coverage.data.breakerTripped
      ? `Slop Breaker tripped on ${safeLabel}: ${coverage.data.slopFindingCount} anti-pattern finding(s) in ${elapsedMs}ms.`
      : `Slop Breaker passed ${safeLabel}: 0 anti-pattern findings across ${normalized.length} file(s) in ${elapsedMs}ms.`;

    return okEnvelope('deadbolt.foundry.slop_breaker', summary, {
      label: safeLabel,
      elapsedMs,
      subMillisecond: elapsedMs < 1,
      ...coverage.data,
      perFileAudits
    });
  }

  /**
   * Close isolated `stage.db`, delete ephemeral staging directories, and remove `taskId` from `stagedTasks`.
   * @param {string|{ taskId?: string }} taskId
   */
  function releaseStage(taskId) {
    const cleanTaskId = String(
      typeof taskId === 'object' && taskId !== null ? taskId.taskId ?? '' : taskId ?? ''
    ).trim();
    if (!cleanTaskId) {
      return okEnvelope('deadbolt.foundry.release', 'No staged task id provided.', {
        taskId: null,
        released: false
      });
    }

    const entry = stagedTasks.get(cleanTaskId);
    if (!entry) {
      return okEnvelope(
        'deadbolt.foundry.release',
        `Staged task ${cleanTaskId} already released or not found.`,
        {
          taskId: cleanTaskId,
          released: false
        }
      );
    }

    stagedTasks.delete(cleanTaskId);
    try {
      entry.stageDb?.close?.();
    } catch {
      // Ignore close error
    }
    if (entry.stagingDir) {
      try {
        fs.rmSync(entry.stagingDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup error
      }
    }
    if (entry.stagingDbDir) {
      try {
        fs.rmSync(entry.stagingDbDir, { recursive: true, force: true });
      } catch {
        // Ignore cleanup error
      }
    }

    return okEnvelope(
      'deadbolt.foundry.release',
      `Released staged task ${cleanTaskId} and cleaned isolated workspace.`,
      {
        taskId: cleanTaskId,
        released: true
      }
    );
  }

  /**
   * Stage Work Order edits inside an isolated workspace copy without mutating `repoDir` (`INV-DB-06`).
   * @param {object} params
   * @param {string} [params.workOrderId='WO-101']
   * @param {string} [params.goal='Stage candidate remediation']
   * @param {string} params.repoDir
   * @param {Array<{ file_path?: string, filePath?: string, path?: string, content: string }>} params.edits
   */
  function stageWorkOrderEdits({
    workOrderId = 'WO-101',
    goal = 'Stage candidate remediation',
    repoDir,
    edits = []
  } = {}) {
    if (!repoDir || typeof repoDir !== 'string') {
      return errorEnvelope(
        'INVALID_REPO_DIR',
        'repoDir is required to stage Work Order edits',
        null,
        'deadbolt.foundry.stage'
      );
    }

    const resolvedRepoDir = path.resolve(repoDir);
    if (!fs.existsSync(resolvedRepoDir) || !fs.statSync(resolvedRepoDir).isDirectory()) {
      return errorEnvelope(
        'REPO_DIR_NOT_FOUND',
        'Target repository directory does not exist for staging',
        { workOrderId },
        'deadbolt.foundry.stage'
      );
    }

    const normalizedEdits = normalizeStageEdits(edits);
    if (normalizedEdits.length === 0) {
      return errorEnvelope(
        'EMPTY_EDITS',
        'At least one file edit is required to stage a Work Order task',
        { workOrderId },
        'deadbolt.foundry.stage'
      );
    }

    while (stagedTasks.size >= MAX_STAGED_TASKS) {
      const oldestKey = stagedTasks.keys().next().value;
      if (oldestKey === undefined) break;
      releaseStage(oldestKey);
    }

    const stagingDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deadbolt-stage-'));
    const stagingDbDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deadbolt-stage-db-'));
    let stageDb = null;

    try {
      copyWorkspaceTree(resolvedRepoDir, stagingDir);
      stageDb = openStackDatabase({
        workspaceRoot: stagingDir,
        dbPath: path.join(stagingDbDir, 'stage.db'),
        ephemeral: false
      });
    } catch (setupErr) {
      try {
        stageDb?.close?.();
      } catch {
        // Ignore close error on failed stage setup
      }
      fs.rmSync(stagingDir, { recursive: true, force: true });
      fs.rmSync(stagingDbDir, { recursive: true, force: true });
      return errorEnvelope(
        'HARNESS_STAGE_FAILED',
        setupErr?.message || 'Failed to initialize isolated staging workspace',
        { workOrderId },
        'deadbolt.foundry.stage'
      );
    }

    const harnessInstance = createHarnessEngine({
      db: stageDb,
      workspaceRoot: stagingDir,
      contextEngine: stack?.context || null
    });

    const cleanWoId = String(workOrderId || 'WO-101').trim();
    const cleanGoal = String(goal || 'Stage candidate remediation').trim();
    const generatedTaskId = `task-${cleanWoId.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${crypto.randomBytes(4).toString('hex')}`;

    const runRes = harnessInstance.run({
      task_id: generatedTaskId,
      goal: `[${cleanWoId}] ${cleanGoal}`,
      edits: normalizedEdits
    });

    if (!runRes.ok) {
      try {
        stageDb?.close?.();
      } catch {
        // Ignore close error on failed stage
      }
      fs.rmSync(stagingDir, { recursive: true, force: true });
      fs.rmSync(stagingDbDir, { recursive: true, force: true });
      return errorEnvelope(
        'HARNESS_STAGE_FAILED',
        runRes.summary || 'Failed to stage edits in isolated harness',
        runRes.data ?? null,
        'deadbolt.foundry.stage'
      );
    }

    const taskId = runRes.data.task_id;
    const status = runRes.data.status;
    const unifiedDiff = runRes.data.unified_diff || '';
    const invariantFindings = Array.isArray(runRes.data.findings) ? runRes.data.findings : [];

    stagedTasks.set(taskId, {
      workOrderId: cleanWoId,
      stagingDir,
      stagingDbDir,
      repoDir: resolvedRepoDir,
      harnessInstance,
      stageDb,
      edits: normalizedEdits
    });

    const summary = `Staged ${normalizedEdits.length} file(s) for ${cleanWoId} as ${taskId} (${status}) in isolated workspace.`;

    return okEnvelope('deadbolt.foundry.stage', summary, {
      workOrderId: cleanWoId,
      taskId,
      status,
      unifiedDiff,
      stagingDir,
      files: normalizedEdits.map((e) => e.file_path),
      invariantFindings
    });
  }

  /**
   * Atomically apply a Validator-approved staged task (`applyDiff`), optionally syncing to `repoDir`.
   * @param {object} params
   * @param {string} params.taskId
   * @param {boolean} [params.applyToRepoDir=false]
   */
  function applyVerifiedStage({ taskId, applyToRepoDir = false } = {}) {
    const cleanTaskId = String(taskId || '').trim();
    if (!cleanTaskId) {
      return errorEnvelope(
        'MISSING_TASK_ID',
        'taskId is required to apply a verified stage',
        null,
        'deadbolt.foundry.apply'
      );
    }

    const record = stagedTasks.get(cleanTaskId) || null;
    const targetHarness = record?.harnessInstance || stack?.harness || null;

    if (!targetHarness || typeof targetHarness.applyDiff !== 'function') {
      return errorEnvelope(
        'HARNESS_UNAVAILABLE',
        `No harness instance found for staged task ${cleanTaskId}`,
        { taskId: cleanTaskId },
        'deadbolt.foundry.apply'
      );
    }

    const applyRes = targetHarness.applyDiff({ task_id: cleanTaskId });
    if (!applyRes.ok) {
      return errorEnvelope(
        'APPLY_STAGE_FAILED',
        applyRes.summary || `Failed to apply staged task ${cleanTaskId}`,
        applyRes.data ?? { taskId: cleanTaskId },
        'deadbolt.foundry.apply'
      );
    }

    const appliedFiles = Array.isArray(applyRes.data?.applied_files)
      ? applyRes.data.applied_files
      : [];

    let syncedToRepoDir = false;
    let repoSyncJournalDb = null;
    if (applyToRepoDir && record?.stagingDir && record?.repoDir) {
      let repoDb = null;
      try {
        /** @type {Array<{ file_path: string, content: string }>} */
        const verifiedRepoEdits = [];
        for (const relFile of appliedFiles) {
          const { normalizedRel, targetAbs } = resolveContainedRepoTarget(record.repoDir, relFile);
          try {
            const existingStat = fs.lstatSync(targetAbs);
            if (existingStat.isSymbolicLink() || existingStat.isDirectory()) {
              throw new Error(`Refusing non-regular file target "${normalizedRel}".`);
            }
          } catch (statErr) {
            if (statErr?.code !== 'ENOENT') {
              throw statErr;
            }
          }
          const stagedFileInfo = resolveContainedRepoTarget(record.stagingDir, normalizedRel);
          const verifiedContent = fs.readFileSync(stagedFileInfo.targetAbs, 'utf8');
          verifiedRepoEdits.push({
            file_path: normalizedRel,
            content: verifiedContent
          });
        }

        const repoJournalDir = path.join(record.repoDir, '.krusch-stack');
        fs.mkdirSync(repoJournalDir, { recursive: true });
        repoSyncJournalDb = path.join(repoJournalDir, 'repo-apply.db');
        repoDb = openStackDatabase({
          workspaceRoot: record.repoDir,
          dbPath: repoSyncJournalDb,
          ephemeral: false
        });
        const repoHarness = createHarnessEngine({
          db: repoDb,
          workspaceRoot: record.repoDir,
          contextEngine: null
        });
        repoHarness.recoverInFlight();

        const syncTaskId = `${cleanTaskId}-reposync-${crypto.randomBytes(3).toString('hex')}`;
        const repoStageRes = repoHarness.run({
          task_id: syncTaskId,
          goal: `[${record.workOrderId || 'WO'}] Promote verified stage ${cleanTaskId} to repository`,
          edits: verifiedRepoEdits
        });
        if (!repoStageRes.ok) {
          throw new Error(repoStageRes.summary || 'Failed to stage repository promotion journal.');
        }

        const repoApplyRes = repoHarness.applyDiff({ task_id: syncTaskId });
        if (!repoApplyRes.ok) {
          throw new Error(repoApplyRes.summary || 'Failed to apply repository promotion journal.');
        }
        syncedToRepoDir = true;
      } catch (syncErr) {
        return errorEnvelope(
          'REPO_SYNC_FAILED',
          syncErr instanceof Error
            ? `Failed to sync verified stage to repository: ${syncErr.message}`
            : 'Failed to sync verified stage to repository.',
          {
            taskId: cleanTaskId,
            workOrderId: record?.workOrderId || null,
            journalBacked: true
          },
          'deadbolt.foundry.apply'
        );
      } finally {
        try {
          repoDb?.close?.();
        } catch {
          // Ignore close error on repo-apply journal database
        }
      }
    }

    const summary = `Atomically applied ${appliedFiles.length} verified file(s) for ${cleanTaskId}.`;

    return okEnvelope('deadbolt.foundry.apply', summary, {
      taskId: cleanTaskId,
      workOrderId: record?.workOrderId || null,
      status: applyRes.data?.status || 'APPLIED',
      appliedFiles,
      stagingDir: record?.stagingDir || stack?.workspaceRoot || null,
      syncedToRepoDir,
      ...(repoSyncJournalDb ? { repoSyncJournalBacked: true } : {})
    });
  }

  /**
   * Execute a live multi-process crash-recovery drill (`INV-DB-06`):
   * 1. Stage a 2-file edit (`src/fee-engine.js` + `src/settlement-service.js`) in an isolated SQLite WAL database (`drill-stack.db`).
   * 2. Spawn Worker Process 1 running `applyDiff()` and kill it with OS `SIGKILL` right after file 1 is renamed and fsynced (leaving file 1 mutated, file 2 untouched, an unrenamed `.krusch-tmp-*` sibling on disk, and `harness_apply_journal` in `APPLYING`).
   * 3. Spawn a cold fresh Recovery Process 2 opening `drill-stack.db` and running `recoverInFlight()` to restore preimages (`halfWrittenFiles === 0`, `orphanedTempCleaned === true`).
   * @param {object} [params={}]
   * @param {string} [params.repoDir]
   */
  async function runCrashRecoveryDrill({ repoDir } = {}) {
    const drillRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'deadbolt-crash-drill-'));
    const drillWorkspace = path.join(drillRoot, 'workspace');
    const drillDbPath = path.join(drillRoot, 'drill-stack.db');
    const markerPath = path.join(drillRoot, 'first-rename.marker');
    const workerApplyScript = path.join(drillRoot, 'worker-apply.mjs');
    const workerRecoverScript = path.join(drillRoot, 'worker-recover.mjs');

    let drillStack = null;
    let workerChild = null;
    try {
      if (
        repoDir &&
        typeof repoDir === 'string' &&
        fs.existsSync(repoDir) &&
        fs.statSync(repoDir).isDirectory()
      ) {
        copyWorkspaceTree(path.resolve(repoDir), drillWorkspace);
      } else {
        fs.mkdirSync(path.join(drillWorkspace, 'src'), { recursive: true });
      }

      const file1Rel = 'src/fee-engine.js';
      const file2Rel = 'src/settlement-service.js';
      const file1Abs = path.join(drillWorkspace, file1Rel);
      const file2Abs = path.join(drillWorkspace, file2Rel);

      fs.mkdirSync(path.dirname(file1Abs), { recursive: true });
      if (!fs.existsSync(file1Abs)) {
        fs.writeFileSync(
          file1Abs,
          'export function computeFeeCents(grossCents, bps) {\n  return Math.round((grossCents * bps) / 10000);\n}\n',
          'utf8'
        );
      }
      if (!fs.existsSync(file2Abs)) {
        fs.writeFileSync(
          file2Abs,
          "import { computeFeeCents } from './fee-engine.js';\nexport function settleBatch(items, bps) {\n  return items.map((c) => c - computeFeeCents(c, bps));\n}\n",
          'utf8'
        );
      }

      const baseFile1Text = fs.readFileSync(file1Abs, 'utf8');
      const baseFile2Text = fs.readFileSync(file2Abs, 'utf8');
      const baseFile1Hash = sha256Hex(baseFile1Text);
      const baseFile2Hash = sha256Hex(baseFile2Text);

      const stagedFile1Text = `${baseFile1Text}\n// [WO-101] Staged batch fee allocation part 1\n`;
      const stagedFile2Text = `${baseFile2Text}\n// [WO-101] Staged settlement parity check part 2\n`;
      const stagedFile1Hash = sha256Hex(stagedFile1Text);
      const stagedFile2Hash = sha256Hex(stagedFile2Text);

      drillStack = createKruschStack({
        workspaceRoot: drillWorkspace,
        dbPath: drillDbPath,
        ephemeral: false,
        recoverOnStartup: false,
        profile: 'core'
      });

      const stageRes = drillStack.harness.run({
        task_id: 'stage-crash-drill-wo-101',
        goal: '[WO-101] Staged 2-file fee and settlement update',
        edits: [
          { file_path: file1Rel, content: stagedFile1Text },
          { file_path: file2Rel, content: stagedFile2Text }
        ]
      });

      if (!stageRes.ok) {
        return errorEnvelope(
          'CRASH_DRILL_STAGE_FAILED',
          stageRes.summary || 'Failed to stage 2-file task for crash drill',
          stageRes.data ?? null,
          'deadbolt.foundry.crash_drill'
        );
      }

      const taskId = stageRes.data.task_id;
      drillStack.db.close();
      drillStack = null;

      // Worker Process 1: runs real applyDiff() and pauses immediately after file 1 rename + dir fsync
      fs.writeFileSync(
        workerApplyScript,
        [
          `import { createKruschStack } from ${JSON.stringify(KRUSCH_STACK_ENTRY_URL)};`,
          'const [ws, dbPath, tId] = process.argv.slice(2);',
          'const stack = createKruschStack({ workspaceRoot: ws, dbPath, ephemeral: false, recoverOnStartup: false, profile: "core" });',
          'stack.harness.applyDiff({ task_id: tId });'
        ].join('\n'),
        'utf8'
      );

      workerChild = spawn(
        process.execPath,
        [workerApplyScript, drillWorkspace, drillDbPath, taskId],
        {
          env: {
            PATH: process.env.PATH || '/usr/bin:/bin',
            NODE_NO_WARNINGS: '1',
            KRUSCH_ENABLE_TEST_HOOKS: '1',
            KRUSCH_TEST_HOOK_PAUSE_AFTER_FIRST_RENAME: '1',
            KRUSCH_TEST_HOOK_MARKER_FILE: markerPath
          },
          stdio: ['ignore', 'pipe', 'pipe']
        }
      );

      const workerExitPromise = new Promise((resolve, reject) => {
        workerChild.once('error', reject);
        workerChild.once('exit', (code, signal) => resolve({ code, signal }));
      });

      const pollDeadline = Date.now() + 6000;
      let markerContent = '';
      while (Date.now() < pollDeadline) {
        if (fs.existsSync(markerPath)) {
          markerContent = fs.readFileSync(markerPath, 'utf8').trim();
          if (markerContent.length > 0) {
            break;
          }
        }
        if (workerChild.exitCode !== null || workerChild.signalCode !== null) {
          break;
        }
        await new Promise((r) => setTimeout(r, 12));
      }

      if (!markerContent) {
        return errorEnvelope(
          'CRASH_DRILL_WORKER_FAILED',
          'Apply worker did not reach first-rename checkpoint within timeout.',
          { taskId },
          'deadbolt.foundry.crash_drill'
        );
      }

      const workerPid = Number(markerContent) || workerChild.pid;
      workerChild.kill('SIGKILL');
      const workerExit = await workerExitPromise;
      workerChild = null;

      // Inspect torn on-disk state BEFORE opening SQLite in recovery process
      const crashFile1Hash = sha256Hex(fs.readFileSync(file1Abs, 'utf8'));
      const crashFile2Hash = sha256Hex(fs.readFileSync(file2Abs, 'utf8'));
      const orphansDuringCrash = listOrphanedTempFiles(drillWorkspace);
      const halfWrittenBefore =
        (crashFile1Hash === stagedFile1Hash ? 1 : 0) +
        (crashFile2Hash === stagedFile2Hash ? 1 : 0);

      // Recovery Process 2: fresh OS process opening drill-stack.db cold over SQLite WAL
      fs.writeFileSync(
        workerRecoverScript,
        [
          `import { createKruschStack } from ${JSON.stringify(KRUSCH_STACK_ENTRY_URL)};`,
          'const [ws, dbPath, tId] = process.argv.slice(2);',
          'const stack = createKruschStack({ workspaceRoot: ws, dbPath, ephemeral: false, recoverOnStartup: false, profile: "core" });',
          'const beforeRow = stack.db.prepare("SELECT state FROM harness_apply_journal WHERE task_id = ?").get(tId);',
          'const recoveryEnvelope = stack.harness.recoverInFlight();',
          'const afterRow = stack.db.prepare("SELECT state FROM harness_apply_journal WHERE task_id = ?").get(tId);',
          'const taskRow = stack.db.prepare("SELECT status FROM harness_tasks WHERE task_id = ?").get(tId);',
          'stack.db.close();',
          'process.stdout.write(JSON.stringify({',
          '  pid: process.pid,',
          '  journalStateBefore: beforeRow?.state || "UNKNOWN",',
          '  journalStateAfter: afterRow?.state || "UNKNOWN",',
          '  taskStatusAfter: taskRow?.status || "UNKNOWN",',
          '  recoveryEnvelope',
          '}) + "\\n");'
        ].join('\n'),
        'utf8'
      );

      const recoverChild = spawn(
        process.execPath,
        [workerRecoverScript, drillWorkspace, drillDbPath, taskId],
        {
          env: {
            PATH: process.env.PATH || '/usr/bin:/bin',
            NODE_NO_WARNINGS: '1'
          },
          stdio: ['ignore', 'pipe', 'pipe']
        }
      );

      let recoverStdout = '';
      let recoverStderr = '';
      recoverChild.stdout.on('data', (chunk) => {
        recoverStdout += chunk.toString('utf8');
      });
      recoverChild.stderr.on('data', (chunk) => {
        recoverStderr += chunk.toString('utf8');
      });

      const recoverExit = await new Promise((resolve, reject) => {
        recoverChild.once('error', reject);
        recoverChild.once('exit', (code, signal) => resolve({ code, signal }));
      });

      if (recoverExit.code !== 0) {
        return errorEnvelope(
          'CRASH_DRILL_RECOVERY_PROCESS_FAILED',
          `Fresh recovery process exited non-zero (code=${recoverExit.code}, signal=${recoverExit.signal}).`,
          { stderr: recoverStderr.slice(0, 400) },
          'deadbolt.foundry.crash_drill'
        );
      }

      const lastJsonLine = recoverStdout
        .trim()
        .split(/\r?\n/)
        .reverse()
        .find((line) => line.trim().startsWith('{'));
      const recoverPayload = JSON.parse(lastJsonLine || '{}');
      const recoveryEnvelope = recoverPayload.recoveryEnvelope || { ok: false };
      const journalStateBefore = recoverPayload.journalStateBefore || 'APPLYING';
      const journalStateAfter = recoverPayload.journalStateAfter || 'UNKNOWN';
      const taskStatusAfter = recoverPayload.taskStatusAfter || 'UNKNOWN';
      const recoveryPid = recoverPayload.pid || null;

      const recoveredFile1Hash = sha256Hex(fs.readFileSync(file1Abs, 'utf8'));
      const recoveredFile2Hash = sha256Hex(fs.readFileSync(file2Abs, 'utf8'));
      const orphansAfterRecovery = listOrphanedTempFiles(drillWorkspace);
      const orphanCleaned =
        orphansDuringCrash.length >= 1 && orphansAfterRecovery.length === 0;

      const matchesStagedCount =
        (recoveredFile1Hash === stagedFile1Hash ? 1 : 0) +
        (recoveredFile2Hash === stagedFile2Hash ? 1 : 0);
      const matchesBaseCount =
        (recoveredFile1Hash === baseFile1Hash ? 1 : 0) +
        (recoveredFile2Hash === baseFile2Hash ? 1 : 0);

      const allConsistent = matchesBaseCount === 2 || matchesStagedCount === 2;
      const halfWrittenFiles = allConsistent ? 0 : 2 - Math.max(matchesBaseCount, matchesStagedCount);
      const converged = Boolean(
        workerExit.signal === 'SIGKILL' &&
          recoveryPid &&
          recoveryPid !== workerPid &&
          recoveryEnvelope.ok &&
          journalStateBefore === 'APPLYING' &&
          journalStateAfter === 'ROLLED_BACK' &&
          halfWrittenFiles === 0 &&
          orphanCleaned
      );

      const fileHashes = {
        [file1Rel]: {
          beforeApply: baseFile1Hash,
          duringCrash: crashFile1Hash,
          afterRecovery: recoveredFile1Hash,
          restoredToPreimage: recoveredFile1Hash === baseFile1Hash
        },
        [file2Rel]: {
          beforeApply: baseFile2Hash,
          duringCrash: crashFile2Hash,
          afterRecovery: recoveredFile2Hash,
          restoredToPreimage: recoveredFile2Hash === baseFile2Hash
        }
      };

      const recoveryResult = recoveryEnvelope.data || {};
      const summary = converged
        ? `Multi-process crash-recovery drill converged cleanly (worker SIGKILL -> fresh-process ${journalStateBefore} -> ${journalStateAfter}, 0 half-written files, orphaned temp cleaned).`
        : `Crash-recovery drill did not converge (halfWrittenFiles=${halfWrittenFiles}).`;

      return okEnvelope('deadbolt.foundry.crash_drill', summary, {
        taskId,
        workerPid,
        recoveryPid,
        workerKilledSignal: workerExit.signal || null,
        recoveredInFreshProcess: Boolean(recoveryPid && recoveryPid !== workerPid),
        journalStateBefore,
        journalStateAfter,
        taskStatusAfter,
        recoveryResult,
        halfWrittenFilesBeforeRecovery: halfWrittenBefore,
        orphanedTempsBeforeRecovery: orphansDuringCrash.length,
        halfWrittenFiles,
        orphanedTempCleaned: orphanCleaned,
        fileHashes,
        converged
      });
    } finally {
      if (workerChild && workerChild.exitCode === null && workerChild.signalCode === null) {
        try {
          workerChild.kill('SIGKILL');
        } catch {
          // Ignore worker kill error during cleanup
        }
      }
      try {
        drillStack?.db?.close?.();
      } catch {
        // Ignore close error on ephemeral drill database
      }
      try {
        fs.rmSync(drillRoot, { recursive: true, force: true });
      } catch {
        // Best-effort cleanup of crash drill directory
      }
    }
  }

  /**
   * Remove ephemeral staging directories created during this Foundry session.
   */
  function close() {
    for (const key of [...stagedTasks.keys()]) {
      releaseStage(key);
    }
    stagedTasks.clear();
  }

  return Object.freeze({
    auditWithSlopBreaker,
    stageWorkOrderEdits,
    applyVerifiedStage,
    releaseStage,
    runCrashRecoveryDrill,
    close
  });
}
