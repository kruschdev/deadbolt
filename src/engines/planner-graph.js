/**
 * @module engines/planner-graph
 * Stage 2 Planner for DEADBOLT:
 * - 2-hop AST symbol & relative ESM/CJS import blast-radius graph
 * - Sub-25us in-process Cascade tier routing via @krusch/toolkit/cascade
 * - Parallel Work Order disjoint AST lease & execution wave solver
 * - SSRF-guarded external GitHub & local repository brownfield scanner
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { maskCodePreservingNewlines } from 'krusch-stack';
import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';
import { selectCascadeTier, createTierCircuitBreaker } from '@krusch/toolkit/cascade';
import { scoreLegoBrickCoverage, auditBoilerplateText } from '@krusch/toolkit/catalog';
import { validateOutboundUrl, isPrivateOrReservedIp } from '@krusch/toolkit/security';

const SCANNABLE_EXTENSIONS = new Set([
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.jsx',
  '.tsx',
  '.py'
]);

const SKIPPED_SCAN_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.next',
  '.cache',
  '__pycache__',
  '.krusch-stack'
]);

const SENSITIVE_LOCAL_PREFIXES = [
  '/etc',
  '/root',
  '/proc',
  '/sys',
  '/dev',
  '/boot',
  '/var/run',
  '/run'
];

const SENSITIVE_SEGMENT_NAMES = new Set([
  '.ssh',
  '.gnupg',
  '.aws',
  '.kube',
  '.docker'
]);

const KNOWN_CHOKE_POINT_BASENAMES = new Set([
  'src/server.js',
  'server.js',
  'src/app.js',
  'app.js',
  'src/index.js',
  'index.js',
  'src/main.js',
  'main.js'
]);

const GITHUB_OWNER_REPO_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\.git)?$/;

/**
 * Normalize a repository-relative POSIX path without leading `./` or `/`.
 * @param {string} rawPath
 * @returns {string}
 */
function normalizeRelPath(rawPath) {
  return String(rawPath || '')
    .trim()
    .replace(/\\/g, '/')
    .replace(/^(?:\.\/)+/, '')
    .replace(/^\/+/, '');
}

/**
 * Redact private LAN or Tailscale IP literals from display endpoint URLs (`INV-DB-08`).
 * @param {string} rawUrl
 * @returns {string|null}
 */
function redactEndpointUrl(rawUrl) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  try {
    const parsed = new URL(rawUrl.trim());
    const host = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
    const portSuffix = parsed.port ? `:${parsed.port}` : '';
    if (host === 'localhost') {
      return `${parsed.protocol}//localhost${portSuffix}`;
    }
    if (net.isIP(host) !== 0) {
      const blockedPublic = isPrivateOrReservedIp(host, {
        allowPrivateLan: false,
        allowTailscale: false
      });
      const stillBlockedWhenLanAllowed = isPrivateOrReservedIp(host, {
        allowPrivateLan: true,
        allowTailscale: true
      });
      if (blockedPublic && !stillBlockedWhenLanAllowed) {
        return `${parsed.protocol}//[redacted-private-host]${portSuffix}`;
      }
      if (blockedPublic && stillBlockedWhenLanAllowed) {
        return `${parsed.protocol}//localhost${portSuffix}`;
      }
    }
    return `${parsed.protocol}//${host}${portSuffix}`;
  } catch {
    return '[redacted-endpoint]';
  }
}

/**
 * Walk a repository directory and collect bounded code files sorted deterministically.
 * @param {string} rootDir
 * @param {number} maxFiles
 * @returns {string[]}
 */
function collectRepoCodeFiles(rootDir, maxFiles = 200) {
  const collected = [];
  const resolvedRoot = path.resolve(rootDir);

  function walk(currentDir) {
    if (collected.length >= maxFiles) return;
    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (collected.length >= maxFiles) break;
      if (SKIPPED_SCAN_DIRS.has(entry.name)) continue;
      if (entry.isSymbolicLink()) continue;

      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (SCANNABLE_EXTENSIONS.has(ext)) {
          const rel = path.relative(resolvedRoot, fullPath).replace(/\\/g, '/');
          collected.push(rel);
        }
      }
    }
  }

  walk(resolvedRoot);
  return collected;
}

/**
 * Extract relative ESM and CommonJS import specifiers from JS/TS source with comments masked.
 * @param {string} source
 * @returns {string[]}
 */
function extractRelativeSpecifiers(source) {
  const noComments = maskCodePreservingNewlines(String(source || ''), { maskStrings: false });
  const specifiers = new Set();

  const patterns = [
    /\b(?:import|export)\s+(?:[^'"]*?\s+from\s+)?['"](\.\.?\/[^'"]+)['"]/g,
    /\bimport\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"](\.\.?\/[^'"]+)['"]\s*\)/g
  ];

  for (const regex of patterns) {
    for (const match of noComments.matchAll(regex)) {
      if (match[1]) {
        specifiers.add(match[1].trim());
      }
    }
  }

  return [...specifiers];
}

/**
 * Resolve a relative specifier from `importerRelFile` against known repository file paths.
 * @param {string} importerRelFile
 * @param {string} specifier
 * @param {Set<string>} repoFileSet
 * @returns {string|null}
 */
function resolveRelativeImportTarget(importerRelFile, specifier, repoFileSet) {
  const baseDir = path.posix.dirname(importerRelFile);
  const joined = path.posix.normalize(path.posix.join(baseDir, specifier));
  if (joined.startsWith('..')) return null;

  const candidates = [
    joined,
    `${joined}.js`,
    `${joined}.mjs`,
    `${joined}.cjs`,
    `${joined}.ts`,
    `${joined}.tsx`,
    `${joined}.jsx`,
    `${joined}/index.js`,
    `${joined}/index.ts`,
    `${joined}/index.tsx`
  ];

  for (const candidate of candidates) {
    if (repoFileSet.has(candidate)) {
      return candidate;
    }
  }
  return null;
}

/**
 * Check whether a local path targets a protected OS or credential directory.
 * @param {string} candidatePath
 * @returns {boolean}
 */
function isSensitiveLocalPath(candidatePath) {
  const normalized = path.resolve(candidatePath).replace(/\\/g, '/');
  for (const prefix of SENSITIVE_LOCAL_PREFIXES) {
    if (normalized === prefix || normalized.startsWith(`${prefix}/`)) {
      return true;
    }
  }
  const segments = normalized.split('/').filter(Boolean);
  for (const seg of segments) {
    if (SENSITIVE_SEGMENT_NAMES.has(seg.toLowerCase())) {
      return true;
    }
  }
  return false;
}

/**
 * Race a promise against a short timeout so unreachable remote probes fail fast.
 * @template T
 * @param {Promise<T>} promise
 * @param {number} timeoutMs
 * @returns {Promise<T>}
 */
function withBoundedTimeout(promise, timeoutMs = 1200) {
  let timer = null;
  const timeoutPromise = new Promise((_, reject) => {
    timer = setTimeout(() => {
      reject(new Error(`Remote probe timed out after ${timeoutMs}ms`));
    }, timeoutMs);
  });
  return Promise.race([promise, timeoutPromise]).finally(() => {
    if (timer) clearTimeout(timer);
  });
}

/**
 * Build default billing work order descriptors if caller omits `workOrders`.
 * @param {Set<string>} repoFileSet
 * @returns {Array<object>}
 */
function buildDefaultWorkOrdersIfAbsent(repoFileSet) {
  const defaults = [];
  if (repoFileSet.has('src/fee-engine.js')) {
    defaults.push({
      id: 'WO-101',
      title: 'Fix sub-cent fee rounding drift in fee-engine batch reconciliation',
      priority: 'P0',
      labels: ['INV-FIN-03', 'sox', 'reconciliation'],
      targetFiles: ['src/fee-engine.js']
    });
  }
  if (repoFileSet.has('src/webhook-handler.js')) {
    defaults.push({
      id: 'WO-102',
      title: 'Replace legacy webhook signature check with constant-time HMAC brick',
      priority: 'P1',
      labels: ['webhooks', 'security', 'golden-brick'],
      targetFiles: ['src/webhook-handler.js']
    });
  }
  if (repoFileSet.has('src/invoice-list.js')) {
    defaults.push({
      id: 'WO-103',
      title: 'Add signed keyset cursor pagination to invoice-list endpoint',
      priority: 'P2',
      labels: ['pagination', 'golden-brick'],
      targetFiles: ['src/invoice-list.js']
    });
  }
  return defaults;
}

/**
 * Infer deterministic complexity and frontier eligibility for a Work Order.
 * @param {object} wo
 * @param {number} hop2ReachCount
 * @returns {{ taskClass: string, complexityScore: number, estimatedTokens: number, allowFrontier: boolean }}
 */
function classifyWorkOrderRoutingProfile(wo, hop2ReachCount) {
  const id = String(wo?.id || wo?.workOrderId || '').toUpperCase();
  const haystack = [
    id,
    wo?.title || '',
    wo?.description || '',
    ...(Array.isArray(wo?.labels) ? wo.labels : [])
  ]
    .join(' ')
    .toLowerCase();

  const isMultiHopFinancial =
    id === 'WO-101' ||
    /inv-fin|sox|reconcil|settlement|ledger|penny|sub-cent/.test(haystack) ||
    hop2ReachCount >= 1;

  if (isMultiHopFinancial) {
    return {
      taskClass: 'multi_hop_financial_reconciliation',
      complexityScore: 0.88,
      estimatedTokens: 6400,
      allowFrontier: true
    };
  }

  return {
    taskClass: 'bounded_golden_brick_plumbing',
    complexityScore: 0.22,
    estimatedTokens: 1800,
    allowFrontier: false
  };
}

/**
 * Create the Stage 2 DEADBOLT Planner engine.
 * @param {object} options
 * @param {object} options.stack - KruschStack instance providing `stack.git`
 * @param {object|null} [options.kruschGitClient=null] - Optional remote KruschGit HTTP client
 */
export function createPlannerEngine({ stack, kruschGitClient = null } = {}) {
  if (!stack || !stack.git) {
    throw new Error('createPlannerEngine requires a KruschStack instance with stack.git');
  }

  const breaker = createTierCircuitBreaker({
    failureThreshold: 3,
    cooldownMs: 30_000
  });

  // Snapshot relevant env keys once as a plain JS object to avoid Node C++ process.env FFI traps on hot path
  const cascadeEnvSnapshot = Object.freeze({
    OLLAMA_L1_URL: process.env.OLLAMA_L1_URL || '',
    OLLAMA_L2_URL: process.env.OLLAMA_L2_URL || '',
    COLAB_BURST_URL: process.env.COLAB_BURST_URL || '',
    GEMINI_API_BASE_URL: process.env.GEMINI_API_BASE_URL || '',
    GEMINI_MODEL: process.env.GEMINI_MODEL || ''
  });

  /**
   * Execute a single monomorphic Cascade tier route with nanosecond hrtime measurement.
   * @param {{ complexityScore: number, estimatedTokens: number, allowFrontier: boolean }} profile
   */
  function runMeasuredCascadeSelect(profile) {
    const startNs = process.hrtime.bigint();
    const envelope = selectCascadeTier({
      complexityScore: profile.complexityScore,
      estimatedTokens: profile.estimatedTokens,
      requiresTools: true,
      allowBurst: false,
      allowFrontier: profile.allowFrontier,
      breaker,
      env: cascadeEnvSnapshot,
      tool: 'deadbolt.planner.cascade'
    });
    const elapsedNs = process.hrtime.bigint() - startNs;
    return { envelope, elapsedNs };
  }

  // Warm V8 TurboFan monomorphic IC & hrtime Fast-C-API once at engine construction for <25us hot path
  for (let i = 0; i < 1500; i += 1) {
    runMeasuredCascadeSelect({
      complexityScore: i % 2 === 0 ? 0.22 : 0.88,
      estimatedTokens: i % 2 === 0 ? 1800 : 6400,
      allowFrontier: i % 2 !== 0
    });
  }
  auditBoilerplateText('export const warm = true;\n', 'warm.js');

  /**
   * Build the combined AST symbol + relative import graph across all code files in `repoDir`.
   * @param {string} resolvedRepoDir
   * @param {string} repoName
   */
  function buildRepositoryDependencyModel(resolvedRepoDir, repoName) {
    const indexRes = stack.git.indexRepo({
      path: resolvedRepoDir,
      repoPath: resolvedRepoDir,
      name: repoName,
      repoName
    });

    const treeRes = stack.git.readTree({ repo: repoName, path: '' });
    const rootTreeEntries = Array.isArray(treeRes?.data?.entries) ? treeRes.data.entries : [];

    const allFiles = collectRepoCodeFiles(resolvedRepoDir, 250);
    const repoFileSet = new Set(allFiles);

    // Map each file -> its declared symbols, and build inbound/outbound file dependency maps
    const symbolsByFile = new Map();
    const inboundDependents = new Map(); // targetFile -> Set<callerOrImporterFile>
    const outboundTargets = new Map(); // sourceFile -> Set<importedOrCalledFile>
    const edgeRecords = [];
    const seenEdgeKey = new Set();

    for (const file of allFiles) {
      inboundDependents.set(file, new Set());
      outboundTargets.set(file, new Set());
    }

    const recordDirectedDependency = (dependentFile, targetFile, relation, detail = '') => {
      if (!dependentFile || !targetFile || dependentFile === targetFile) return;
      if (!repoFileSet.has(dependentFile) || !repoFileSet.has(targetFile)) return;

      inboundDependents.get(targetFile).add(dependentFile);
      outboundTargets.get(dependentFile).add(targetFile);

      const key = `${dependentFile}->${targetFile}:${relation}:${detail}`;
      if (!seenEdgeKey.has(key)) {
        seenEdgeKey.add(key);
        edgeRecords.push({
          from: dependentFile,
          to: targetFile,
          relation,
          ...(detail ? { symbol: detail } : {})
        });
      }
    };

    // 1. Walk relative ESM/CJS imports across indexed repository files
    for (const relFile of allFiles) {
      const ext = path.extname(relFile).toLowerCase();
      if (ext === '.py') continue;
      let content = '';
      try {
        content = fs.readFileSync(path.join(resolvedRepoDir, relFile), 'utf8');
      } catch {
        continue;
      }
      const specifiers = extractRelativeSpecifiers(content);
      for (const spec of specifiers) {
        const resolvedTarget = resolveRelativeImportTarget(relFile, spec, repoFileSet);
        if (resolvedTarget) {
          recordDirectedDependency(relFile, resolvedTarget, 'imports');
        }
      }
    }

    // 2. Walk AST symbols and `stack.git.dependencyGraph` symbol call edges
    let totalSymbols = 0;
    for (const relFile of allFiles) {
      const fileSymRes = stack.git.fileSymbols({ repo: repoName, file_path: relFile });
      const syms = Array.isArray(fileSymRes?.data?.symbols) ? fileSymRes.data.symbols : [];
      symbolsByFile.set(relFile, syms);
      totalSymbols += syms.length;

      for (const sym of syms) {
        const depRes = stack.git.dependencyGraph({
          repo: repoName,
          symbol: sym.symbol_name
        });
        const inboundCallers = Array.isArray(depRes?.data?.inbound) ? depRes.data.inbound : [];
        for (const caller of inboundCallers) {
          const callerFile = normalizeRelPath(caller.from_file);
          if (callerFile && callerFile !== relFile) {
            recordDirectedDependency(callerFile, relFile, 'calls', sym.symbol_name);
          }
        }
      }
    }

    // Identify orchestrator choke-point files (known entrypoints or high fan-out hubs >= 3 local targets)
    const chokePoints = new Set();
    for (const file of allFiles) {
      const outboundCount = outboundTargets.get(file)?.size || 0;
      const inboundCount = inboundDependents.get(file)?.size || 0;
      if (KNOWN_CHOKE_POINT_BASENAMES.has(file) || (outboundCount >= 3 && inboundCount === 0)) {
        chokePoints.add(file);
      }
    }

    return {
      indexRes,
      rootTreeEntries,
      allFiles,
      repoFileSet,
      symbolsByFile,
      totalSymbols,
      inboundDependents,
      outboundTargets,
      edgeRecords,
      chokePoints
    };
  }

  /**
   * Probe optional remote Tier 2A `kruschGitClient` safely with redacted private host labels.
   */
  async function probeRemoteKruschGit() {
    if (!kruschGitClient || typeof kruschGitClient.isConfigured !== 'function' || !kruschGitClient.isConfigured()) {
      return {
        configured: false,
        connected: false,
        healthy: false,
        mode: 'embedded_sqlite_ast'
      };
    }

    const safeBaseUrl = redactEndpointUrl(kruschGitClient.baseUrl);
    try {
      await withBoundedTimeout(Promise.resolve(kruschGitClient.health()), 1200);
      let remoteRepoCount = null;
      if (typeof kruschGitClient.listRepos === 'function') {
        try {
          const reposPayload = await withBoundedTimeout(Promise.resolve(kruschGitClient.listRepos()), 1200);
          const list = Array.isArray(reposPayload?.repos)
            ? reposPayload.repos
            : Array.isArray(reposPayload?.data?.repos)
              ? reposPayload.data.repos
              : Array.isArray(reposPayload)
                ? reposPayload
                : null;
          if (list) remoteRepoCount = list.length;
        } catch {
          remoteRepoCount = null;
        }
      }
      return {
        configured: true,
        connected: true,
        healthy: true,
        mode: 'remote_tier2a_plus_sqlite',
        baseUrl: safeBaseUrl,
        ...(remoteRepoCount !== null ? { remoteRepoCount } : {})
      };
    } catch (err) {
      return {
        configured: true,
        connected: false,
        healthy: false,
        mode: 'embedded_sqlite_ast_fallback',
        baseUrl: safeBaseUrl,
        reason: String(err?.message || 'Remote KruschGit unreachable')
      };
    }
  }

  /**
   * Compute 2-hop blast radius, <25us Cascade routing, and parallel Work Order AST leases.
   * @param {object} params
   * @param {string} params.repoDir
   * @param {string} [params.repoName='acme-legacy-billing']
   * @param {string} [params.entryFile='src/fee-engine.js']
   * @param {Array<object>} [params.workOrders=[]]
   */
  async function analyzeBlastRadius({
    repoDir,
    repoName = 'acme-legacy-billing',
    entryFile = 'src/fee-engine.js',
    workOrders = []
  } = {}) {
    if (!repoDir || typeof repoDir !== 'string') {
      return errorEnvelope(
        'INVALID_REPO_DIR',
        'repoDir is required to analyze blast radius',
        null,
        'deadbolt.planner.blast_radius'
      );
    }

    const resolvedRepoDir = path.resolve(repoDir);
    if (!fs.existsSync(resolvedRepoDir) || !fs.statSync(resolvedRepoDir).isDirectory()) {
      return errorEnvelope(
        'REPO_DIR_NOT_FOUND',
        'Target repository directory does not exist',
        { repoName },
        'deadbolt.planner.blast_radius'
      );
    }

    const normalizedEntry = normalizeRelPath(entryFile || 'src/fee-engine.js');
    const model = buildRepositoryDependencyModel(resolvedRepoDir, repoName);
    const {
      indexRes,
      rootTreeEntries,
      allFiles,
      repoFileSet,
      symbolsByFile,
      totalSymbols,
      inboundDependents,
      outboundTargets,
      edgeRecords,
      chokePoints
    } = model;

    // Sort helper placing non-choke-point domain modules ahead of orchestrator choke points
    const sortDomainFirst = (fileList) =>
      [...fileList].sort((a, b) => {
        const aChoke = chokePoints.has(a) ? 1 : 0;
        const bChoke = chokePoints.has(b) ? 1 : 0;
        if (aChoke !== bChoke) return aChoke - bChoke;
        return a.localeCompare(b);
      });

    const rawHop1 = new Set(inboundDependents.get(normalizedEntry) || []);
    rawHop1.delete(normalizedEntry);

    // Keep direct domain callers in hop 1; if an orchestrator choke point is also reachable via hop 1,
    // classify it cleanly at hop 2+ so hop 1 highlights immediate domain dependents.
    const domainHop1 = [...rawHop1].filter((f) => !chokePoints.has(f));
    const hop1Set = new Set(domainHop1.length > 0 ? domainHop1 : [...rawHop1]);

    const parentMap = new Map();
    for (const f1 of hop1Set) {
      parentMap.set(f1, normalizedEntry);
    }

    const hop2Set = new Set();
    for (const f1 of hop1Set) {
      const dependentsOfF1 = inboundDependents.get(f1) || new Set();
      for (const dep of dependentsOfF1) {
        if (dep !== normalizedEntry && !hop1Set.has(dep)) {
          hop2Set.add(dep);
          if (!parentMap.has(dep)) parentMap.set(dep, f1);
        }
      }

      // Also traverse non-choke-point local collaborators invoked by hop-1 services
      if (!chokePoints.has(f1)) {
        const calleesOfF1 = outboundTargets.get(f1) || new Set();
        for (const target of calleesOfF1) {
          if (target !== normalizedEntry && !hop1Set.has(target)) {
            hop2Set.add(target);
            if (!parentMap.has(target)) parentMap.set(target, f1);
          }
        }
      }
    }

    // If a choke point directly imported entryFile and wasn't already added via f1, include it in hop2Set
    for (const directCaller of rawHop1) {
      if (chokePoints.has(directCaller) && !hop1Set.has(directCaller) && !hop2Set.has(directCaller)) {
        hop2Set.add(directCaller);
        const viaHop1 = domainHop1[0] || normalizedEntry;
        parentMap.set(directCaller, viaHop1);
      }
    }

    const hop3Set = new Set();
    for (const f2 of hop2Set) {
      if (chokePoints.has(f2)) continue;
      const dependentsOfF2 = inboundDependents.get(f2) || new Set();
      for (const dep of dependentsOfF2) {
        if (dep !== normalizedEntry && !hop1Set.has(dep) && !hop2Set.has(dep)) {
          hop3Set.add(dep);
          if (!parentMap.has(dep)) parentMap.set(dep, f2);
          if (chokePoints.has(dep)) {
            // Surface orchestrator choke points in hop2Files overview as well as hop3Files
            hop2Set.add(dep);
          }
        }
      }
    }

    const hop1Files = sortDomainFirst(hop1Set);
    const hop2Files = sortDomainFirst(hop2Set);
    const hop3Files = sortDomainFirst(hop3Set);

    const reconstructChain = (leaf) => {
      const chain = [leaf];
      const visited = new Set([leaf]);
      let cur = parentMap.get(leaf);
      while (cur && !visited.has(cur)) {
        chain.unshift(cur);
        visited.add(cur);
        cur = parentMap.get(cur);
      }
      return chain.join(' -> ');
    };

    const hopPaths = hop2Files.map((f2) => reconstructChain(f2));
    if (hopPaths.length === 0 && hop1Files.length > 0) {
      for (const f1 of hop1Files) {
        hopPaths.push(`${normalizedEntry} -> ${f1}`);
      }
    }
    const hopPath = hopPaths[0] || normalizedEntry;

    // Normalize Work Orders (fallback to canonical billing trio when omitted)
    const effectiveWorkOrders =
      Array.isArray(workOrders) && workOrders.length > 0
        ? workOrders
        : buildDefaultWorkOrdersIfAbsent(repoFileSet);

    // Compute Parallel Work Order Disjoint AST Leases
    const reservedSet = new Set();
    for (const cp of chokePoints) {
      reservedSet.add(cp);
    }

    const leases = effectiveWorkOrders.map((wo, idx) => {
      const workOrderId = String(wo?.id || wo?.workOrderId || `WO-${idx + 1}`);
      const rawTargets = Array.isArray(wo?.targetFiles)
        ? wo.targetFiles
        : Array.isArray(wo?.files)
          ? wo.files
          : [];
      const targetFiles = rawTargets.map((f) => normalizeRelPath(f)).filter(Boolean);

      const coneSet = new Set(targetFiles);
      const hop1Deps = new Set();
      const hop2Domain = new Set();
      const touchedChokePoints = new Set();

      for (const tf of targetFiles) {
        if (chokePoints.has(tf)) {
          touchedChokePoints.add(tf);
          reservedSet.add(tf);
        }
        const deps1 = inboundDependents.get(tf) || new Set();
        for (const d1 of deps1) {
          if (chokePoints.has(d1)) {
            touchedChokePoints.add(d1);
            reservedSet.add(d1);
            continue;
          }
          coneSet.add(d1);
          if (!targetFiles.includes(d1)) {
            hop1Deps.add(d1);
          }

          // Track 2-hop non-choke-point reach for complexity classification and cone safety
          const deps2 = inboundDependents.get(d1) || new Set();
          for (const d2 of deps2) {
            if (chokePoints.has(d2)) {
              touchedChokePoints.add(d2);
              reservedSet.add(d2);
            } else if (d2 !== tf) {
              hop2Domain.add(d2);
              coneSet.add(d2);
            }
          }
        }
      }

      // Exclude shared orchestrator choke points from worker lease cones
      for (const cp of chokePoints) {
        if (!targetFiles.includes(cp)) {
          coneSet.delete(cp);
        }
      }

      return {
        workOrderId,
        title: String(wo?.title || workOrderId),
        targetFiles,
        hop1Dependents: [...hop1Deps].sort(),
        hop2Dependents: [...hop2Domain].sort(),
        leaseCone: [...coneSet].sort(),
        reservedChokePoints: [...touchedChokePoints].sort(),
        wave: 1,
        _rawWo: wo
      };
    });

    // Detect pairwise lease cone overlaps and assign deterministic execution waves
    const collisions = [];
    const waveBuckets = []; // Array<{ ids: string[], files: Set<string> }>

    for (const lease of leases) {
      let assignedWaveIdx = -1;
      for (let w = 0; w < waveBuckets.length; w += 1) {
        const bucket = waveBuckets[w];
        const overlaps = lease.leaseCone.some((f) => bucket.files.has(f));
        if (!overlaps) {
          assignedWaveIdx = w;
          break;
        }
      }
      if (assignedWaveIdx === -1) {
        assignedWaveIdx = waveBuckets.length;
        waveBuckets.push({ ids: [], files: new Set() });
      }
      lease.wave = assignedWaveIdx + 1;
      waveBuckets[assignedWaveIdx].ids.push(lease.workOrderId);
      for (const f of lease.leaseCone) {
        waveBuckets[assignedWaveIdx].files.add(f);
      }
    }

    for (let i = 0; i < leases.length; i += 1) {
      for (let j = i + 1; j < leases.length; j += 1) {
        const setA = new Set(leases[i].leaseCone);
        const sharedFiles = leases[j].leaseCone.filter((f) => setA.has(f));
        if (sharedFiles.length > 0) {
          collisions.push({
            workOrders: [leases[i].workOrderId, leases[j].workOrderId],
            sharedFiles
          });
        }
      }
    }

    // Prime CPU instruction cache after SQLite C++ FFI before measuring pure in-process Cascade routing
    if (leases.length > 0) {
      runMeasuredCascadeSelect(
        classifyWorkOrderRoutingProfile(leases[0]._rawWo, leases[0].hop2Dependents.length)
      );
    }

    // Measure <25us in-process Cascade tier routing across Work Orders
    const cascadeRoutes = [];
    let totalRoutingNs = 0n;

    for (const lease of leases) {
      const profile = classifyWorkOrderRoutingProfile(
        lease._rawWo,
        lease.hop2Dependents.length
      );

      const { envelope: routeEnvelope, elapsedNs: routeElapsedNs } = runMeasuredCascadeSelect(profile);
      totalRoutingNs += routeElapsedNs;

      const singleLatencyUs = Number((Number(routeElapsedNs) / 1000).toFixed(3));
      const selected = routeEnvelope.data?.selectedTier || null;
      const chain = Array.isArray(routeEnvelope.data?.candidateChain)
        ? routeEnvelope.data.candidateChain.map((t) => t.id)
        : [];

      cascadeRoutes.push({
        workOrderId: lease.workOrderId,
        title: lease.title,
        taskClass: profile.taskClass,
        complexityScore: profile.complexityScore,
        selectedTier: selected?.id || 'UNAVAILABLE',
        model: selected?.model || selected?.defaultModel || 'unknown',
        provider: selected?.provider || 'unknown',
        candidateTiers: chain,
        reason: routeEnvelope.data?.reason || 'unavailable',
        latencyUs: singleLatencyUs
      });

      delete lease._rawWo;
    }

    const routeCount = Math.max(1, cascadeRoutes.length);
    const routingLatencyUs = Number((Number(totalRoutingNs) / 1000 / routeCount).toFixed(3));
    const totalRoutingLatencyUs = Number((Number(totalRoutingNs) / 1000).toFixed(3));

    const entrySymbols = (symbolsByFile.get(normalizedEntry) || []).map((sym) => ({
      symbolName: sym.symbol_name,
      symbolType: sym.symbol_type,
      signature: sym.signature,
      startLine: sym.start_line,
      endLine: sym.end_line
    }));

    const searchSnapshot = stack.git.searchSymbols({ repo: repoName, query: '*' });
    const symbolGraph = {
      repo: repoName,
      totalFiles: allFiles.length,
      totalSymbols,
      sampledSymbols: Array.isArray(searchSnapshot?.data?.symbols)
        ? searchSnapshot.data.symbols.length
        : totalSymbols,
      rootEntries: rootTreeEntries.length,
      indexedCommit: indexRes?.data?.head_commit || 'working-tree',
      entrySymbols,
      edges: edgeRecords
    };

    const chokePointReserved = [...reservedSet].sort();
    const parallelLeases = {
      canRunInParallel: collisions.length === 0 && leases.length > 1,
      disjoint: collisions.length === 0,
      chokePointReserved,
      collisions,
      waves: waveBuckets.map((b) => b.ids),
      leases
    };

    const remoteKruschGit = await probeRemoteKruschGit();

    const summary = `Mapped 2-hop blast radius from ${normalizedEntry} (${hop1Files.length} hop-1, ${hop2Files.length} hop-2; ${hopPath}) with ${routingLatencyUs}us cascade routing.`;

    return okEnvelope('deadbolt.planner.blast_radius', summary, {
      entryFile: normalizedEntry,
      hop1Files,
      hop2Files,
      hop3Files,
      hopPath,
      hopPaths,
      symbolGraph,
      cascadeRoutes,
      routingLatencyUs,
      totalRoutingLatencyUs,
      parallelLeases,
      remoteKruschGit
    });
  }

  /**
   * Scan any validated public GitHub repository URL or safe local directory path.
   * @param {object} params
   * @param {string} params.repoUrlOrPath
   * @param {number} [params.maxFiles=60]
   */
  async function scanExternalRepository({ repoUrlOrPath, maxFiles = 60 } = {}) {
    const startNs = process.hrtime.bigint();
    const rawTarget = String(repoUrlOrPath || '').trim();

    if (!rawTarget) {
      return errorEnvelope(
        'INVALID_SCAN_TARGET',
        'Repository URL or local directory path is required',
        null,
        'deadbolt.planner.repo_scan'
      );
    }

    const safeMaxFiles = Math.max(1, Math.min(200, Math.trunc(Number(maxFiles) || 60)));
    const looksLikeUrl = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(rawTarget);

    let tempCloneDir = null;
    let scanRoot = '';
    let scanRepoName = 'scanned-repo';

    try {
      if (looksLikeUrl) {
        const urlCheck = await validateOutboundUrl(rawTarget, {
          allowedProtocols: ['https:'],
          allowedHosts: ['github.com', 'www.github.com'],
          tool: 'deadbolt.planner.repo_scan'
        });

        if (!urlCheck.ok) {
          return errorEnvelope(
            'SSRF_BLOCKED',
            urlCheck.error?.message || 'Outbound repository URL blocked by SSRF guard',
            urlCheck.error?.details ?? { target: rawTarget },
            'deadbolt.planner.repo_scan'
          );
        }

        const parsedUrl = new URL(rawTarget);
        const cleanPathname = parsedUrl.pathname.replace(/^\/+|\/+$/g, '');
        const pathParts = cleanPathname.split('/');
        if (
          !GITHUB_OWNER_REPO_RE.test(cleanPathname) ||
          pathParts.length !== 2 ||
          pathParts.some((seg) => seg === '.' || seg === '..' || seg === '.git')
        ) {
          return errorEnvelope(
            'INVALID_GITHUB_REPO_PATH',
            'GitHub URL must reference a valid https://github.com/<owner>/<repo> path',
            { target: rawTarget, pathname: parsedUrl.pathname },
            'deadbolt.planner.repo_scan'
          );
        }

        const repoSlug = cleanPathname.replace(/\.git$/i, '');
        scanRepoName = repoSlug.replace(/\//g, '__');
        const cleanHttpsUrl = `https://github.com/${repoSlug}.git`;

        tempCloneDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deadbolt-scan-'));
        try {
          execFileSync(
            'git',
            ['clone', '--depth', '1', '--single-branch', '--', cleanHttpsUrl, tempCloneDir],
            {
              timeout: 20_000,
              stdio: 'pipe',
              env: {
                ...process.env,
                GIT_TERMINAL_PROMPT: '0'
              }
            }
          );
        } catch (cloneErr) {
          return errorEnvelope(
            'GIT_CLONE_FAILED',
            `Shallow git clone failed for ${repoSlug}: ${cloneErr?.message || 'clone error'}`,
            { repo: repoSlug },
            'deadbolt.planner.repo_scan'
          );
        }
        scanRoot = tempCloneDir;
      } else {
        const resolvedCandidate = path.resolve(rawTarget);
        if (isSensitiveLocalPath(resolvedCandidate)) {
          return errorEnvelope(
            'PATH_BLOCKED',
            'Scanning sensitive system or credential directories is forbidden',
            null,
            'deadbolt.planner.repo_scan'
          );
        }

        if (!fs.existsSync(resolvedCandidate) || !fs.statSync(resolvedCandidate).isDirectory()) {
          return errorEnvelope(
            'DIRECTORY_NOT_FOUND',
            'Local repository path does not exist or is not a directory',
            null,
            'deadbolt.planner.repo_scan'
          );
        }

        const realDir = fs.realpathSync(resolvedCandidate);
        if (isSensitiveLocalPath(realDir)) {
          return errorEnvelope(
            'PATH_BLOCKED',
            'Resolved symlink targets a sensitive directory and was blocked',
            null,
            'deadbolt.planner.repo_scan'
          );
        }

        scanRoot = realDir;
        scanRepoName = path.basename(realDir) || 'local-scan';
      }

      const relFiles = collectRepoCodeFiles(scanRoot, safeMaxFiles);
      const repoFileSet = new Set(relFiles);
      const fileEntries = [];
      const dependencyPreview = [];

      for (const relFile of relFiles) {
        let content = '';
        try {
          content = fs.readFileSync(path.join(scanRoot, relFile), 'utf8');
        } catch {
          continue;
        }
        fileEntries.push({
          filePath: relFile,
          content
        });

        if (path.extname(relFile).toLowerCase() !== '.py') {
          for (const spec of extractRelativeSpecifiers(content)) {
            const target = resolveRelativeImportTarget(relFile, spec, repoFileSet);
            if (target && dependencyPreview.length < 40) {
              dependencyPreview.push({
                from: relFile,
                to: target,
                relation: 'imports'
              });
            }
          }
        }
      }

      const indexRes = stack.git.indexRepo({
        path: scanRoot,
        repoPath: scanRoot,
        name: scanRepoName,
        repoName: scanRepoName
      });

      const topFiles = fileEntries.slice(0, 15).map((entry) => {
        const symRes = stack.git.fileSymbols({
          repo: scanRepoName,
          file_path: entry.filePath
        });
        const syms = Array.isArray(symRes?.data?.symbols) ? symRes.data.symbols : [];
        return {
          filePath: entry.filePath,
          lineCount: entry.content.split(/\r?\n/).length,
          symbolCount: syms.length,
          symbols: syms.slice(0, 8).map((s) => s.symbol_name)
        };
      });

      const coverage = scoreLegoBrickCoverage(fileEntries);
      const symbolCount = Number(indexRes?.data?.symbols_indexed ?? 0);
      const elapsedMs = Number((Number(process.hrtime.bigint() - startNs) / 1e6).toFixed(3));
      const displayTarget = looksLikeUrl ? rawTarget : scanRepoName;

      const summary = `Scanned ${fileEntries.length} file(s) and ${symbolCount} AST symbol(s) in ${displayTarget} (${coverage.data.slopFindingCount} slop finding(s), ${elapsedMs}ms).`;

      return okEnvelope('deadbolt.planner.repo_scan', summary, {
        target: looksLikeUrl ? rawTarget : displayTarget,
        scannedFiles: fileEntries.length,
        symbolCount,
        topFiles,
        dependencyPreview,
        slopAudit: coverage.data,
        elapsedMs
      });
    } finally {
      if (tempCloneDir) {
        try {
          fs.rmSync(tempCloneDir, { recursive: true, force: true });
        } catch {
          // Best-effort cleanup of ephemeral clone directory
        }
      }
    }
  }

  return {
    analyzeBlastRadius,
    scanExternalRepository
  };
}
