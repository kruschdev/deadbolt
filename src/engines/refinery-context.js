import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';
import {
  createRawRagIndex,
  chunkConversationWindows,
  rerankCandidateWindows,
  estimateTokenCount
} from '@krusch/toolkit/raw-rag';
import { delimitUntrustedContent } from '@krusch/toolkit/harness-engineering';
import { sanitizeAgentMessage } from '@krusch/toolkit/trajectory-guard';
import { buildHydraContextString } from '@krusch/toolkit/hydradb';
import {
  BILLING_WORK_ORDERS,
  ORG_CONTEXT_MODALITIES,
  BILLING_REPO_SNAPSHOT
} from '../fixtures/billing-scenario.js';

const ANCHOR_REL_FILES = Object.freeze([
  'src/sox-reconciler.js',
  'src/settlement-service.js',
  'src/fee-engine.js'
]);

const MODALITY_KEYS = Object.freeze([
  'tickets',
  'codebaseSpans',
  'pastSessions',
  'emails',
  'chats',
  'transcripts'
]);

function isSubpathContained(rootDir, candidateDir) {
  if (!rootDir || !candidateDir) {
    return false;
  }
  try {
    const absRoot = path.resolve(rootDir);
    const absCandidate = path.resolve(candidateDir);
    if (absCandidate !== absRoot && !absCandidate.startsWith(absRoot + path.sep)) {
      return false;
    }
    if (fs.existsSync(absRoot) && fs.existsSync(absCandidate)) {
      const realRoot = fs.realpathSync(absRoot);
      const realCandidate = fs.realpathSync(absCandidate);
      if (realCandidate !== realRoot && !realCandidate.startsWith(realRoot + path.sep)) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

function buildTrustedConversationTurns() {
  const turns = [];

  for (const email of ORG_CONTEXT_MODALITIES.emails || []) {
    if (email.trust === 'untrusted') continue;
    turns.push({
      turnId: email.id,
      modality: 'emails',
      speaker: email.speaker,
      timestamp: email.date,
      content: `[Email ${email.id} | ${email.subject}] ${email.content}`
    });
  }

  for (const chat of ORG_CONTEXT_MODALITIES.chats || []) {
    if (chat.trust === 'untrusted') continue;
    turns.push({
      turnId: chat.id,
      modality: 'chats',
      speaker: chat.speaker,
      timestamp: chat.date,
      content: `[Chat ${chat.channel} | ${chat.id}] ${chat.content}`
    });
  }

  for (const transcript of ORG_CONTEXT_MODALITIES.transcripts || []) {
    if (transcript.trust === 'untrusted') continue;
    turns.push({
      turnId: transcript.id,
      modality: 'transcripts',
      speaker: transcript.speaker,
      timestamp: transcript.date,
      content: `[Transcript ${transcript.id}] ${transcript.content}`
    });
  }

  return turns;
}

function findSpanByFile(relFile) {
  return (
    (ORG_CONTEXT_MODALITIES.codebaseSpans || []).find((span) => span.file === relFile) || {
      file: relFile,
      locator: 'L1',
      quotedSentence: ''
    }
  );
}

function clampTextToTokenBudget(text, maxTokens) {
  const raw = String(text || '');
  const used = estimateTokenCount(raw);
  if (used <= maxTokens) {
    return { text: raw, tokensUsed: used, truncated: false };
  }
  const approxMaxChars = Math.max(256, Math.floor((maxTokens - 16) * 3.5));
  const clipped = `${raw.slice(0, approxMaxChars).trimEnd()}\n...[bounded to tokenBudget]`;
  return {
    text: clipped,
    tokensUsed: estimateTokenCount(clipped),
    truncated: true
  };
}

export function createRefineryEngine({ stack, hydraClient = null, workspaceRoot } = {}) {
  const stackRoot = path.resolve(stack?.workspaceRoot || workspaceRoot || process.cwd());
  const mirrorSlot = crypto
    .createHash('sha256')
    .update(`${stackRoot}:${process.pid}`)
    .digest('hex')
    .slice(0, 12);
  const mirrorBaseDir = path.join(stackRoot, 'data', 'refinery-anchors', mirrorSlot);

  let activeRepoDir = null;
  let anchorMode = 'mirror';
  let rawRag = null;
  let rawRagWindowCount = 0;
  let lastSeedMeta = null;

  function syncAnchorFiles(sourceRepoDir = null) {
    if (sourceRepoDir) {
      activeRepoDir = path.resolve(sourceRepoDir);
    }

    if (activeRepoDir && isSubpathContained(stackRoot, activeRepoDir)) {
      anchorMode = 'direct';
      const fileMap = {};
      for (const relFile of ANCHOR_REL_FILES) {
        const absTarget = path.join(activeRepoDir, relFile);
        fileMap[relFile] = path.relative(stackRoot, absTarget).replace(/\\/g, '/');
      }
      return fileMap;
    }

    anchorMode = 'mirror';
    fs.mkdirSync(mirrorBaseDir, { recursive: true });
    const fileMap = {};

    for (const relFile of ANCHOR_REL_FILES) {
      const mirrorAbs = path.join(mirrorBaseDir, relFile);
      fs.mkdirSync(path.dirname(mirrorAbs), { recursive: true });

      if (activeRepoDir) {
        const externalAbs = path.join(activeRepoDir, relFile);
        if (fs.existsSync(externalAbs)) {
          const liveContent = fs.readFileSync(externalAbs, 'utf8');
          fs.writeFileSync(mirrorAbs, liveContent, 'utf8');
        } else if (fs.existsSync(mirrorAbs)) {
          fs.rmSync(mirrorAbs, { force: true });
        }
      } else {
        const snapshotContent = BILLING_REPO_SNAPSHOT.cleanRepoFiles[relFile] || '';
        fs.writeFileSync(mirrorAbs, snapshotContent, 'utf8');
      }

      fileMap[relFile] = path.relative(stackRoot, mirrorAbs).replace(/\\/g, '/');
    }

    return fileMap;
  }

  function mapAnchorDisplayPath(storedRelFile) {
    const normalized = String(storedRelFile || '').replace(/\\/g, '/');
    for (const relFile of ANCHOR_REL_FILES) {
      if (normalized === relFile || normalized.endsWith(`/${relFile}`)) {
        return relFile;
      }
    }
    return normalized;
  }

  function scanUntrustedExternalInputs() {
    const untrustedItems = (ORG_CONTEXT_MODALITIES.chats || []).filter(
      (item) => item.trust === 'untrusted'
    );

    let neutralizedTags = 0;
    let infectedCount = 0;
    let highestRisk = 'LOW';
    const riskRank = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
    const threatSet = new Set();
    const inspectedItems = [];

    for (const item of untrustedItems) {
      const delimited = delimitUntrustedContent(item.content, {
        source: item.source || item.id,
        trustLevel: 'untrusted'
      });
      const sanitized = sanitizeAgentMessage(item.content);

      neutralizedTags += Number(delimited.neutralizedTags || 0);
      if (sanitized.isInfected) {
        infectedCount += 1;
      }
      const itemRisk = String(sanitized.riskLevel || 'LOW').toUpperCase();
      if ((riskRank[itemRisk] || 0) > (riskRank[highestRisk] || 0)) {
        highestRisk = itemRisk;
      }
      for (const patternName of sanitized.detectedPatterns || []) {
        threatSet.add(patternName);
      }
      if (delimited.neutralizedTags > 0) {
        threatSet.add('closing_delimiter_escape_attempt');
      }

      inspectedItems.push({
        id: item.id,
        channel: item.channel,
        speaker: item.speaker,
        source: item.source || 'external_comment',
        neutralizedTags: delimited.neutralizedTags,
        isSafe: sanitized.isSafe,
        isInfected: sanitized.isInfected,
        riskLevel: itemRisk,
        detectedPatterns: sanitized.detectedPatterns || [],
        delimitedContent: delimited.delimited,
        sanitizedMessage: sanitized.sanitizedMessage
      });
    }

    const threatsDetected = [...threatSet];
    return {
      scannedCount: untrustedItems.length,
      infectedCount,
      neutralizedTags,
      threatsDetected,
      threatCount: threatsDetected.length,
      blocked: infectedCount > 0 || neutralizedTags > 0,
      riskLevel: highestRisk,
      items: inspectedItems
    };
  }

  async function seedOrganizationalContext({ repoDir, forceReseed = false } = {}) {
    if (!stack || !stack.context) {
      return errorEnvelope(
        'REFINERY_STACK_MISSING',
        'createRefineryEngine requires a krusch-stack instance exposing stack.context.',
        {},
        'deadbolt.refinery.seed'
      );
    }

    const anchorMap = syncAnchorFiles(repoDir || activeRepoDir);
    const soxSpan = findSpanByFile('src/sox-reconciler.js');
    const settlementSpan = findSpanByFile('src/settlement-service.js');
    const feeSpan = findSpanByFile('src/fee-engine.js');

    const soxRelFile = anchorMap['src/sox-reconciler.js'];
    const settlementRelFile = anchorMap['src/settlement-service.js'];
    const feeRelFile = anchorMap['src/fee-engine.js'];

    const existingLookup = stack.context.retrieve({
      query: 'INV-FIN-03',
      include_lineage: true,
      limit_tokens: 2000
    });
    const existingItems = existingLookup?.data?.items || [];
    const matchingInv03 = existingItems.find(
      (item) =>
        String(item.content || '').startsWith('INV-FIN-03:') &&
        item.provenance?.file === soxRelFile &&
        item.drift_status === 'VALID'
    );

    let invFin02Id = null;
    let invFin03Id = null;
    let adrDecisionId = null;
    let lessonId = null;
    let reusedContextStore = false;

    if (matchingInv03 && !forceReseed) {
      reusedContextStore = true;
      invFin03Id = Number(matchingInv03.id);
      const priorNode = (matchingInv03.lineage || []).find(
        (node) => Number(node.id) !== invFin03Id && String(node.content || '').includes('INV-FIN-02')
      );
      invFin02Id = priorNode ? Number(priorNode.id) : null;

      const allExisting = stack.context.retrieve({
        query: '*',
        include_lineage: false,
        limit_tokens: 3000
      })?.data?.items || [];
      const existingAdr = allExisting.find((it) => String(it.content || '').startsWith('ADR-044'));
      const existingLesson = allExisting.find((it) =>
        String(it.content || '').startsWith('WO-101 2-Hop Blast Radius Lesson:')
      );
      adrDecisionId = existingAdr ? Number(existingAdr.id) : null;
      lessonId = existingLesson ? Number(existingLesson.id) : null;
    } else {
      const priorPool = stack.context.retrieve({
        query: '*',
        include_lineage: false,
        limit_tokens: 4000
      })?.data?.items || [];
      for (const staleItem of priorPool) {
        const text = String(staleItem.content || '');
        if (
          text.startsWith('INV-FIN-02:') ||
          text.startsWith('INV-FIN-03:') ||
          text.startsWith('ADR-044') ||
          text.startsWith('WO-101 2-Hop Blast Radius Lesson:')
        ) {
          stack.context.revise({
            action: 'invalidate',
            target_id: Number(staleItem.id),
            reason: 'Reseeded Deadbolt Refinery context for updated workspace target.'
          });
        }
      }

      const inv02Res = stack.context.remember({
        category: 'invariant',
        content:
          'INV-FIN-02: Legacy MVP settlement batch policy permitted up to 1 cent rounding variance across multi-line invoices during initial rollout.'
      });
      invFin02Id = Number(inv02Res?.data?.id);

      const inv03Res = stack.context.revise({
        action: 'supersede',
        target_id: invFin02Id,
        new_content:
          'INV-FIN-03: Sum of settled line-item net payouts plus batch processor fee in integer cents must equal gross invoice total in integer cents (deltaCents === 0). Must not set `strictSox = false` in protected reconciler.',
        reason:
          'Q1 SOX external audit revoked INV-FIN-02 after 3-way split settlement batches drifted by +1 cent against processor batch fee.',
        provenance: {
          file: soxRelFile,
          locator: soxSpan.locator,
          quoted_sentence: soxSpan.quotedSentence
        }
      });
      invFin03Id = Number(inv03Res?.data?.new_id);

      const adrRes = stack.context.remember({
        category: 'decision',
        content:
          'ADR-044 (WO-101): Allocate multi-line processor fees in src/fee-engine.js using integer basis-point floor division plus largest-remainder cent carry ranked by remainderBps, amountCents, and lineIndex so line fees sum identically to batchFeeCents.',
        provenance: {
          file: feeRelFile,
          locator: feeSpan.locator,
          quoted_sentence: feeSpan.quotedSentence
        }
      });
      adrDecisionId = Number(adrRes?.data?.id);

      const lessonRes = stack.context.remember({
        category: 'lesson',
        content:
          'WO-101 2-Hop Blast Radius Lesson: Per-line Math.round passes single-line $100.00 unit tests (10000 cents at 250 bps = 250 fee cents) while creating a +1 cent net discrepancy on 3-way split batches ([3334, 3333, 3333] -> 83+83+83 = 249 fee cents vs 250 expected) two hops downstream in reconcileSettlementLedger.',
        provenance: {
          file: settlementRelFile,
          locator: settlementSpan.locator,
          quoted_sentence: settlementSpan.quotedSentence
        }
      });
      lessonId = Number(lessonRes?.data?.id);
    }

    const trustedTurns = buildTrustedConversationTurns();
    const previewWindows = chunkConversationWindows(trustedTurns, {
      windowTokens: 256,
      overlapTokens: 32,
      sessionId: 'deadbolt-org-context-v1'
    });

    rawRag = createRawRagIndex({
      offline: true,
      mock: true,
      windowTokens: 256,
      overlapTokens: 32,
      finalRerankK: 10,
      maxEvidenceTokens: 1600
    });
    const addTurnsStats = await rawRag.addTurns(trustedTurns, {
      sessionId: 'deadbolt-org-context-v1'
    });
    rawRagWindowCount = Number(addTurnsStats?.addedWindows ?? previewWindows.length);

    let hydraSync = {
      configured: false,
      synced: false,
      mode: 'sqlite_road_mode',
      ingestedCount: 0
    };

    if (Boolean(hydraClient?.isConfigured?.())) {
      try {
        const hydraMemories = [
          {
            id: 'deadbolt-inv-fin-02',
            title: 'INV-FIN-02 (Superseded Legacy Rounding Policy)',
            text:
              'INV-FIN-02 permitted +/-1 cent batch settlement rounding variance during MVP rollout. Superseded by INV-FIN-03.',
            metadata: {
              status: 'superseded',
              invariant_code: 'INV-FIN-02',
              superseded_by: 'deadbolt-inv-fin-03'
            }
          },
          {
            id: 'deadbolt-inv-fin-03',
            title: 'INV-FIN-03 (Active SOX Zero-Cent Batch Parity)',
            text:
              'INV-FIN-03 mandates exact zero-cent parity between settled line-item net payouts plus batch processor fee and gross invoice cents (deltaCents === 0, strictSox = true).',
            metadata: {
              status: 'active',
              invariant_code: 'INV-FIN-03',
              supersedes_id: 'deadbolt-inv-fin-02',
              work_order_id: 'WO-101'
            }
          }
        ];
        await hydraClient.ingestMemories(hydraMemories, { upsert: true });
        hydraSync = {
          configured: true,
          synced: true,
          mode: 'hydradb_v2_live',
          ingestedCount: hydraMemories.length
        };
      } catch (err) {
        hydraSync = {
          configured: true,
          synced: false,
          mode: 'hydradb_error_fallback',
          ingestedCount: 0,
          error: err instanceof Error ? err.message : String(err)
        };
      }
    }

    const healthSnapshot = stack.context.health()?.data || {};
    const untrustedDeferredCount = (ORG_CONTEXT_MODALITIES.chats || []).filter(
      (c) => c.trust === 'untrusted'
    ).length;

    lastSeedMeta = {
      seeded: true,
      reusedContextStore,
      anchorMode,
      memoryIds: {
        invFin02Id,
        invFin03Id,
        adrDecisionId,
        lessonId
      },
      lineage: {
        supersededCode: 'INV-FIN-02',
        supersededMemoryId: invFin02Id,
        activeCode: 'INV-FIN-03',
        activeMemoryId: invFin03Id,
        supersedes_id: invFin02Id
      },
      spanAnchors: [
        { file: 'src/sox-reconciler.js', resolvedFile: soxRelFile, locator: soxSpan.locator },
        { file: 'src/settlement-service.js', resolvedFile: settlementRelFile, locator: settlementSpan.locator },
        { file: 'src/fee-engine.js', resolvedFile: feeRelFile, locator: feeSpan.locator }
      ],
      contextHealth: healthSnapshot,
      rawRagStats: {
        trustedTurnsIndexed: trustedTurns.length,
        windowCount: rawRagWindowCount,
        windowTokens: 256,
        overlapTokens: 32,
        untrustedDeferredCount
      },
      hydraSync
    };

    return okEnvelope(
      'deadbolt.refinery.seed',
      `Seeded Deadbolt organizational context across 6 modalities (${rawRagWindowCount} Raw-RAG window(s), INV-FIN-02 -> INV-FIN-03 lineage active).`,
      lastSeedMeta
    );
  }

  async function hydrateWorkOrderContext({
    workOrderId = 'WO-101',
    query = 'INV-FIN-03 fee rounding batch settlement reconciliation',
    tokenBudget = 4000,
    repoDir = null
  } = {}) {
    if (!stack || !stack.context) {
      return errorEnvelope(
        'REFINERY_STACK_MISSING',
        'createRefineryEngine requires a krusch-stack instance exposing stack.context.',
        {},
        'deadbolt.refinery.hydrate'
      );
    }

    const effectiveBudget = Math.max(400, Math.min(4000, Math.trunc(Number(tokenBudget) || 4000)));
    const initialHealth = stack.context.health()?.data || {};
    if ((Number(initialHealth.active) || 0) === 0 || !rawRag) {
      await seedOrganizationalContext({ repoDir });
    } else if (repoDir || (anchorMode === 'mirror' && activeRepoDir)) {
      syncAnchorFiles(repoDir || activeRepoDir);
    }

    const workOrder =
      BILLING_WORK_ORDERS.find((item) => item.id === workOrderId) || BILLING_WORK_ORDERS[0];

    const contextMemoryBudget = Math.min(1400, Math.max(250, Math.floor(effectiveBudget * 0.38)));
    const retrieveRes = stack.context.retrieve({
      query,
      include_state: true,
      include_lineage: true,
      limit_tokens: contextMemoryBudget
    });
    const allActiveRes = stack.context.retrieve({
      query: '*',
      include_state: false,
      include_lineage: true,
      limit_tokens: 3000
    });
    const healthData = stack.context.health()?.data || {};

    const activePoolItems = allActiveRes?.data?.items || [];
    const rankedMemories = retrieveRes?.data?.items || [];

    const anchors = activePoolItems
      .filter((item) => item.provenance?.file)
      .map((item) => ({
        memoryId: Number(item.id),
        category: item.category,
        file: mapAnchorDisplayPath(item.provenance.file),
        resolvedFile: item.provenance.file,
        locator: item.provenance.locator || 'L1',
        driftStatus: item.drift_status || 'VALID'
      }));

    const driftedCount = Number(healthData.drifted_count || 0);
    const spanStatus = driftedCount > 0 ? 'STALE_DRIFT' : 'VALID';
    const spanIntegrity = {
      status: spanStatus,
      valid: spanStatus === 'VALID',
      activeCount: Number(healthData.active || 0),
      supersededCount: Number(healthData.superseded || 0),
      driftedCount,
      healedCount: Number(healthData.healed_count || 0),
      anchors
    };

    const inv03FromRanked = rankedMemories.find(
      (item) =>
        String(item.content || '').startsWith('INV-FIN-03:') &&
        Array.isArray(item.lineage) &&
        item.lineage.length > 0
    );
    const inv03LookupItems = inv03FromRanked
      ? []
      : stack.context.retrieve({
          query: 'INV-FIN-03',
          include_state: false,
          limit_tokens: 1000
        })?.data?.items || [];
    const inv03Item =
      inv03FromRanked ||
      inv03LookupItems.find((item) => String(item.content || '').startsWith('INV-FIN-03:')) ||
      activePoolItems.find((item) => String(item.content || '').startsWith('INV-FIN-03:')) ||
      null;

    const lineageChain = [];
    if (inv03Item && Array.isArray(inv03Item.lineage) && inv03Item.lineage.length > 0) {
      let prevId = null;
      for (let i = 0; i < inv03Item.lineage.length; i += 1) {
        const node = inv03Item.lineage[i];
        const nextNode = inv03Item.lineage[i + 1] || null;
        const codeMatch = /\b(INV-FIN-\d+)\b/.exec(String(node.content || ''));
        lineageChain.push({
          id: Number(node.id),
          invariantCode: codeMatch ? codeMatch[1] : `MEM-${node.id}`,
          category: node.category,
          status: node.status,
          supersedes_id: prevId,
          supersedesId: prevId,
          superseded_by: nextNode ? Number(nextNode.id) : null,
          supersededBy: nextNode ? Number(nextNode.id) : null,
          content: node.content,
          createdAt: node.created_at || null
        });
        prevId = Number(node.id);
      }
    } else {
      for (const session of ORG_CONTEXT_MODALITIES.pastSessions || []) {
        lineageChain.push({
          id: session.id,
          invariantCode: session.invariantCode,
          category: 'invariant',
          status: session.status,
          supersedes_id: session.supersedesId,
          supersedesId: session.supersedesId,
          superseded_by: session.status === 'superseded' ? 'INV-FIN-03' : null,
          supersededBy: session.status === 'superseded' ? 'INV-FIN-03' : null,
          content: session.summary,
          createdAt: session.date
        });
      }
    }

    const ragEvidenceCap = Math.min(1000, Math.max(240, Math.floor(effectiveBudget * 0.3)));
    const rawRagResult = await rawRag.retrieve(query, {
      topK: 8,
      maxEvidenceTokens: ragEvidenceCap,
      offline: true
    });
    const rerankedWindows = await rerankCandidateWindows(
      query,
      rawRagResult.selectedWindows || [],
      { topK: 6, offline: true }
    );

    const untrustedGuard = scanUntrustedExternalInputs();

    let hydraSync = {
      configured: Boolean(hydraClient?.isConfigured?.()),
      queried: false,
      mode: lastSeedMeta?.hydraSync?.mode || 'sqlite_road_mode',
      contextSnippet: ''
    };

    if (hydraSync.configured) {
      try {
        const hydraQueryRes = await hydraClient.queryContext({
          query: `${workOrder.id} ${query}`,
          maxResults: 4,
          graphContext: true
        });
        const formattedHydra = buildHydraContextString(hydraQueryRes, { maxChunks: 3 });
        hydraSync = {
          configured: true,
          queried: true,
          mode: 'hydradb_v2_live',
          contextSnippet: formattedHydra
        };
      } catch (err) {
        hydraSync = {
          configured: true,
          queried: false,
          mode: 'hydradb_error_fallback',
          contextSnippet: '',
          error: err instanceof Error ? err.message : String(err)
        };
      }
    }

    const ticketItems = (ORG_CONTEXT_MODALITIES.tickets || []).filter(
      (ticket) =>
        ticket.id === workOrder.id ||
        ticket.id === workOrder.requirementRef ||
        ticket.id === workOrder.blueprintRef
    );
    const spanItems = ORG_CONTEXT_MODALITIES.codebaseSpans || [];
    const sessionItems = ORG_CONTEXT_MODALITIES.pastSessions || [];
    const trustedEmails = (ORG_CONTEXT_MODALITIES.emails || []).filter(
      (item) => item.trust !== 'untrusted'
    );
    const trustedChats = (ORG_CONTEXT_MODALITIES.chats || []).filter(
      (item) => item.trust !== 'untrusted'
    );
    const trustedTranscripts = (ORG_CONTEXT_MODALITIES.transcripts || []).filter(
      (item) => item.trust !== 'untrusted'
    );

    const briefingSections = [
      `# DEADBOLT Stage 1 Refinery Briefing (${workOrder.id})`,
      `Span Lock Integrity (INV-12): ${spanIntegrity.status} (${spanIntegrity.driftedCount} drifted / ${spanIntegrity.activeCount} active)`,
      '',
      '## 1. Software Factory Work Order, Requirement & Blueprint (tickets)',
      ...ticketItems.map((item) => `- [${item.id} | ${item.kind}] ${item.content}`),
      '',
      '## 2. Anchored Codebase Spans (codebaseSpans)',
      ...spanItems.map((span) => {
        const liveAnchor = anchors.find((a) => a.file === span.file);
        const lockLabel = liveAnchor ? liveAnchor.driftStatus : spanIntegrity.status;
        return `- ${span.file}#${span.locator} [${lockLabel}] (${span.symbol}): ${span.summary}`;
      }),
      '',
      '## 3. Prior Agent Session Lineage (pastSessions & krusch-context-mcp)',
      ...lineageChain.map(
        (node) =>
          `- [${node.invariantCode} | ${node.status}${node.supersedes_id ? ` | supersedes=${node.supersedes_id}` : ''}] ${node.content}`
      ),
      ...sessionItems.map((sess) => `- [${sess.id} | ${sess.outcome}] ${sess.summary}`),
      '',
      '## 4. Audit & Controller Directives (emails)',
      ...trustedEmails.map((em) => `- [${em.id} | ${em.speaker}] ${em.content}`),
      '',
      '## 5. Engineering Channel Signals & Untrusted Guard (chats)',
      ...trustedChats.map((ch) => `- [${ch.channel} | ${ch.speaker}] ${ch.content}`),
      `- [Untrusted Guard | INV-DB-07] Scanned ${untrustedGuard.scannedCount} external input(s); neutralized ${untrustedGuard.neutralizedTags} delimiter escape tag(s); blocked=${untrustedGuard.blocked}; threats=${untrustedGuard.threatsDetected.join(', ') || 'none'}.`,
      '',
      '## 6. Architecture Review Transcripts & Raw-RAG Evidence (transcripts)',
      ...trustedTranscripts.map((tr) => `- [${tr.id} | ${tr.speaker}] ${tr.content}`),
      ...(hydraSync.contextSnippet ? ['', '## 7. HydraDB v2 Graph Context', hydraSync.contextSnippet] : [])
    ];

    const safetyCeiling = Math.max(350, effectiveBudget - 25);
    const boundedBriefing = clampTextToTokenBudget(briefingSections.join('\n'), safetyCeiling);

    const modalityBreakdown = {
      tickets: ticketItems.length,
      codebaseSpans: spanItems.length,
      pastSessions: sessionItems.length,
      emails: trustedEmails.length,
      chats: trustedChats.length,
      transcripts: trustedTranscripts.length
    };
    const modalitiesHydrated = MODALITY_KEYS.filter((key) => modalityBreakdown[key] > 0);

    return okEnvelope(
      'deadbolt.refinery.hydrate',
      `Hydrated ${workOrder.id} across ${modalitiesHydrated.length}/6 modalities in ${boundedBriefing.tokensUsed}/${effectiveBudget} tokens (INV-12: ${spanIntegrity.status}).`,
      {
        workOrder,
        contextBriefing: boundedBriefing.text,
        tokensUsed: boundedBriefing.tokensUsed,
        tokenBudget: effectiveBudget,
        truncatedToBudget: boundedBriefing.truncated,
        spanIntegrity,
        lineageChain,
        modalitiesHydrated,
        modalityBreakdown,
        untrustedGuard,
        hydraSync,
        rawRagTelemetry: {
          recalledWindowCount: (rawRagResult.recalledWindows || []).length,
          rerankedWindowCount: rerankedWindows.length,
          evidenceTokens: Number(rawRagResult.evidenceTokens || 0)
        },
        retrievedMemories: rankedMemories.map((item) => ({
          id: Number(item.id),
          category: item.category,
          content: item.content,
          driftStatus: item.drift_status || 'VALID',
          provenance: item.provenance || null
        }))
      }
    );
  }

  function cleanupMirrorAnchors() {
    if (fs.existsSync(mirrorBaseDir)) {
      fs.rmSync(mirrorBaseDir, { recursive: true, force: true });
    }
  }

  return {
    seedOrganizationalContext,
    hydrateWorkOrderContext,
    cleanupMirrorAnchors
  };
}
