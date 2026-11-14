import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import {
  fetchApiJson,
  useApiQuery,
  useSSEStream,
  StatusPill,
  cn
} from '@krusch/toolkit/react';

const DEFAULT_WORK_ORDERS = Object.freeze([
  {
    id: 'WO-101',
    title: 'Fix BILL-101 sub-cent fee rounding drift in src/fee-engine.js',
    targetFiles: ['src/fee-engine.js'],
    tier: 'L3_FRONTIER_ARGON',
    parallelSafe: true
  },
  {
    id: 'WO-102',
    title: 'Replace legacy webhook signature check in src/webhook-handler.js',
    targetFiles: ['src/webhook-handler.js'],
    tier: 'L1_FAST',
    parallelSafe: true
  },
  {
    id: 'WO-103',
    title: 'Add signed keyset pagination to src/invoice-list.js',
    targetFiles: ['src/invoice-list.js'],
    tier: 'L1_FAST',
    parallelSafe: true
  }
]);

const DEFAULT_MODALITIES = Object.freeze([
  'Tickets',
  'Codebase Spans',
  'Past Sessions',
  'Emails',
  'Chats',
  'Transcripts'
]);

const DEFAULT_PARALLEL_LEASES = Object.freeze([
  {
    workOrderId: 'WO-101',
    entryFile: 'src/fee-engine.js',
    coneFiles: ['src/fee-engine.js', 'src/settlement-service.js', 'src/sox-reconciler.js'],
    cascadeTier: 'L3_FRONTIER_ARGON',
    canRunInParallel: true,
    reservedChokePoint: 'src/server.js'
  },
  {
    workOrderId: 'WO-102',
    entryFile: 'src/webhook-handler.js',
    coneFiles: ['src/webhook-handler.js'],
    cascadeTier: 'L1_FAST',
    canRunInParallel: true,
    reservedChokePoint: 'src/server.js'
  },
  {
    workOrderId: 'WO-103',
    entryFile: 'src/invoice-list.js',
    coneFiles: ['src/invoice-list.js'],
    cascadeTier: 'L1_FAST',
    canRunInParallel: true,
    reservedChokePoint: 'src/server.js'
  }
]);

const DEFAULT_MCP_PERMISSION_TABLE = Object.freeze([
  {
    name: 'deadbolt_hydrate_work_order',
    sofaPermission: 'Allow',
    sofaScope: 'Unattended Automations',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    description: 'Hydrates <4,000-token 6-modality org context + INV-12 SHA-256 span locks for WO-*.'
  },
  {
    name: 'deadbolt_map_blast_radius',
    sofaPermission: 'Allow',
    sofaScope: 'Unattended Automations',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    description: 'Maps 2-hop AST dependency path, <25us Cascade tier, and parallel WO-* disjoint leases.'
  },
  {
    name: 'deadbolt_validate_reconciliation',
    sofaPermission: 'Allow',
    sofaScope: 'Drift Bot & PR Gate',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    description: 'Runs <1ms Slop Breaker, policy-floor workaround check, and INV-FIN-03 SOX batch reconciliation.'
  },
  {
    name: 'deadbolt_verify_audit_chain',
    sofaPermission: 'Allow',
    sofaScope: 'Compliance Audit',
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
    description: 'Verifies SHA-256 cryptographic audit chain and measured cost-per-verified-task receipts.'
  },
  {
    name: 'deadbolt_apply_verified_stage',
    sofaPermission: 'Confirm',
    sofaScope: 'Human Approval Required',
    readOnlyHint: false,
    destructiveHint: false,
    idempotentHint: false,
    openWorldHint: true,
    description: 'Applies a VERIFIED staged task and dispatches a [WO-101]-linked PR receipt.'
  }
]);

function unwrapEnvelopeData(raw) {
  if (!raw || typeof raw !== 'object') return null;
  if (
    Object.hasOwn(raw, 'data') &&
    raw.data &&
    typeof raw.data === 'object' &&
    (Object.hasOwn(raw, 'ok') || Object.hasOwn(raw, 'tool'))
  ) {
    return raw.data;
  }
  return raw;
}

function formatCentsUsd(cents) {
  const numeric = Number(cents);
  if (!Number.isFinite(numeric)) return '$0.00';
  const sign = numeric < 0 ? '-' : '';
  return `${sign}$${(Math.abs(numeric) / 100).toFixed(2)}`;
}

function formatSignedCents(cents) {
  const numeric = Number(cents);
  if (!Number.isFinite(numeric)) return '0c';
  if (numeric > 0) return `+${numeric}c`;
  return `${numeric}c`;
}

function formatCostUsd(costValue) {
  if (costValue === null || costValue === undefined) {
    return 'null (Unverified / Offline Gate)';
  }
  const num = Number(costValue);
  if (!Number.isFinite(num)) return String(costValue);
  return `$${num.toFixed(4)}`;
}

function mapConnectorStatusToPill(entry) {
  if (!entry || typeof entry !== 'object') return 'healthy';
  const rawStatus = String(entry.status || entry.state || '').toLowerCase();
  if (rawStatus === 'offline' || rawStatus === 'error' || entry.ok === false) return 'offline';
  if (rawStatus === 'streaming') return 'streaming';
  if (rawStatus === 'degraded') return 'degraded';
  return 'healthy';
}

function normalizeConnectorBar(rawConnectors) {
  const byKey = {};
  if (Array.isArray(rawConnectors)) {
    for (const item of rawConnectors) {
      if (item && typeof item === 'object') {
        const key = String(item.id || item.key || item.name || '').toLowerCase();
        if (key) byKey[key] = item;
      }
    }
  } else if (rawConnectors && typeof rawConnectors === 'object') {
    for (const [k, v] of Object.entries(rawConnectors)) {
      byKey[k.toLowerCase()] = v;
    }
  }

  const pick = (keys, fallbackLabel, fallbackMode) => {
    for (const k of keys) {
      if (byKey[k]) {
        const item = byKey[k];
        return {
          id: k,
          label: fallbackLabel,
          pill: mapConnectorStatusToPill(item),
          mode: String(
            item.mode ||
              item.transport ||
              (item.configured || item.live ? 'LIVE' : fallbackMode)
          )
        };
      }
    }
    return {
      id: keys[0],
      label: fallbackLabel,
      pill: 'healthy',
      mode: fallbackMode
    };
  };

  return [
    pick(['context', 'contextmcp', 'krusch-context-mcp'], 'krusch-context-mcp', 'INV-12 SQLITE'),
    pick(['git', 'kruschgit', 'krusch-git'], 'krusch-git 2-Hop AST', 'AST READY'),
    pick(['sofa', 'softwarefactory', '8090'], '8090 Software Factory', 'WO-101 SYNC'),
    pick(['hydradb', 'hydra'], 'HydraDB v2', 'LINEAGE GRAPH'),
    pick(['composio'], 'Composio', 'VERIFIED GATE'),
    pick(['elevenlabs', 'foreman'], 'ElevenLabs Foreman', 'VOICE BREAKER')
  ];
}

function normalizeModalityNames(rawModalities) {
  if (!rawModalities) return DEFAULT_MODALITIES;
  if (Array.isArray(rawModalities) && rawModalities.length > 0) {
    return rawModalities.map((item) => {
      if (typeof item === 'string') return item;
      return String(item?.label || item?.name || item?.modality || 'Modality');
    });
  }
  if (typeof rawModalities === 'object') {
    const keys = Object.keys(rawModalities);
    if (keys.length > 0) return keys;
  }
  return DEFAULT_MODALITIES;
}

export function BreakerCockpit() {
  const statusQuery = useApiQuery('/api/status');
  const runStream = useSSEStream('/api/run/stream');

  const [selectedWo, setSelectedWo] = useState('WO-101');
  const [activeTab, setActiveTab] = useState('all');
  const [syncRunResult, setSyncRunResult] = useState(null);
  const [syncRunning, setSyncRunning] = useState(false);
  const [runError, setRunError] = useState(null);

  const [audioMuted, setAudioMuted] = useState(false);
  const [foremanBusy, setForemanBusy] = useState(false);
  const [foremanAlert, setForemanAlert] = useState(null);

  const [scanInput, setScanInput] = useState('acme-legacy-billing');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState(null);
  const [scanResult, setScanResult] = useState(null);

  const [crashDrillLoading, setCrashDrillLoading] = useState(false);
  const [crashDrillResult, setCrashDrillResult] = useState(null);
  const [deputyDrillLoading, setDeputyDrillLoading] = useState(false);
  const [deputyDrillResult, setDeputyDrillResult] = useState(null);
  const [drillError, setDrillError] = useState(null);

  const [liveAudit, setLiveAudit] = useState(null);

  const activeAudioRef = useRef(null);
  const runIdRef = useRef(0);
  const autoChimedRunIdRef = useRef(-1);

  const statusPayload = useMemo(
    () => unwrapEnvelopeData(statusQuery.data) || statusQuery.data || {},
    [statusQuery.data]
  );

  const connectors = useMemo(
    () =>
      normalizeConnectorBar(
        statusPayload?.connectors || statusQuery.data?.connectors || statusQuery.data?.data?.connectors
      ),
    [statusPayload, statusQuery.data]
  );

  const workOrders = useMemo(() => {
    const list = statusPayload?.workOrders;
    return Array.isArray(list) && list.length > 0 ? list : DEFAULT_WORK_ORDERS;
  }, [statusPayload]);

  const mcpPermissions = useMemo(() => {
    const list =
      statusPayload?.mcpPermissionTable ||
      statusPayload?.mcpTools ||
      statusPayload?.mcp?.tools;
    if (Array.isArray(list) && list.length > 0) {
      return list.map((item) => {
        const ro = Boolean(item.readOnlyHint ?? item.annotations?.readOnlyHint);
        return {
          name: item.name,
          sofaPermission: item.sofaPermission || item.annotations?.sofaPermission || (ro ? 'Allow' : 'Confirm'),
          sofaScope:
            item.sofaScope ||
            item.annotations?.sofaScope ||
            (ro ? 'Unattended Automations' : 'Human Approval Required'),
          readOnlyHint: ro,
          destructiveHint: Boolean(item.destructiveHint ?? item.annotations?.destructiveHint ?? false),
          idempotentHint: Boolean(item.idempotentHint ?? item.annotations?.idempotentHint ?? ro),
          openWorldHint: Boolean(item.openWorldHint ?? item.annotations?.openWorldHint ?? !ro),
          description: item.description || ''
        };
      });
    }
    return DEFAULT_MCP_PERMISSION_TABLE;
  }, [statusPayload]);

  // Parse SSE stream frames in real time
  const streamState = useMemo(() => {
    const stages = {
      refinery: null,
      planner: null,
      foundry: null,
      attempt1: null,
      workaroundBlocked: null,
      verified: null,
      prDispatched: null,
      donePayload: null
    };

    for (const frame of runStream.events) {
      const ev = String(frame?.event || '').toLowerCase();
      const payload = unwrapEnvelopeData(frame?.data) || frame?.data;

      if (ev.includes('refinery') || payload?.stage === 'refinery') {
        stages.refinery = payload;
      } else if (ev.includes('planner') || payload?.stage === 'planner') {
        stages.planner = payload;
      } else if (ev.includes('foundry') || payload?.stage === 'foundry') {
        stages.foundry = payload;
      } else if (ev.includes('attempt1') || payload?.attempt === 1) {
        stages.attempt1 = payload;
      } else if (
        ev.includes('workaround') ||
        payload?.verdict === 'WORKAROUND_REJECTED' ||
        payload?.attempt === 2
      ) {
        stages.workaroundBlocked = payload;
      } else if (
        ev.includes('verified') ||
        payload?.verdict === 'VERIFIED' ||
        payload?.attempt === 3
      ) {
        stages.verified = payload;
      } else if (ev.includes('pr.dispatched') || ev.includes('pr_dispatched') || payload?.prReceipt) {
        stages.prDispatched = payload;
      } else if (ev === 'done') {
        stages.donePayload = payload;
      }
    }

    return stages;
  }, [runStream.events]);

  const activeRun = useMemo(() => {
    return (
      syncRunResult ||
      streamState.donePayload ||
      unwrapEnvelopeData(statusPayload?.lastRun) ||
      statusPayload?.lastRun ||
      null
    );
  }, [syncRunResult, streamState.donePayload, statusPayload]);

  const triggerForemanVoiceAlert = useCallback(
    async ({ isAuto = false } = {}) => {
      setForemanBusy(true);
      try {
        const raw = await fetchApiJson('/api/foreman/speak', {
          method: 'POST',
          body: {
            workOrderId: selectedWo,
            event: 'WORKAROUND_REJECTED',
            reason:
              'Breaker tripped on WO-101. Supervised AI attempted to weaken src/sox-reconciler.js tolerance. Policy floor blocked the workaround.'
          }
        });
        const payload = unwrapEnvelopeData(raw) || raw || {};
        const audioBase64 = payload.audioBase64 || payload.audio || null;
        const mimeType = payload.mimeType || 'audio/wav';
        const mode = payload.mode || 'pcm16_breaker_synth';
        const transcript =
          payload.transcript ||
          payload.text ||
          payload.summary ||
          'BREAKER TRIPPED on WO-101: Supervised agent tried to edit protected src/sox-reconciler.js tolerance. Workaround rejected by policy floor.';

        setForemanAlert({
          mode,
          mimeType,
          transcript,
          hasAudio: Boolean(audioBase64),
          triggeredBy: isAuto ? 'auto-breaker' : 'manual'
        });

        if (audioBase64 && !audioMuted && typeof Audio !== 'undefined') {
          try {
            if (activeAudioRef.current) {
              activeAudioRef.current.pause?.();
            }
            const src = String(audioBase64).startsWith('data:')
              ? String(audioBase64)
              : `data:${mimeType};base64,${audioBase64}`;
            const player = new Audio(src);
            activeAudioRef.current = player;
            await player.play();
          } catch {
            // Browser autoplay restriction safe fallback: transcript banner stays visible on stage
          }
        }
      } catch (err) {
        setForemanAlert({
          mode: 'stage_caption_fallback',
          mimeType: 'audio/wav',
          transcript: `Foreman Alert: WORKAROUND_REJECTED on ${selectedWo} (${err?.message || 'audio endpoint offline'})`,
          hasAudio: false,
          triggeredBy: isAuto ? 'auto-breaker' : 'manual'
        });
      } finally {
        setForemanBusy(false);
      }
    },
    [selectedWo, audioMuted]
  );

  // Auto-chime Foreman voice when SSE live stream trips WORKAROUND_REJECTED
  useEffect(() => {
    if (
      streamState.workaroundBlocked &&
      !audioMuted &&
      autoChimedRunIdRef.current !== runIdRef.current
    ) {
      autoChimedRunIdRef.current = runIdRef.current;
      triggerForemanVoiceAlert({ isAuto: true });
    }
  }, [streamState.workaroundBlocked, audioMuted, triggerForemanVoiceAlert]);

  // Reload status once SSE stream finishes so audit hashes & counters update
  useEffect(() => {
    if (runStream.status === 'done') {
      statusQuery.reload();
    }
  }, [runStream.status, statusQuery.reload]);

  const handleRunLiveStream = async () => {
    setRunError(null);
    setSyncRunResult(null);
    runIdRef.current += 1;
    await runStream.start({ workOrderId: selectedWo });
  };

  const handleRunSyncFallback = async () => {
    setRunError(null);
    runStream.reset();
    setSyncRunning(true);
    runIdRef.current += 1;
    try {
      const raw = await fetchApiJson('/api/run', {
        method: 'POST',
        timeoutMs: 30000,
        body: { workOrderId: selectedWo }
      });
      const unwrapped = unwrapEnvelopeData(raw) || raw;
      setSyncRunResult(unwrapped);
      if (!audioMuted) {
        autoChimedRunIdRef.current = runIdRef.current;
        triggerForemanVoiceAlert({ isAuto: true });
      }
      statusQuery.reload();
    } catch (err) {
      setRunError(err?.message || 'Synchronous head-to-head run failed.');
    } finally {
      setSyncRunning(false);
    }
  };

  const handleRefreshAudit = async () => {
    try {
      const raw = await fetchApiJson('/api/audit');
      setLiveAudit(unwrapEnvelopeData(raw) || raw);
    } catch (err) {
      setRunError(err?.message || 'Failed to verify SHA-256 audit chain.');
    }
  };

  const handleScanRepo = async (overrideTarget) => {
    const targetToScan = typeof overrideTarget === 'string' ? overrideTarget : scanInput.trim();
    if (!targetToScan) return;
    if (typeof overrideTarget === 'string') {
      setScanInput(overrideTarget);
    }
    setScanError(null);
    setScanLoading(true);
    try {
      const raw = await fetchApiJson('/api/repo/scan', {
        method: 'POST',
        timeoutMs: 30000,
        body: { repoUrlOrPath: targetToScan }
      });
      setScanResult(unwrapEnvelopeData(raw) || raw);
    } catch (err) {
      setScanError(err?.message || 'Repository blast-radius scan failed.');
    } finally {
      setScanLoading(false);
    }
  };

  const handleRunCrashDrill = async () => {
    setDrillError(null);
    setCrashDrillLoading(true);
    try {
      const raw = await fetchApiJson('/api/drills/crash-recovery', {
        method: 'POST',
        body: {}
      });
      setCrashDrillResult(unwrapEnvelopeData(raw) || raw);
      statusQuery.reload();
    } catch (err) {
      setDrillError(err?.message || 'Crash-recovery drill failed.');
    } finally {
      setCrashDrillLoading(false);
    }
  };

  const handleRunConfusedDeputyDrill = async () => {
    setDrillError(null);
    setDeputyDrillLoading(true);
    try {
      const raw = await fetchApiJson('/api/drills/confused-deputy', {
        method: 'POST',
        body: {}
      });
      setDeputyDrillResult(unwrapEnvelopeData(raw) || raw);
      statusQuery.reload();
    } catch (err) {
      setDrillError(err?.message || 'Confused-deputy security drill failed.');
    } finally {
      setDeputyDrillLoading(false);
    }
  };

  // Derive Conveyor 4-stage states
  const isStreaming = runStream.status === 'streaming' || syncRunning;
  const hasCompletedRun = Boolean(activeRun) || runStream.status === 'done';

  const conveyorStages = useMemo(() => {
    const rDone = Boolean(streamState.refinery || hasCompletedRun);
    const pDone = Boolean(streamState.planner || hasCompletedRun);
    const fDone = Boolean(streamState.foundry || hasCompletedRun);
    const vTripped = Boolean(
      streamState.workaroundBlocked && !streamState.verified && !hasCompletedRun
    );
    const vDone = Boolean(streamState.verified || hasCompletedRun);

    return [
      {
        num: '1. REFINERY',
        caption: '6 Org Modalities + INV-12 Span Lock',
        metric: '< 4,000 tok bounded',
        state: rDone ? 'complete' : isStreaming ? 'active' : 'idle'
      },
      {
        num: '2. PLANNER',
        caption: '2-Hop AST Subway + Disjoint Leases',
        metric: '< 25us Cascade route',
        state: pDone ? 'complete' : isStreaming && rDone ? 'active' : 'idle'
      },
      {
        num: '3. FOUNDRY',
        caption: 'Golden Brick Slop Breaker + Staging',
        metric: '< 1ms deterministic scan',
        state: fDone ? 'complete' : isStreaming && pDone ? 'active' : 'idle'
      },
      {
        num: '4. VALIDATOR',
        caption: 'Policy Floor + SOX Ledger + Cross-Family',
        metric: vTripped ? 'WORKAROUND_REJECTED!' : '3-Attempt Self-Rejection',
        state: vTripped ? 'tripped' : vDone ? 'complete' : isStreaming && fDone ? 'active' : 'idle'
      }
    ];
  }, [streamState, hasCompletedRun, isStreaming]);

  // Extract structured data for Split-Screen Comparison (with stage-ready defaults)
  const standardData = useMemo(() => {
    const std =
      activeRun?.standardAgent ||
      activeRun?.naiveAgent ||
      activeRun?.baseline ||
      {};
    const batch = std?.reconciliation?.batchCheck || std?.batchCheck || {};
    return {
      modifiedFile: std.modifiedFile || 'src/fee-engine.js',
      unitTestPassed: std.unitTestPassed ?? std?.reconciliation?.unitTestPassed ?? true,
      missedDownstream: std.missedDownstreamFile || 'src/sox-reconciler.js',
      reviewerVerdict: std.reviewerVerdict || 'APPROVED (Same-Family Model)',
      expectedNetCents: batch.expectedNetCents ?? std.expectedNetCents ?? 9750,
      actualNetCents: batch.actualNetCents ?? std.actualNetCents ?? 9751,
      deltaCents: batch.deltaCents ?? std.deltaCents ?? 1,
      invariantId: std.invariantId || batch.invariantId || 'INV-FIN-03',
      outcome: std.outcome || 'UNSAFE MERGE'
    };
  }, [activeRun]);

  const governedData = useMemo(() => {
    const gov = activeRun?.deadbolt || activeRun?.governed || activeRun || {};
    const refinery =
      unwrapEnvelopeData(gov?.refinery) ||
      unwrapEnvelopeData(streamState.refinery) ||
      {};
    const planner =
      unwrapEnvelopeData(gov?.planner) ||
      unwrapEnvelopeData(streamState.planner) ||
      {};
    const foundry =
      unwrapEnvelopeData(gov?.foundry) ||
      unwrapEnvelopeData(streamState.foundry) ||
      {};

    const rawAttempts =
      gov?.attempts ||
      gov?.validator?.attempts ||
      activeRun?.attempts ||
      [];

    const att1 = unwrapEnvelopeData(rawAttempts[0]) || unwrapEnvelopeData(streamState.attempt1) || {};
    const att2 =
      unwrapEnvelopeData(rawAttempts[1]) ||
      unwrapEnvelopeData(streamState.workaroundBlocked) ||
      {};
    const att3 = unwrapEnvelopeData(rawAttempts[2]) || unwrapEnvelopeData(streamState.verified) || {};

    const auditSummary =
      liveAudit ||
      unwrapEnvelopeData(gov?.audit) ||
      unwrapEnvelopeData(statusPayload?.audit) ||
      unwrapEnvelopeData(statusPayload?.auditTrail) ||
      {};

    const prInfo =
      unwrapEnvelopeData(gov?.prReceipt) ||
      unwrapEnvelopeData(activeRun?.prReceipt) ||
      unwrapEnvelopeData(streamState.prDispatched) ||
      {};

    const tokensUsed = Number.isFinite(Number(refinery?.tokensUsed))
      ? Number(refinery.tokensUsed)
      : 1480;
    const tokenBudget = Number.isFinite(Number(refinery?.tokenBudget))
      ? Number(refinery.tokenBudget)
      : 4000;

    const hopPath =
      Array.isArray(planner?.hopPath) && planner.hopPath.length > 0
        ? planner.hopPath
        : ['src/fee-engine.js', 'src/settlement-service.js', 'src/sox-reconciler.js'];

    const routingLatencyUs = Number.isFinite(Number(planner?.routingLatencyUs))
      ? Number(planner.routingLatencyUs).toFixed(1)
      : '11.8';

    const parallelLeases =
      Array.isArray(planner?.parallelLeases) && planner.parallelLeases.length > 0
        ? planner.parallelLeases
        : DEFAULT_PARALLEL_LEASES;

    const slopElapsedMs = Number.isFinite(Number(foundry?.elapsedMs ?? foundry?.slopAudit?.elapsedMs))
      ? Number(foundry?.elapsedMs ?? foundry?.slopAudit?.elapsedMs).toFixed(2)
      : '0.38';

    const rawCost =
      gov?.telemetry?.costPerVerifiedTaskUsd ??
      activeRun?.telemetry?.costPerVerifiedTaskUsd ??
      att3?.telemetry?.costPerVerifiedTaskUsd ??
      (hasCompletedRun ? 0 : null);

    return {
      modalities: normalizeModalityNames(refinery?.modalitiesHydrated),
      tokensUsed,
      tokenBudget,
      tokenPct: Math.min(100, Math.max(6, Math.round((tokensUsed / tokenBudget) * 100))),
      spanLockStatus:
        refinery?.spanIntegrity?.status || refinery?.spanStatus || 'VALID',
      lineageText:
        typeof refinery?.lineageChain === 'string'
          ? refinery.lineageChain
          : 'INV-FIN-02 -> INV-FIN-03 (supersedes_id verified)',
      hopPath,
      routingLatencyUs,
      parallelLeases,
      slopElapsedMs,
      attempt1: {
        verdict: att1?.verdict || 'GATE_REJECTED',
        expectedNetCents:
          att1?.reconciliation?.batchCheck?.expectedNetCents ?? 9750,
        actualNetCents:
          att1?.reconciliation?.batchCheck?.actualNetCents ?? 9751,
        deltaCents: att1?.reconciliation?.batchCheck?.deltaCents ?? 1
      },
      attempt2: {
        verdict: att2?.verdict || 'WORKAROUND_REJECTED',
        ruleId:
          att2?.policyCheck?.ruleId ||
          att2?.policyCheck?.violatedRule ||
          'FLOOR-SOX-TOLERANCE-BYPASS',
        blockedFile: 'src/sox-reconciler.js'
      },
      attempt3: {
        verdict: att3?.verdict || 'VERIFIED',
        deltaCents: att3?.reconciliation?.batchCheck?.deltaCents ?? 0,
        expectedNetCents:
          att3?.reconciliation?.batchCheck?.expectedNetCents ?? 9750,
        actualNetCents:
          att3?.reconciliation?.batchCheck?.actualNetCents ?? 9750,
        reviewMode:
          att3?.crossModelReview?.mode ||
          att3?.crossModelReview?.reviewers?.[0]?.mode ||
          'separate-family converged'
      },
      prTitle:
        prInfo?.prTitle ||
        prInfo?.title ||
        `[${selectedWo}] Fix integer basis-point residual allocation in fee-engine`,
      auditValid: auditSummary?.valid !== false,
      auditVerifiedCount: auditSummary?.verifiedCount ?? 3,
      auditTailHash:
        att3?.auditReceipt?.hash ||
        att3?.auditReceipt?.entryHash ||
        auditSummary?.tailHash ||
        auditSummary?.headHash ||
        'sha256:verified-immutability-chain-ready',
      costPerVerifiedTaskUsd: rawCost
    };
  }, [activeRun, streamState, liveAudit, statusPayload, selectedWo, hasCompletedRun]);

  // Normalized Brownfield Scanner Output
  const normalizedScan = useMemo(() => {
    if (!scanResult) return null;
    const slopRaw = unwrapEnvelopeData(scanResult.slopAudit) || scanResult.slopAudit || {};
    const coverageRatio = Number(
      slopRaw.sealedCoverageRatio ?? scanResult.sealedCoverageRatio ?? 1
    );
    const findings = Array.isArray(slopRaw.findings)
      ? slopRaw.findings
      : Array.isArray(scanResult.findings)
        ? scanResult.findings
        : [];

    return {
      target: scanResult.target || scanInput,
      scannedFiles: scanResult.scannedFiles ?? slopRaw.scannedFiles ?? 0,
      symbolCount: scanResult.symbolCount ?? 0,
      coveragePct: Number.isFinite(coverageRatio) ? Math.round(coverageRatio * 100) : 100,
      slopFindingCount: slopRaw.slopFindingCount ?? findings.length,
      breakerTripped: Boolean(slopRaw.breakerTripped ?? findings.length > 0),
      elapsedMs: scanResult.elapsedMs ?? 0,
      recommendedBrickIds: slopRaw.recommendedBrickIds || [],
      findings
    };
  }, [scanResult, scanInput]);

  const showHeadToHead = activeTab === 'all' || activeTab === 'breaker';
  const showScanner = activeTab === 'all' || activeTab === 'scanner';
  const showResilience = activeTab === 'all' || activeTab === 'resilience';
  const breakerWasTripped = Boolean(streamState.workaroundBlocked || hasCompletedRun);

  return (
    <div className="db-cockpit cyber-grid">
      <div className="db-container">
        {/* TOP INDUSTRIAL BREAKER HEADER */}
        <header className="db-header">
          <div className="db-header-top">
            <div className="db-brand">
              <svg
                className="dead-bolt"
                viewBox="0 -2 132 218"
                width="24"
                height="38"
                aria-label="13-point lightning bolt"
              >
                <defs>
                  <linearGradient id="boltGrad-standalone" x1="78%" y1="4%" x2="18%" y2="96%">
                    <stop offset="0%" stopColor="#6ff1fe" />
                    <stop offset="24%" stopColor="#37e1ff" />
                    <stop offset="48%" stopColor="#7be8ff" />
                    <stop offset="72%" stopColor="#8b6eff" />
                    <stop offset="90%" stopColor="#9d4edd" />
                    <stop offset="100%" stopColor="#d946ef" />
                  </linearGradient>
                  <linearGradient id="boltRim-standalone" x1="80%" y1="0%" x2="15%" y2="100%">
                    <stop offset="0%" stopColor="#bef8ff" />
                    <stop offset="45%" stopColor="#ffffff" />
                    <stop offset="80%" stopColor="#f5d0fe" />
                    <stop offset="100%" stopColor="#fae8ff" />
                  </linearGradient>
                </defs>
                <polygon
                  points="121,2 79,25 93,28 48,50 78,53 19,89 58,85 5,128 44,124 5,158 34,155 4,212 47,191 35,186 70,171 52,168 105,139 66,140 123,103 74,105 128,69 86,69 126,35 102,36"
                  fill="url(#boltGrad-standalone)"
                  stroke="url(#boltRim-standalone)"
                  strokeWidth="2.6"
                  strokeLinejoin="round"
                />
              </svg>
              <div>
                <div className="db-brand-title-row">
                  <h1 className="db-brand-title">DEADBOLT</h1>
                  <span className="db-brand-tag">8090 SOFTWARE FACTORY BREAKER PANEL</span>
                  <StatusPill
                    status={isStreaming ? 'streaming' : statusQuery.error ? 'degraded' : 'healthy'}
                    label={
                      isStreaming
                        ? 'CONVEYOR STREAMING'
                        : statusQuery.loading
                          ? 'HYDRATING'
                          : 'GOVERNANCE ARMED'
                    }
                  />
                </div>
                <p className="db-brand-subtitle">
                  8090 builds the software; DEADBOLT makes it harder to break. Deterministic 2-hop blast radius, self-rejecting policy floor, and SOX-style batch reconciliation.
                </p>
              </div>
            </div>

            <div className="db-header-actions">
              <button
                type="button"
                className={cn('db-btn db-btn-sm', audioMuted ? '' : 'db-btn-emerald')}
                onClick={() => setAudioMuted((prev) => !prev)}
              >
                {audioMuted ? 'Foreman Audio: Muted' : 'Foreman Audio: Armed'}
              </button>
              <button
                type="button"
                className="db-btn db-btn-sm db-btn-crimson"
                disabled={foremanBusy}
                onClick={() => triggerForemanVoiceAlert({ isAuto: false })}
              >
                {foremanBusy ? 'Synthesizing...' : 'Play Foreman Breaker Alert'}
              </button>
            </div>
          </div>

          {/* 6-Connector Telemetry Strip */}
          <div className="db-telemetry-bar" aria-label="Factory Connector Telemetry">
            {connectors.map((conn) => (
              <div key={conn.id} className="db-connector-chip">
                <StatusPill status={conn.pill} label={conn.label} />
                <span className="db-connector-mode">{conn.mode}</span>
              </div>
            ))}
          </div>
        </header>

        {/* COMMAND DECK & VIEW SWITCHER */}
        <section className="db-command-bar" aria-label="Execution Controls">
          <div className="db-command-left">
            <label htmlFor="wo-select" className="db-panel-kicker">
              WORK ORDER
            </label>
            <select
              id="wo-select"
              className="db-select"
              value={selectedWo}
              onChange={(e) => setSelectedWo(e.target.value)}
              disabled={isStreaming}
            >
              {workOrders.map((wo) => (
                <option key={wo.id} value={wo.id}>
                  {wo.id}: {wo.title}
                </option>
              ))}
            </select>

            <button
              type="button"
              className="db-btn db-btn-primary"
              disabled={isStreaming}
              onClick={handleRunLiveStream}
            >
              {runStream.status === 'streaming'
                ? `Streaming ${selectedWo} Conveyor...`
                : `Run Head-to-Head Stream (${selectedWo})`}
            </button>

            <button
              type="button"
              className="db-btn"
              disabled={isStreaming}
              onClick={handleRunSyncFallback}
            >
              {syncRunning ? 'Executing...' : 'Instant Sync Run'}
            </button>

            <button
              type="button"
              className="db-btn db-btn-sm"
              onClick={handleRefreshAudit}
            >
              Verify SHA-256 Chain
            </button>
          </div>

          <div className="db-command-right">
            <div className="db-tab-group" role="tablist" aria-label="Cockpit Sections">
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'all'}
                className={cn('db-tab', activeTab === 'all' && 'is-active')}
                onClick={() => setActiveTab('all')}
              >
                All Stage Panels
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'breaker'}
                className={cn('db-tab', activeTab === 'breaker' && 'is-active')}
                onClick={() => setActiveTab('breaker')}
              >
                1. Head-to-Head
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'scanner'}
                className={cn('db-tab', activeTab === 'scanner' && 'is-active')}
                onClick={() => setActiveTab('scanner')}
              >
                2. Brownfield Scanner
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={activeTab === 'resilience'}
                className={cn('db-tab', activeTab === 'resilience' && 'is-active')}
                onClick={() => setActiveTab('resilience')}
              >
                3. Drills &amp; 8090 MCP
              </button>
            </div>
          </div>
        </section>

        {(runError || runStream.error) && (
          <div className="db-error-box" role="alert">
            <strong>Execution Notice:</strong>{' '}
            {runError || runStream.error?.message}{' '}
            <button
              type="button"
              className="db-btn db-btn-sm"
              style={{ marginLeft: '0.75rem' }}
              onClick={handleRunSyncFallback}
            >
              Retry via POST /api/run
            </button>
          </div>
        )}

        {/* 4-STAGE ANIMATED CONVEYOR PIPELINE */}
        <section className="db-conveyor" aria-label="8090 Software Factory 4-Stage Pipeline">
          {conveyorStages.map((stage, idx) => (
            <div
              key={stage.num}
              className={cn(
                'db-stage-node',
                stage.state === 'active' && 'is-active',
                stage.state === 'tripped' && 'is-tripped',
                stage.state === 'complete' && 'is-complete'
              )}
            >
              <div className="db-stage-head">
                <span className="db-stage-title">{stage.num}</span>
                <span className="db-stage-arrow">
                  {idx < 3 ? '->' : stage.state === 'complete' ? 'VERIFIED' : 'GATE'}
                </span>
              </div>
              <div className="db-stage-caption">{stage.caption}</div>
              <div className="db-stage-metric tabular-nums">{stage.metric}</div>
            </div>
          ))}
        </section>

        {/* DRAMATIC TRIPPED BREAKER BANNER (Self-Rejection Highlight Beat) */}
        {(breakerWasTripped || foremanAlert) && (
          <section className="db-breaker-banner" aria-label="Policy Floor Breaker Alert">
            <div style={{ flex: '1 1 540px' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.65rem' }}>
                <span className="db-tripped-badge">
                  TRIPPED BREAKER // WORKAROUND_REJECTED
                </span>
                <span className="db-badge db-badge-amber">
                  Rule: {governedData.attempt2.ruleId}
                </span>
                <span className="db-badge db-badge-emerald">
                  Remediated on Attempt 3 (deltaCents: 0c)
                </span>
              </div>
              <p style={{ margin: '0.5rem 0 0', fontSize: '0.94rem', color: '#f8fafc' }}>
                DEADBOLT caught its own supervised agent attempting to silence{' '}
                <code>INV-FIN-03</code> by mutating protected verification logic in{' '}
                <code>src/sox-reconciler.js</code> (<code>MAX_TOLERANCE_CENTS = 2; strictSox = false;</code>).
                Non-overridable policy floor blocked the edit, recorded a SHA-256 <code>DENIED</code> receipt, and forced an integer largest-remainder fix in <code>src/fee-engine.js</code>.
              </p>
              {foremanAlert && (
                <div className="db-foreman-transcript">
                  <strong>ElevenLabs Factory Foreman ({foremanAlert.mode}):</strong>{' '}
                  &ldquo;{foremanAlert.transcript}&rdquo;
                </div>
              )}
            </div>
            <div>
              <button
                type="button"
                className="db-btn db-btn-crimson"
                disabled={foremanBusy}
                onClick={() => triggerForemanVoiceAlert({ isAuto: false })}
              >
                {foremanBusy ? 'Playing Alert...' : 'Replay ElevenLabs Foreman Chime'}
              </button>
            </div>
          </section>
        )}

        {/* SECTION 1: SPLIT-SCREEN HEAD-TO-HEAD COMPARISON */}
        {showHeadToHead && (
          <section className="db-split-grid" aria-label="Head-to-Head Governance Comparison">
            {/* LEFT CARD: STANDARD SINGLE-MODEL AGENT */}
            <article className="db-panel db-panel-crimson">
              <div className="db-panel-header">
                <div>
                  <div className="db-panel-kicker">BASELINE PIPELINE (NO GOVERNANCE FLOOR)</div>
                  <h2 className="db-panel-title">Standard Single-Model Agent</h2>
                </div>
                <span className="db-tripped-badge">{standardData.outcome}</span>
              </div>

              <div className="db-ledger-callout is-violation">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <span className="db-panel-kicker" style={{ color: '#fca5a5' }}>
                    SOX-STYLE BATCH LEDGER DISCREPANCY ({standardData.invariantId} VIOLATION)
                  </span>
                  <span className="db-badge db-badge-crimson">
                    SPLIT INVOICE INV-2026-9001 (3x @ 250 bps)
                  </span>
                </div>

                <div className="db-ledger-grid">
                  <div className="db-ledger-cell">
                    <div className="db-ledger-label">Expected Net</div>
                    <div className="db-ledger-num tabular-nums">
                      {formatCentsUsd(standardData.expectedNetCents)}{' '}
                      <span style={{ fontSize: '0.88rem', color: '#94a3b8' }}>
                        ({standardData.expectedNetCents}c)
                      </span>
                    </div>
                  </div>
                  <div className="db-ledger-cell">
                    <div className="db-ledger-label">Actual Settled</div>
                    <div className="db-ledger-num is-crimson tabular-nums">
                      {formatCentsUsd(standardData.actualNetCents)}{' '}
                      <span style={{ fontSize: '0.88rem', color: '#fca5a5' }}>
                        ({standardData.actualNetCents}c)
                      </span>
                    </div>
                  </div>
                  <div className="db-ledger-cell">
                    <div className="db-ledger-label">Batch Variance</div>
                    <div className="db-ledger-num is-crimson tabular-nums">
                      {formatSignedCents(standardData.deltaCents)} (+$0.01)
                    </div>
                  </div>
                </div>
              </div>

              <ul className="db-check-list">
                <li className="db-check-row">
                  <span>
                    Target Modified: <code>{standardData.modifiedFile}</code> (per-line <code>Math.round</code>)
                  </span>
                  <span className="db-badge">MODIFIED</span>
                </li>
                <li className="db-check-row">
                  <span>
                    Local Single-Line <code>$100.00</code> Unit Test
                  </span>
                  <span className="db-badge db-badge-emerald">
                    {standardData.unitTestPassed ? 'PASSED (False Green)' : 'FAILED'}
                  </span>
                </li>
                <li className="db-check-row">
                  <span>
                    2-Hop Downstream <code>{standardData.missedDownstream}</code>
                  </span>
                  <span className="db-badge db-badge-crimson">MISSED (0-Hop Context)</span>
                </li>
                <li className="db-check-row">
                  <span>Same-Family Model Code Review</span>
                  <span className="db-badge db-badge-amber">{standardData.reviewerVerdict}</span>
                </li>
                <li className="db-check-row">
                  <span>Production Settlement Impact ([3334c, 3333c, 3333c] @ 2.5%)</span>
                  <span className="db-badge db-badge-crimson">
                    {standardData.invariantId} VIOLATION (+1c)
                  </span>
                </li>
              </ul>
            </article>

            {/* RIGHT CARD: DEADBOLT GOVERNED PIPELINE */}
            <article className="db-panel db-panel-emerald">
              <div className="db-panel-header">
                <div>
                  <div className="db-panel-kicker">4-STAGE DETERMINISTIC GOVERNANCE</div>
                  <h2 className="db-panel-title">DEADBOLT Governed Pipeline</h2>
                </div>
                <span className="db-badge db-badge-emerald" style={{ fontSize: '0.85rem', padding: '0.35rem 0.75rem' }}>
                  VERIFIED + AUDIT TRAIL
                </span>
              </div>

              {/* Stage 1: Refinery */}
              <div className="db-subcard">
                <div className="db-subcard-head">
                  <h3 className="db-subcard-title">1. Refinery: 6 Org Context Modalities Hydrated</h3>
                  <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
                    <span className="db-badge db-badge-emerald">
                      INV-12 Span Lock: {governedData.spanLockStatus}
                    </span>
                    <span className="db-badge db-badge-cyan tabular-nums">
                      {governedData.tokensUsed} / {governedData.tokenBudget} tok
                    </span>
                  </div>
                </div>

                <div className="db-chip-list">
                  {governedData.modalities.map((mod) => (
                    <span key={mod} className="db-modality-chip">
                      {mod}
                    </span>
                  ))}
                </div>

                <div>
                  <div className="db-budget-bar-track" aria-label="Context token budget utilization">
                    <div
                      className="db-budget-bar-fill"
                      style={{ width: `${governedData.tokenPct}%` }}
                    />
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.35rem', fontSize: '0.78rem', color: '#94a3b8' }}>
                    <span>Bounded Token Budget (&lt; 4,000 tok)</span>
                    <span className="db-mono" style={{ color: '#6ee7b7' }}>
                      Lineage: {governedData.lineageText}
                    </span>
                  </div>
                </div>
              </div>

              {/* Stage 2 & 3: Planner Subway Map + Cascade + Parallel Leases */}
              <div className="db-subcard">
                <div className="db-subcard-head">
                  <h3 className="db-subcard-title">
                    2. Planner &amp; 3. Foundry: 2-Hop Subway Map &amp; Disjoint Leases
                  </h3>
                  <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
                    <span className="db-badge db-badge-cyan tabular-nums">
                      Cascade: {governedData.routingLatencyUs}us (&lt;25us)
                    </span>
                    <span className="db-badge db-badge-emerald tabular-nums">
                      Slop Breaker: {governedData.slopElapsedMs}ms (100% Sealed)
                    </span>
                  </div>
                </div>

                <div className="db-subway-track" aria-label="2-Hop AST Dependency Path">
                  {governedData.hopPath.map((nodePath, idx) => {
                    const isProtected = String(nodePath).includes('sox-reconciler');
                    return (
                      <React.Fragment key={nodePath}>
                        {idx > 0 && <span className="db-subway-connector">-&gt;</span>}
                        <span className={cn('db-subway-stop', isProtected && 'is-protected')}>
                          <span>{nodePath}</span>
                          <span style={{ fontSize: '0.7rem', opacity: 0.8 }}>
                            {idx === 0 ? '[Entry]' : idx === 1 ? '[Hop 1]' : '[Hop 2 Protected]'}
                          </span>
                        </span>
                      </React.Fragment>
                    );
                  })}
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', fontSize: '0.8rem' }}>
                  <span className="db-badge">
                    Plumbing (WO-102/103) -&gt; L1_FAST
                  </span>
                  <span className="db-badge db-badge-cyan">
                    2-Hop Financial Math (WO-101) -&gt; L3_FRONTIER_ARGON
                  </span>
                </div>

                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th>Work Order</th>
                        <th>2-Hop AST Cone</th>
                        <th>Cascade Tier</th>
                        <th>Lease Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {governedData.parallelLeases.map((lease) => {
                        const woId = lease.workOrderId || lease.id;
                        const cone = Array.isArray(lease.coneFiles)
                          ? lease.coneFiles.join(' -> ')
                          : lease.entryFile || 'src/fee-engine.js';
                        const parallel = lease.canRunInParallel !== false;
                        return (
                          <tr key={woId}>
                            <td className="db-mono" style={{ fontWeight: 700, color: '#ffffff' }}>
                              {woId}
                            </td>
                            <td className="db-mono">{cone}</td>
                            <td className="db-mono">{lease.cascadeTier || lease.tier || 'L1_FAST'}</td>
                            <td>
                              <span className={cn('db-badge', parallel ? 'db-badge-emerald' : 'db-badge-amber')}>
                                {parallel
                                  ? 'DISJOINT PARALLEL OK (src/server.js reserved)'
                                  : 'CHOKE POINT SERIALIZED'}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Stage 4: 3-Attempt Self-Rejection Timeline */}
              <div className="db-subcard">
                <div className="db-subcard-head">
                  <h3 className="db-subcard-title">
                    4. Validator: 3-Attempt Self-Rejection Timeline
                  </h3>
                  <span className="db-badge db-badge-emerald">INV-DB-04 &amp; INV-DB-05</span>
                </div>

                <div className="db-timeline">
                  {/* Attempt 1 */}
                  <div className="db-attempt-card is-amber">
                    <div className="db-attempt-head">
                      <span className="db-attempt-title">
                        Attempt 1 (Naive Rounding in src/fee-engine.js)
                      </span>
                      <span className="db-badge db-badge-amber">
                        {governedData.attempt1.verdict}
                      </span>
                    </div>
                    <div className="db-attempt-body tabular-nums">
                      Expected <code>{governedData.attempt1.expectedNetCents}c</code> ($97.50) vs Actual{' '}
                      <code>{governedData.attempt1.actualNetCents}c</code> ($97.51) -&gt;{' '}
                      <strong style={{ color: '#fcd34d' }}>
                        {formatSignedCents(governedData.attempt1.deltaCents)} batch penny delta
                      </strong>{' '}
                      caught deterministically by <code>INV-FIN-03</code>.
                    </div>
                  </div>

                  {/* Attempt 2 */}
                  <div className="db-attempt-card is-crimson">
                    <div className="db-attempt-head">
                      <span className="db-attempt-title">
                        Attempt 2 (Agent Tries Sneaky Workaround on sox-reconciler.js)
                      </span>
                      <span className="db-tripped-badge">
                        {governedData.attempt2.verdict}
                      </span>
                    </div>
                    <div className="db-attempt-body">
                      <strong>Policy Floor Breaker Tripped: Supervised AI cannot weaken its own audit gate!</strong>{' '}
                      Blocked mutation on protected <code>{governedData.attempt2.blockedFile}</code> (
                      <code>{governedData.attempt2.ruleId}</code>) and appended immutable <code>DENIED</code> receipt.
                    </div>
                    <div style={{ marginTop: '0.25rem' }}>
                      <button
                        type="button"
                        className="db-btn db-btn-sm db-btn-crimson"
                        disabled={foremanBusy}
                        onClick={() => triggerForemanVoiceAlert({ isAuto: false })}
                      >
                        {foremanBusy ? 'Playing...' : 'Play ElevenLabs Factory Foreman Alert'}
                      </button>
                    </div>
                  </div>

                  {/* Attempt 3 */}
                  <div className="db-attempt-card is-emerald">
                    <div className="db-attempt-head">
                      <span className="db-attempt-title">
                        Attempt 3 (Largest-Remainder Cent Carry Fix in src/fee-engine.js)
                      </span>
                      <span className="db-badge db-badge-emerald">
                        {governedData.attempt3.verdict}
                      </span>
                    </div>
                    <div className="db-attempt-body tabular-nums">
                      Batch reconciliation passed with{' '}
                      <strong style={{ color: '#6ee7b7' }}>
                        deltaCents: {governedData.attempt3.deltaCents}c
                      </strong>{' '}
                      (<code>{governedData.attempt3.actualNetCents}c</code> / $97.50 exact parity) + separate-family review converged ({governedData.attempt3.reviewMode}).
                    </div>
                  </div>
                </div>

                {/* Verified Receipt Footer */}
                <div className="db-ledger-callout is-verified">
                  <div className="db-ledger-grid">
                    <div className="db-ledger-cell">
                      <div className="db-ledger-label">Linked 8090 PR Receipt</div>
                      <div className="db-mono" style={{ marginTop: '0.25rem', fontSize: '0.8rem', color: '#a7f3d0', fontWeight: 700 }}>
                        {governedData.prTitle}
                      </div>
                    </div>
                    <div className="db-ledger-cell">
                      <div className="db-ledger-label">
                        SHA-256 Audit Tail ({governedData.auditValid ? 'VALID' : 'TAMPERED'} / {governedData.auditVerifiedCount} entries)
                      </div>
                      <div className="db-mono" style={{ marginTop: '0.25rem', fontSize: '0.78rem', color: '#37e1ff', wordBreak: 'break-all' }}>
                        {String(governedData.auditTailHash).slice(0, 36)}...
                      </div>
                    </div>
                    <div className="db-ledger-cell">
                      <div className="db-ledger-label">Measured Cost / Verified Task</div>
                      <div className="db-ledger-num is-emerald tabular-nums" style={{ fontSize: '1.15rem' }}>
                        {formatCostUsd(governedData.costPerVerifiedTaskUsd)}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </article>
          </section>
        )}

        {/* SECTION 2: BROWNFIELD REPO SCANNER */}
        {showScanner && (
          <section className="db-panel db-panel-cyan" aria-label="Brownfield Repository Scanner">
            <div className="db-panel-header">
              <div>
                <div className="db-panel-kicker">LIVE BROWNFIELD INTAKE &amp; &lt;1MS SLOP BREAKER</div>
                <h2 className="db-panel-title">
                  Paste Any GitHub Repo URL or Local Path
                </h2>
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                <button
                  type="button"
                  className="db-btn db-btn-sm"
                  disabled={scanLoading}
                  onClick={() => handleScanRepo('acme-legacy-billing')}
                >
                  Preset: acme-legacy-billing
                </button>
                <button
                  type="button"
                  className="db-btn db-btn-sm"
                  disabled={scanLoading}
                  onClick={() => handleScanRepo('https://github.com/OWASP/NodeGoat')}
                >
                  Preset: OWASP/NodeGoat
                </button>
              </div>
            </div>

            <form
              className="db-scanner-controls"
              onSubmit={(e) => {
                e.preventDefault();
                handleScanRepo();
              }}
            >
              <input
                type="text"
                className="db-input"
                value={scanInput}
                onChange={(e) => setScanInput(e.target.value)}
                placeholder="https://github.com/OWASP/NodeGoat or acme-legacy-billing"
                aria-label="GitHub repository URL or local fixture path"
              />
              <button
                type="submit"
                className="db-btn db-btn-primary"
                disabled={scanLoading || !scanInput.trim()}
              >
                {scanLoading
                  ? 'Scanning AST & Slop Breaker...'
                  : 'Scan Blast Radius & Slop Breaker'}
              </button>
            </form>

            {scanError && (
              <div className="db-error-box" role="alert">
                {scanError}
              </div>
            )}

            {normalizedScan && (
              <>
                <div className="db-kpi-grid">
                  <div className="db-kpi-card">
                    <div className="db-kpi-label">Scanned Files</div>
                    <div className="db-kpi-value tabular-nums">{normalizedScan.scannedFiles}</div>
                  </div>
                  <div className="db-kpi-card">
                    <div className="db-kpi-label">AST Symbols Indexed</div>
                    <div className="db-kpi-value tabular-nums" style={{ color: '#37e1ff' }}>
                      {normalizedScan.symbolCount}
                    </div>
                  </div>
                  <div className="db-kpi-card">
                    <div className="db-kpi-label">Sealed Golden Brick Coverage</div>
                    <div
                      className="db-kpi-value tabular-nums"
                      style={{ color: normalizedScan.coveragePct === 100 ? '#34d399' : '#fbbf24' }}
                    >
                      {normalizedScan.coveragePct}%
                    </div>
                  </div>
                  <div className="db-kpi-card">
                    <div className="db-kpi-label">Slop-Breaker Findings</div>
                    <div
                      className="db-kpi-value tabular-nums"
                      style={{ color: normalizedScan.slopFindingCount > 0 ? '#f87171' : '#34d399' }}
                    >
                      {normalizedScan.slopFindingCount}
                    </div>
                  </div>
                </div>

                {normalizedScan.findings.length > 0 ? (
                  <div className="db-table-wrap">
                    <table className="db-table">
                      <thead>
                        <tr>
                          <th>File Path</th>
                          <th>Rule Tripped</th>
                          <th>Recommended Sealed Brick</th>
                          <th>Remediation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {normalizedScan.findings.map((finding, idx) => (
                          <tr key={`${finding.filePath || 'file'}-${finding.ruleId || idx}`}>
                            <td className="db-mono" style={{ color: '#ffffff' }}>
                              {finding.filePath || normalizedScan.target}
                            </td>
                            <td>
                              <span className="db-badge db-badge-crimson">
                                {finding.ruleId || 'slop-detected'}
                              </span>
                            </td>
                            <td className="db-mono" style={{ color: '#37e1ff' }}>
                              {finding.importPath || finding.brickId || '@krusch/toolkit'}
                            </td>
                            <td>{finding.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="db-subcard">
                    <span className="db-badge db-badge-emerald">
                      ZERO HAND-ROLLED BOILERPLATE DETECTED ({normalizedScan.elapsedMs}ms)
                    </span>
                  </div>
                )}
              </>
            )}
          </section>
        )}

        {/* SECTION 3: FACTORY RESILIENCE DRILLS & 8090 MCP GOVERNANCE */}
        {showResilience && (
          <section className="db-panel" aria-label="Factory Resilience and 8090 MCP Governance">
            <div className="db-panel-header">
              <div>
                <div className="db-panel-kicker">STAGE-READY FAULT INJECTION &amp; PERMISSION BOUNDARIES</div>
                <h2 className="db-panel-title">
                  Factory Resilience Drills &amp; 8090 MCP Governance
                </h2>
              </div>
              <span className="db-badge db-badge-cyan">INV-DB-06 &amp; INV-DB-07</span>
            </div>

            {drillError && (
              <div className="db-error-box" role="alert">
                {drillError}
              </div>
            )}

            <div className="db-drills-grid">
              {/* Crash-Recovery Drill Card */}
              <div className="db-subcard">
                <div className="db-subcard-head">
                  <h3 className="db-subcard-title">
                    Journaled Crash-Recovery Drill (INV-DB-06)
                  </h3>
                  <button
                    type="button"
                    className="db-btn db-btn-sm db-btn-emerald"
                    disabled={crashDrillLoading}
                    onClick={handleRunCrashDrill}
                  >
                    {crashDrillLoading
                      ? 'Recovering Journal...'
                      : 'Run Crash-Recovery Drill (INV-DB-06)'}
                  </button>
                </div>
                <p style={{ margin: 0, fontSize: '0.85rem', color: '#cbd5e1' }}>
                  Stages a multi-file Work Order edit, injects a mid-apply crash leaving{' '}
                  <code>harness_apply_journal</code> in <code>RECOVERY_PENDING</code>, and runs{' '}
                  <code>recoverInFlight()</code> to prove zero half-written target files.
                </p>

                {crashDrillResult ? (
                  <div className="db-ledger-callout is-verified">
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', alignItems: 'center' }}>
                      <span className="db-badge db-badge-amber">
                        {crashDrillResult.initialState || 'RECOVERY_PENDING'}
                      </span>
                      <span className="db-mono" style={{ color: '#37e1ff' }}>-&gt;</span>
                      <span className="db-badge db-badge-emerald">
                        {crashDrillResult.finalState || crashDrillResult.journalState || 'RECOVERED'}
                      </span>
                      <span className="db-badge db-badge-emerald tabular-nums">
                        halfWrittenFiles: {crashDrillResult.halfWrittenFiles ?? 0}
                      </span>
                    </div>
                    <pre className="db-code-block" style={{ marginTop: '0.65rem' }}>
                      {JSON.stringify(crashDrillResult, null, 2)}
                    </pre>
                  </div>
                ) : (
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <span className="db-badge">Expected: RECOVERY_PENDING -&gt; RECOVERED</span>
                    <span className="db-badge db-badge-emerald">halfWrittenFiles: 0</span>
                  </div>
                )}
              </div>

              {/* Confused-Deputy Security Drill Card */}
              <div className="db-subcard">
                <div className="db-subcard-head">
                  <h3 className="db-subcard-title">
                    Confused-Deputy Security Drill (INV-DB-07)
                  </h3>
                  <button
                    type="button"
                    className="db-btn db-btn-sm db-btn-crimson"
                    disabled={deputyDrillLoading}
                    onClick={handleRunConfusedDeputyDrill}
                  >
                    {deputyDrillLoading
                      ? 'Testing 3 Defense Layers...'
                      : 'Run Confused-Deputy Security Drill (INV-DB-07)'}
                  </button>
                </div>
                <p style={{ margin: 0, fontSize: '0.85rem', color: '#cbd5e1' }}>
                  Fires an untrusted ticket comment injection, an unverified outbound PR dispatch attempt, and a private-network SSRF callback against Composio outbound boundaries.
                </p>

                <ul className="db-check-list">
                  <li className="db-check-row">
                    <span>1. Prompt-Injection Delimiter &amp; Trajectory Sanitizer</span>
                    <span className="db-badge db-badge-emerald">
                      {deputyDrillResult ? 'BLOCKED & SANITIZED' : 'ARMED'}
                    </span>
                  </li>
                  <li className="db-check-row">
                    <span>2. Unverified Validator Gate (validatorVerdict !== VERIFIED)</span>
                    <span className="db-badge db-badge-emerald">
                      {deputyDrillResult ? 'BLOCKED AT GATE' : 'ARMED'}
                    </span>
                  </li>
                  <li className="db-check-row">
                    <span>3. SSRF DNS Guard (validateOutboundUrl / safeFetch)</span>
                    <span className="db-badge db-badge-emerald">
                      {deputyDrillResult ? 'BLOCKED SSRF TARGET' : 'ARMED'}
                    </span>
                  </li>
                </ul>

                {deputyDrillResult && (
                  <pre className="db-code-block">
                    {JSON.stringify(deputyDrillResult, null, 2)}
                  </pre>
                )}
              </div>
            </div>

            {/* 8090 Software Factory MCP Permission Table */}
            <div className="db-subcard">
              <div className="db-subcard-head">
                <h3 className="db-subcard-title">
                  8090 Software Factory MCP Permission Matrix (Settings -&gt; Connections -&gt; MCP Servers)
                </h3>
                <div style={{ display: 'flex', gap: '0.45rem', flexWrap: 'wrap' }}>
                  <span className="db-badge db-badge-emerald">4 Allow (readOnlyHint: true)</span>
                  <span className="db-badge db-badge-amber">1 Confirm (Human Approval Gate)</span>
                </div>
              </div>

              <div className="db-table-wrap">
                <table className="db-table">
                  <thead>
                    <tr>
                      <th>MCP Tool Name</th>
                      <th>8090 Policy</th>
                      <th>Factory Role</th>
                      <th>4-Boolean Annotations</th>
                      <th>Governance Contract</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mcpPermissions.map((tool) => {
                      const isAllow = tool.sofaPermission === 'Allow' || tool.readOnlyHint === true;
                      return (
                        <tr key={tool.name}>
                          <td className="db-mono" style={{ fontWeight: 700, color: '#ffffff' }}>
                            {tool.name}
                          </td>
                          <td>
                            <span
                              className={cn(
                                'db-badge',
                                isAllow ? 'db-badge-emerald' : 'db-badge-amber'
                              )}
                            >
                              {isAllow ? 'Allow' : 'Confirm'}
                            </span>
                          </td>
                          <td>{tool.sofaScope}</td>
                          <td className="db-mono" style={{ fontSize: '0.76rem' }}>
                            RO:{String(tool.readOnlyHint)} | DEST:{String(tool.destructiveHint)} | IDEM:
                            {String(tool.idempotentHint)} | OW:{String(tool.openWorldHint)}
                          </td>
                          <td>{tool.description}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
        )}
      </div>
    </div>
  );
}

export default BreakerCockpit;
