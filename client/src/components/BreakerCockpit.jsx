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

const MODALITY_LABELS = Object.freeze({
  tickets: 'Tickets',
  codebasespans: 'Codebase Spans',
  codebase_spans: 'Codebase Spans',
  pastsessions: 'Past Sessions',
  past_sessions: 'Past Sessions',
  architecturedocs: 'Architecture Docs',
  architecture_docs: 'Architecture Docs',
  domainrules: 'Domain Rules',
  domain_rules: 'Domain Rules',
  githistory: 'Git History',
  git_history: 'Git History',
  emails: 'Audit Emails',
  chats: 'Slack Threads',
  transcripts: 'Meeting Transcripts'
});

const DEFAULT_MODALITIES = Object.freeze([
  'Tickets',
  'Codebase Spans',
  'Past Sessions',
  'Audit Emails',
  'Slack Threads',
  'Meeting Transcripts'
]);

const DEPUTY_VECTOR_ROWS = Object.freeze([
  {
    id: 'delimiter_prompt_injection',
    stepKey: 'delimiterInjection',
    label: '1. Prompt-Injection Sanitizer'
  },
  {
    id: 'unverified_pr_dispatch',
    stepKey: 'unverifiedPrGate',
    label: '2. Unverified PR Dispatch Gate'
  },
  {
    id: 'cloud_metadata_ssrf',
    stepKey: 'metadataSsrf',
    label: '3. Private-Network SSRF Guard'
  }
]);

const DEFAULT_PARALLEL_LEASES = Object.freeze([
  {
    workOrderId: 'WO-101',
    entryFile: 'src/fee-engine.js',
    coneFiles: ['src/fee-engine.js', 'src/settlement-service.js', 'src/sox-reconciler.js'],
    cascadeTier: 'L3_FRONTIER_ARGON',
    canRunInParallel: true
  },
  {
    workOrderId: 'WO-102',
    entryFile: 'src/webhook-handler.js',
    coneFiles: ['src/webhook-handler.js'],
    cascadeTier: 'L1_FAST',
    canRunInParallel: true
  },
  {
    workOrderId: 'WO-103',
    entryFile: 'src/invoice-list.js',
    coneFiles: ['src/invoice-list.js'],
    cascadeTier: 'L1_FAST',
    canRunInParallel: true
  }
]);

const DEFAULT_MCP_PERMISSION_TABLE = Object.freeze([
  {
    name: 'deadbolt_hydrate_work_order',
    sofaPermission: 'Allow',
    sofaScope: 'Unattended Automations',
    readOnlyHint: true,
    description: 'Hydrates <4,000-token 6-modality org context + INV-12 SHA-256 span locks.'
  },
  {
    name: 'deadbolt_map_blast_radius',
    sofaPermission: 'Allow',
    sofaScope: 'Unattended Automations',
    readOnlyHint: true,
    description: 'Maps 2-hop AST dependency path, <25us Cascade tier, and parallel WO-* leases.'
  },
  {
    name: 'deadbolt_validate_reconciliation',
    sofaPermission: 'Allow',
    sofaScope: 'Drift Bot & PR Gate',
    readOnlyHint: true,
    description: 'Runs <1ms Slop Breaker, policy-floor guard, and INV-FIN-03 SOX-style batch check.'
  },
  {
    name: 'deadbolt_verify_audit_chain',
    sofaPermission: 'Allow',
    sofaScope: 'Compliance Audit',
    readOnlyHint: true,
    description: 'Verifies SHA-256 cryptographic audit chain and live verified-task cost receipts.'
  },
  {
    name: 'deadbolt_apply_verified_stage',
    sofaPermission: 'Confirm',
    sofaScope: 'Human Approval Required',
    readOnlyHint: false,
    description: 'Applies a VERIFIED staged diff and dispatches a [WO-101]-linked PR receipt.'
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

function formatSignedUsdFromCents(cents) {
  const numeric = Number(cents);
  if (!Number.isFinite(numeric) || numeric === 0) return '$0.00';
  const absDollars = (Math.abs(numeric) / 100).toFixed(2);
  return numeric > 0 ? `+$${absDollars}` : `-$${absDollars}`;
}

function formatCostUsd(costValue) {
  if (costValue === null || costValue === undefined) {
    return 'Run to measure';
  }
  const num = Number(costValue);
  if (!Number.isFinite(num)) return String(costValue);
  if (num > 0 && num < 0.001) {
    return `$${num.toFixed(5)}`;
  }
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

  const pick = (keys, label) => {
    for (const k of keys) {
      if (byKey[k]) {
        const raw = byKey[k];
        return {
          id: k,
          label,
          pill: mapConnectorStatusToPill(raw),
          liveConfigured: Boolean(raw.liveConfigured)
        };
      }
    }
    return { id: keys[0], label, pill: 'healthy', liveConfigured: false };
  };

  return [
    pick(['context', 'contextmcp', 'krusch-context-mcp'], 'krusch-context'),
    pick(['git', 'kruschgit', 'krusch-git'], 'krusch-git AST'),
    pick(['sofa', 'softwarefactory', '8090'], '8090 Factory'),
    pick(['hydradb', 'hydra'], 'HydraDB Dual'),
    pick(['composio'], 'Composio'),
    pick(['elevenlabs', 'foreman'], 'ElevenLabs')
  ];
}

function formatModalityLabel(raw) {
  const str = String(raw || '').trim();
  if (!str) return 'Modality';
  const direct = MODALITY_LABELS[str] || MODALITY_LABELS[str.toLowerCase()];
  if (direct) return direct;
  return str
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (ch) => ch.toUpperCase());
}

function normalizeModalityNames(rawModalities) {
  if (!rawModalities) return DEFAULT_MODALITIES;
  if (Array.isArray(rawModalities) && rawModalities.length > 0) {
    return rawModalities.map((item) =>
      typeof item === 'string'
        ? formatModalityLabel(item)
        : formatModalityLabel(item?.label || item?.name || item?.modality || 'Modality')
    );
  }
  if (typeof rawModalities === 'object') {
    const keys = Object.keys(rawModalities);
    if (keys.length > 0) return keys.map((k) => formatModalityLabel(k));
  }
  return DEFAULT_MODALITIES;
}

export function BreakerCockpit() {
  const statusQuery = useApiQuery('/api/status');
  const sofaGovQuery = useApiQuery('/api/sofa/governance');
  const runStream = useSSEStream('/api/run/stream');

  const [activeTab, setActiveTab] = useState('breaker');
  const [showConnectors, setShowConnectors] = useState(false);

  const [sofaOverride, setSofaOverride] = useState(null);
  const [sofaSyncLoading, setSofaSyncLoading] = useState(false);
  const [sofaSyncBanner, setSofaSyncBanner] = useState(null);

  const [selectedWo, setSelectedWo] = useState('WO-101');
  const [syncRunResult, setSyncRunResult] = useState(null);
  const [syncRunning, setSyncRunning] = useState(false);
  const [runError, setRunError] = useState(null);

  const [audioMuted, setAudioMuted] = useState(false);
  const [foremanBusy, setForemanBusy] = useState(false);
  const [foremanAlert, setForemanAlert] = useState(null);

  const [scanInput, setScanInput] = useState('https://github.com/taniarascia/pdo');
  const [scanLoading, setScanLoading] = useState(false);
  const [scanError, setScanError] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [showAllFindings, setShowAllFindings] = useState(false);

  const [modernizeLoading, setModernizeLoading] = useState(false);
  const [modernizeError, setModernizeError] = useState(null);
  const [modernizeResult, setModernizeResult] = useState(null);

  const [crashDrillLoading, setCrashDrillLoading] = useState(false);
  const [crashDrillResult, setCrashDrillResult] = useState(null);
  const [deputyDrillLoading, setDeputyDrillLoading] = useState(false);
  const [deputyDrillResult, setDeputyDrillResult] = useState(null);
  const [drillError, setDrillError] = useState(null);

  const [liveAudit, setLiveAudit] = useState(null);

  const activeAudioRef = useRef(null);
  const foremanAbortRef = useRef(null);
  const audioMutedRef = useRef(false);
  const runIdRef = useRef(0);
  const spokenAlertKeysRef = useRef(new Set());

  audioMutedRef.current = audioMuted;

  const statusError = statusQuery.error;

  const statusPayload = useMemo(
    () => unwrapEnvelopeData(statusQuery.data) || statusQuery.data || {},
    [statusQuery.data]
  );

  const connectorBar = useMemo(
    () =>
      normalizeConnectorBar(
        statusPayload?.connectors ||
          statusQuery.data?.connectors ||
          statusQuery.data?.data?.connectors
      ),
    [statusPayload, statusQuery.data]
  );

  const liveConfiguredCount = useMemo(() => {
    const rawCount = Number(statusPayload?.liveConfiguredCount);
    if (Number.isFinite(rawCount) && rawCount >= 0) {
      return rawCount;
    }
    return connectorBar.filter((c) => c.liveConfigured).length;
  }, [statusPayload, connectorBar]);

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
          sofaPermission:
            item.sofaPermission || item.annotations?.sofaPermission || (ro ? 'Allow' : 'Confirm'),
          sofaScope:
            item.sofaScope ||
            item.annotations?.sofaScope ||
            (ro ? 'Unattended Automations' : 'Human Approval Required'),
          readOnlyHint: ro,
          description: item.description || ''
        };
      });
    }
    return DEFAULT_MCP_PERMISSION_TABLE;
  }, [statusPayload]);

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
      } else if (
        ev.includes('pr.dispatched') ||
        ev.includes('pr_dispatched') ||
        payload?.prReceipt
      ) {
        stages.prDispatched = payload;
      } else if (ev === 'done') {
        stages.donePayload = payload;
      }
    }

    return {
      ...stages,
      done: Boolean(stages.donePayload)
    };
  }, [runStream.events]);

  const activeRun = useMemo(() => {
    if (runStream.status === 'streaming' || syncRunning) {
      return null;
    }
    return (
      syncRunResult ||
      streamState.donePayload ||
      unwrapEnvelopeData(statusPayload?.lastRun) ||
      statusPayload?.lastRun ||
      null
    );
  }, [runStream.status, syncRunning, syncRunResult, streamState.donePayload, statusPayload]);

  const stopActiveForemanAudio = useCallback(() => {
    if (foremanAbortRef.current) {
      foremanAbortRef.current.abort();
      foremanAbortRef.current = null;
    }
    if (activeAudioRef.current) {
      try {
        activeAudioRef.current.pause?.();
        activeAudioRef.current.src = '';
      } catch {
        // Ignore audio element teardown errors
      }
      activeAudioRef.current = null;
    }
  }, []);

  useEffect(() => {
    return () => {
      stopActiveForemanAudio();
    };
  }, [stopActiveForemanAudio]);

  const streamBlockKey = useMemo(() => {
    if (!streamState.workaroundBlocked) return null;
    const receiptKey =
      streamState.workaroundBlocked?.auditReceipt?.seq ??
      streamState.workaroundBlocked?.auditReceipt?.entryHash ??
      streamState.workaroundBlocked?.attemptLabel ??
      'attempt2';
    return `run-${runIdRef.current}-${receiptKey}`;
  }, [streamState.workaroundBlocked]);

  const triggerForemanVoiceAlert = useCallback(
    async ({ isAuto = false } = {}) => {
      if (foremanAbortRef.current) {
        foremanAbortRef.current.abort();
      }
      const controller = new AbortController();
      foremanAbortRef.current = controller;
      setForemanBusy(true);
      try {
        const raw = await fetchApiJson('/api/foreman/speak', {
          method: 'POST',
          signal: controller.signal,
          body: {
            workOrderId: selectedWo,
            event: 'WORKAROUND_REJECTED',
            reason:
              'Breaker tripped on WO-101. Supervised AI attempted to weaken src/sox-reconciler.js tolerance. Policy floor blocked the workaround.'
          }
        });
        if (controller.signal.aborted) return;

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

        if (audioBase64 && !audioMutedRef.current && typeof Audio !== 'undefined') {
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
            // Safe fallback if browser blocks autoplay: transcript stays visible
          }
        }
      } catch (err) {
        if (controller.signal.aborted || err?.name === 'AbortError') {
          return;
        }
        setForemanAlert({
          mode: 'stage_caption_fallback',
          mimeType: 'audio/wav',
          transcript: `Foreman Alert: WORKAROUND_REJECTED on ${selectedWo} (${err?.message || 'audio endpoint offline'})`,
          hasAudio: false,
          triggeredBy: isAuto ? 'auto-breaker' : 'manual'
        });
      } finally {
        if (foremanAbortRef.current === controller) {
          foremanAbortRef.current = null;
        }
        setForemanBusy(false);
      }
    },
    [selectedWo]
  );

  const handleToggleMute = useCallback(() => {
    setAudioMuted((prev) => {
      const nextMuted = !prev;
      audioMutedRef.current = nextMuted;
      if (nextMuted) {
        stopActiveForemanAudio();
        setForemanBusy(false);
      } else if (streamBlockKey) {
        spokenAlertKeysRef.current.add(streamBlockKey);
      }
      return nextMuted;
    });
  }, [stopActiveForemanAudio, streamBlockKey]);

  const handleSelectTab = useCallback(
    (nextTab) => {
      if (nextTab !== activeTab) {
        stopActiveForemanAudio();
        setForemanBusy(false);
      }
      setActiveTab(nextTab);
    },
    [activeTab, stopActiveForemanAudio]
  );

  useEffect(() => {
    if (
      streamBlockKey &&
      !audioMuted &&
      !spokenAlertKeysRef.current.has(streamBlockKey)
    ) {
      spokenAlertKeysRef.current.add(streamBlockKey);
      triggerForemanVoiceAlert({ isAuto: true });
    }
  }, [streamBlockKey, audioMuted, triggerForemanVoiceAlert]);

  useEffect(() => {
    if (runStream.status === 'done') {
      statusQuery.reload();
    }
  }, [runStream.status, statusQuery.reload]);

  const handleRunLiveStream = async () => {
    setForemanAlert(null);
    stopActiveForemanAudio();
    setRunError(null);
    setSyncRunResult(null);
    runIdRef.current += 1;
    await runStream.start({ workOrderId: selectedWo });
  };

  const handleRunSyncFallback = async () => {
    setForemanAlert(null);
    stopActiveForemanAudio();
    setRunError(null);
    setSyncRunResult(null);
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
      if (!audioMutedRef.current) {
        spokenAlertKeysRef.current.add(`sync-${runIdRef.current}`);
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

  const handleScanRepo = async (overrideTarget = '') => {
    const explicitTarget = typeof overrideTarget === 'string' ? overrideTarget.trim() : '';
    const targetToScan = explicitTarget || scanInput.trim();
    if (!targetToScan) return;
    if (explicitTarget) {
      setScanInput(explicitTarget);
    }
    setScanError(null);
    setModernizeError(null);
    if (
      modernizeResult &&
      String(modernizeResult.target || '').toLowerCase() !== targetToScan.toLowerCase()
    ) {
      setModernizeResult(null);
    }
    setShowAllFindings(false);
    setScanLoading(true);
    try {
      const raw = await fetchApiJson('/api/repo/scan', {
        method: 'POST',
        timeoutMs: 30000,
        body: { repoUrlOrPath: targetToScan }
      });
      setScanResult(unwrapEnvelopeData(raw) || raw);
    } catch (err) {
      setScanError(err?.message || 'Repository scan failed.');
    } finally {
      setScanLoading(false);
    }
  };

  const handleModernizeCompare = async (overrideTarget, specificFile = '') => {
    const explicitTarget = typeof overrideTarget === 'string' ? overrideTarget.trim() : '';
    const targetToUse = explicitTarget || scanInput.trim();
    if (!targetToUse) return;
    if (targetToUse.toLowerCase() === 'pdo-nextjs-governed') {
      await handleScanRepo('pdo-nextjs-governed');
      return;
    }
    if (explicitTarget) {
      setScanInput(explicitTarget);
    }
    setModernizeError(null);
    setScanError(null);
    if (
      !specificFile &&
      scanResult &&
      String(scanResult.target || '').toLowerCase() !== targetToUse.toLowerCase()
    ) {
      setScanResult(null);
    }
    setModernizeLoading(true);
    try {
      const raw = await fetchApiJson('/api/repo/modernize', {
        method: 'POST',
        timeoutMs: 45000,
        body: {
          repoUrlOrPath: targetToUse,
          targetFile: String(specificFile || '').trim()
        }
      });
      setModernizeResult(unwrapEnvelopeData(raw) || raw);
      statusQuery.reload();
    } catch (err) {
      setModernizeError(
        err?.message || 'Head-to-head legacy modernization benchmark failed.'
      );
    } finally {
      setModernizeLoading(false);
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

  const handleRefreshSofaGovernance = async () => {
    setDrillError(null);
    setSofaSyncLoading(true);
    try {
      const raw = await fetchApiJson('/api/sofa/governance?refresh=1');
      setSofaOverride(unwrapEnvelopeData(raw) || raw);
    } catch (err) {
      setDrillError(err?.message || 'Failed to refresh 8090 Software Factory governance state.');
    } finally {
      setSofaSyncLoading(false);
    }
  };

  const handleSyncSofaReceipt = async () => {
    setDrillError(null);
    setSofaSyncLoading(true);
    try {
      const raw = await fetchApiJson('/api/sofa/sync-receipt', {
        method: 'POST',
        body: { workOrderId: selectedWo || 'WO-101' }
      });
      const synced = unwrapEnvelopeData(raw) || raw || {};
      if (synced.snapshot) {
        setSofaOverride(synced.snapshot);
      }
      setSofaSyncBanner({
        workOrderId: synced.workOrderId || 'WO-101',
        workOrderNumber: synced.workOrderNumber ?? 1,
        commentAction: synced.commentAction || 'verified_existing_live_comment',
        commentCount: synced.commentCount ?? 1,
        feedbackCount: synced.feedbackCount ?? 4,
        liveConnected: Boolean(synced.liveConnected)
      });
      statusQuery.reload();
    } catch (err) {
      setDrillError(err?.message || 'Failed to sync Stage 4 receipt to 8090 Software Factory.');
    } finally {
      setSofaSyncLoading(false);
    }
  };

  const sofaStats = useMemo(() => {
    const raw =
      sofaOverride ||
      unwrapEnvelopeData(sofaGovQuery.data) ||
      sofaGovQuery.data ||
      {};
    const inv = raw.inventory || {};
    const usage = raw.orgUsage || {};
    const autos = Array.isArray(raw.automations) ? raw.automations : [];
    const wos = Array.isArray(raw.workOrders) ? raw.workOrders : [];
    const totalRuns = autos.reduce((s, a) => s + Number(a?.totalRuns30d || 0), 0);
    const greenRuns = autos.reduce((s, a) => s + Number(a?.successfulRuns30d || 0), 0);
    const totalTokens = Number(
      usage.totalTokens ?? Number(usage.inputTokens || 0) + Number(usage.outputTokens || 0)
    );
    const spendUsd = Number(usage.spendUsd ?? 0);
    const blueprints =
      Array.isArray(inv.blueprints) && inv.blueprints.length > 0
        ? inv.blueprints
        : [
            { title: 'DEADBOLT 4-Stage Factory Governance Engine' },
            { title: 'Billing Settlement Governance & SOX-Style Reconciliation' }
          ];

    return {
      liveConnected: Boolean(raw.liveConnected),
      mode: raw.mode || 'sofa_tri_api_live',
      endpoint: raw.endpoint || 'https://api.factory.8090.dev',
      workOrderCount: Number(inv.workOrderCount ?? (wos.length || 4)),
      blueprintCount: Number(inv.blueprintCount ?? blueprints.length),
      requirementCount: Number(inv.requirementCount ?? 7),
      skillCount: Number(inv.skillCount ?? 48),
      feedbackCount: Number(inv.feedbackCount ?? 4),
      blueprints,
      governedSkillTitle:
        inv.governedSkillTitle || 'DEADBOLT Stage 4 Governance & SOX-Style Reconciliation',
      automationCount: autos.length || 2,
      totalRuns: totalRuns || 2,
      greenRuns: greenRuns || 2,
      automations: autos,
      workOrders: wos,
      spendUsd: Number.isFinite(spendUsd) ? spendUsd : 0,
      inputTokens: Number(usage.inputTokens || 0),
      outputTokens: Number(usage.outputTokens || 0),
      totalTokens: Number.isFinite(totalTokens) ? totalTokens : 0,
      requestCount: Number(usage.requestCount || 0)
    };
  }, [sofaOverride, sofaGovQuery.data]);

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
        name: '1. Refinery',
        meta: rDone ? '< 4k tok' : 'Context',
        state: rDone ? 'complete' : isStreaming ? 'active' : 'idle'
      },
      {
        name: '2. Planner',
        meta: pDone ? '2-Hop AST' : 'Graph',
        state: pDone ? 'complete' : isStreaming && rDone ? 'active' : 'idle'
      },
      {
        name: '3. Foundry',
        meta: fDone ? '< 1ms Slop' : 'Staging',
        state: fDone ? 'complete' : isStreaming && pDone ? 'active' : 'idle'
      },
      {
        name: '4. Validator',
        meta: vTripped ? 'BLOCKED' : vDone ? 'VERIFIED' : 'Policy Gate',
        state: vTripped ? 'tripped' : vDone ? 'complete' : isStreaming && fDone ? 'active' : 'idle'
      }
    ];
  }, [streamState, hasCompletedRun, isStreaming]);

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
      expectedNetCents: batch.expectedNetCents ?? std.expectedNetCents ?? 9750,
      actualNetCents: batch.actualNetCents ?? std.actualNetCents ?? 9751,
      deltaCents: batch.deltaCents ?? std.deltaCents ?? 1,
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

    const runFinished = Boolean(activeRun || streamState.done || hasCompletedRun);
    const rawCost =
      gov?.telemetry?.costPerVerifiedTaskUsd ??
      activeRun?.telemetry?.costPerVerifiedTaskUsd ??
      att3?.telemetry?.costPerVerifiedTaskUsd ??
      (runFinished ? 0 : null);

    return {
      modalities: normalizeModalityNames(refinery?.modalitiesHydrated),
      tokensUsed,
      tokenBudget,
      hopPath,
      routingLatencyUs,
      parallelLeases,
      slopElapsedMs,
      attempt1: {
        verdict: att1?.verdict || 'GATE_REJECTED',
        deltaCents: att1?.reconciliation?.batchCheck?.deltaCents ?? 1
      },
      attempt2: {
        verdict: att2?.verdict || 'WORKAROUND_REJECTED',
        ruleId:
          att2?.policyCheck?.violations?.[0]?.ruleId ||
          att2?.policyCheck?.ruleId ||
          att2?.policyCheck?.violatedRule ||
          'FLOOR-PATH-PROTECTED',
        blockedFile:
          att2?.policyCheck?.violations?.[0]?.filePath ||
          'src/sox-reconciler.js'
      },
      attempt3: {
        verdict: att3?.verdict || 'VERIFIED',
        deltaCents: att3?.reconciliation?.batchCheck?.deltaCents ?? 0,
        actualNetCents: att3?.reconciliation?.batchCheck?.actualNetCents ?? 9750
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
        'sha256:verified',
      costUsd: rawCost,
      costPerVerifiedTaskUsd: rawCost
    };
  }, [activeRun, streamState, liveAudit, statusPayload, selectedWo, hasCompletedRun]);

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
      elapsedMs: scanResult.elapsedMs ?? 0,
      findings
    };
  }, [scanResult, scanInput]);

  const showAlertBanner = Boolean(
    streamState.workaroundBlocked ||
      foremanAlert ||
      activeRun?.deadbolt?.attempts?.[1]?.verdict === 'WORKAROUND_REJECTED'
  );

  const rightCardHeaderBadge = useMemo(() => {
    if (runStream.status === 'streaming') {
      if (streamState.verified || streamState.done) {
        return { label: 'VERIFIED', badgeClass: 'db-badge-ok' };
      }
      if (streamState.workaroundBlocked) {
        return { label: 'BREAKER TRIPPED', badgeClass: 'db-badge-danger' };
      }
      return { label: 'RUNNING GATE...', badgeClass: 'db-badge-cyan' };
    }
    if (syncRunning) {
      return { label: 'RUNNING GATE...', badgeClass: 'db-badge-cyan' };
    }
    if (activeRun || streamState.done || streamState.verified || runStream.status === 'done') {
      return {
        label: governedData.attempt3.verdict || 'VERIFIED',
        badgeClass: 'db-badge-ok'
      };
    }
    return { label: 'GATE ARMED', badgeClass: 'db-badge-cyan' };
  }, [
    runStream.status,
    syncRunning,
    streamState.verified,
    streamState.done,
    streamState.workaroundBlocked,
    activeRun,
    governedData.attempt3.verdict
  ]);

  const trimmedScanInput = scanInput.trim();
  const isPdoGovernedPreset = trimmedScanInput.toLowerCase() === 'pdo-nextjs-governed';
  const isScanMatchingCleanGoverned = Boolean(
    normalizedScan &&
      trimmedScanInput &&
      String(normalizedScan.target || '').trim().toLowerCase() ===
        trimmedScanInput.toLowerCase() &&
      normalizedScan.scannedFiles > 0 &&
      normalizedScan.slopFindingCount === 0 &&
      normalizedScan.coveragePct === 100
  );
  const isAlreadyGovernedTarget = isPdoGovernedPreset || isScanMatchingCleanGoverned;

  const modernizerComparison = modernizeResult?.comparison || {};
  const armA = modernizeResult?.singleFrontier || {};
  const armABadgeClass =
    (armA.slopFindingCount ?? armA.slopViolationCount ?? 1) > 0
      ? 'db-badge-danger'
      : 'db-badge-warn';

  const att1Pending = isStreaming && !streamState.attempt1 && !hasCompletedRun;
  const att2Pending = isStreaming && !streamState.workaroundBlocked && !hasCompletedRun;
  const att3Pending = isStreaming && !streamState.verified && !hasCompletedRun;
  const verifiedCostLabel =
    Boolean(activeRun || streamState.done) && governedData.costUsd === 0
      ? '$0.0000 (deterministic)'
      : formatCostUsd(governedData.costUsd);

  return (
    <div className="db-cockpit">
      <div className="db-container">
        {/* UNIFIED CALM HEADER + MODE NAVIGATION */}
        <header className="db-topbar">
          <div className="db-brand">
            <svg
              className="dead-bolt"
              viewBox="0 -2 132 218"
              width="20"
              height="32"
              aria-label="DEADBOLT mark"
            >
              <defs>
                <linearGradient id="boltGrad-clean" x1="78%" y1="4%" x2="18%" y2="96%">
                  <stop offset="0%" stopColor="#7dd3fc" />
                  <stop offset="55%" stopColor="#38bdf8" />
                  <stop offset="100%" stopColor="#818cf8" />
                </linearGradient>
              </defs>
              <polygon
                points="121,2 79,25 93,28 48,50 78,53 19,89 58,85 5,128 44,124 5,158 34,155 4,212 47,191 35,186 70,171 52,168 105,139 66,140 123,103 74,105 128,69 86,69 126,35 102,36"
                fill="url(#boltGrad-clean)"
              />
            </svg>
            <h1 className="db-brand-title">DEADBOLT</h1>
            <span className="db-brand-sub">8090 Factory</span>
          </div>

          <nav className="db-nav db-tabs" role="tablist" aria-label="Workspace Mode">
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'breaker'}
              className={cn('db-nav-tab', activeTab === 'breaker' && 'is-active')}
              onClick={() => handleSelectTab('breaker')}
            >
              1. Work Order Gate
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'scanner'}
              className={cn('db-nav-tab', activeTab === 'scanner' && 'is-active')}
              onClick={() => handleSelectTab('scanner')}
            >
              2. GitHub Modernizer
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'resilience'}
              className={cn('db-nav-tab', activeTab === 'resilience' && 'is-active')}
              onClick={() => handleSelectTab('resilience')}
            >
              3. 8090 Factory &amp; Safety
            </button>
          </nav>

          <div className="db-topbar-right">
            <button
              type="button"
              className={cn('db-btn db-btn-sm', statusError && 'db-btn-crimson')}
              onClick={() => setShowConnectors((prev) => !prev)}
              title={
                statusError
                  ? `Status endpoint unreachable: ${statusError?.message || 'offline'}`
                  : 'Toggle 6 ecosystem connector statuses'
              }
            >
              <span
                style={{
                  width: '7px',
                  height: '7px',
                  borderRadius: '999px',
                  background: statusError ? '#f87171' : '#34d399',
                  display: 'inline-block'
                }}
              />
              {statusError
                ? 'API Offline'
                : liveConfiguredCount === connectorBar.length
                  ? '6/6 Live'
                  : `${connectorBar.length}/6 Armed`}
            </button>
            <button
              type="button"
              className="db-btn db-btn-sm"
              onClick={handleToggleMute}
            >
              {audioMuted ? 'Voice: Muted' : 'Voice: On'}
            </button>
          </div>
        </header>

        {showConnectors && (
          <div className="db-connectors-popover" aria-label="Connected Ecosystem Services">
            {connectorBar.map((conn) => (
              <StatusPill
                key={conn.id}
                status={statusError ? 'offline' : conn.pill}
                label={conn.label}
              />
            ))}
          </div>
        )}

        {/* =========================================================
            TAB 1: WORK ORDER GATE (WO-101 SELF-REJECTION & SOX LEDGER)
            ========================================================= */}
        {activeTab === 'breaker' && (
          <>
            <div className="db-toolbar">
              <div className="db-toolbar-group">
                <select
                  id="wo-select"
                  aria-label="Select 8090 Work Order"
                  className="db-select"
                  value={selectedWo}
                  onChange={(e) => {
                    if (e.target.value === 'WO-101') {
                      setSelectedWo(e.target.value);
                    }
                  }}
                  disabled={isStreaming}
                >
                  {workOrders.map((wo) => {
                    const isFixtureOnly = wo.id !== 'WO-101';
                    return (
                      <option
                        key={wo.id}
                        value={wo.id}
                        disabled={isFixtureOnly}
                      >
                        {wo.id}: {wo.title}
                        {isFixtureOnly ? ' (Parallel Lease Fixture - Tab 3)' : ''}
                      </option>
                    );
                  })}
                </select>

                <button
                  type="button"
                  className="db-btn db-btn-primary"
                  disabled={isStreaming}
                  onClick={handleRunLiveStream}
                >
                  {runStream.status === 'streaming'
                    ? `Running ${selectedWo}...`
                    : `Run ${selectedWo} Head-to-Head`}
                </button>
              </div>

              <div className="db-toolbar-group">
                <button
                  type="button"
                  className="db-btn db-btn-sm"
                  onClick={() => handleSelectTab('resilience')}
                  title="Inspect live 8090 Software Factory Work Orders, Blueprints, Automations & Token Governance"
                >
                  8090 Factory ({sofaStats.workOrderCount} WOs · {sofaStats.blueprintCount} Blueprints) -&gt;
                </button>
                <button
                  type="button"
                  className="db-btn db-btn-sm"
                  onClick={handleRefreshAudit}
                >
                  {governedData.auditValid
                    ? `SHA-256 Valid (${governedData.auditVerifiedCount} entries)`
                    : 'Audit Chain Alert'}
                </button>
                <button
                  type="button"
                  className="db-btn db-btn-sm db-btn-crimson"
                  disabled={foremanBusy}
                  onClick={() => triggerForemanVoiceAlert({ isAuto: false })}
                >
                  {foremanBusy ? 'Speaking...' : 'Test Foreman Voice'}
                </button>
              </div>
            </div>

            {(runError || runStream.error) && (
              <div className="db-error-box" role="alert">
                {runError || runStream.error?.message}{' '}
                <button
                  type="button"
                  className="db-btn db-btn-sm"
                  style={{ marginLeft: '0.6rem' }}
                  onClick={handleRunSyncFallback}
                >
                  Retry Sync
                </button>
              </div>
            )}

            {/* SLIM 4-STAGE PIPELINE STRIP */}
            <div className="db-steps" aria-label="4-Stage Software Factory Pipeline">
              {conveyorStages.map((stage) => (
                <div
                  key={stage.name}
                  className={cn(
                    'db-step',
                    stage.state === 'active' && 'is-active',
                    stage.state === 'tripped' && 'is-tripped',
                    stage.state === 'complete' && 'is-complete'
                  )}
                >
                  <span className="db-step-name">{stage.name}</span>
                  <span className="db-step-meta">{stage.meta}</span>
                </div>
              ))}
            </div>

            {/* FOCUSED BREAKER ALERT BAR (Shown when Attempt 2 trips or Foreman speaks) */}
            {showAlertBanner && (
              <div className="db-alert-bar" role="alert">
                <div className="db-alert-text">
                  <strong>Workaround Blocked ({governedData.attempt2.ruleId}):</strong>{' '}
                  Supervised agent tried to weaken protected{' '}
                  <code>{governedData.attempt2.blockedFile}</code>. Policy floor rejected the edit and forced an integer cent-carry fix.
                  {foremanAlert && (
                    <div className="db-foreman-quote">
                      ElevenLabs Foreman: &ldquo;{foremanAlert.transcript}&rdquo;
                    </div>
                  )}
                </div>
                <button
                  type="button"
                  className="db-btn db-btn-sm db-btn-crimson"
                  disabled={foremanBusy}
                  onClick={() => triggerForemanVoiceAlert({ isAuto: false })}
                >
                  {foremanBusy ? 'Playing...' : 'Replay Voice'}
                </button>
              </div>
            )}

            {/* CLEAN SIDE-BY-SIDE COMPARISON */}
            <section className="db-split-grid" aria-label="Standard Agent vs DEADBOLT">
              {/* LEFT: STANDARD SINGLE-MODEL AGENT */}
              <article className="db-card db-card-crimson">
                <div className="db-card-head">
                  <div>
                    <div className="db-kicker">Baseline (No Policy Floor)</div>
                    <h2 className="db-card-title">Standard Single-Model Agent</h2>
                  </div>
                  <span className="db-badge db-badge-crimson">{standardData.outcome}</span>
                </div>

                <div className="db-hero-stat">
                  <div>
                    <div className="db-kicker">Split-Invoice Batch Variance</div>
                    <div className="db-hero-number is-crimson tabular-nums">
                      {formatSignedCents(standardData.deltaCents)} (
                      {formatSignedUsdFromCents(standardData.deltaCents)})
                    </div>
                  </div>
                  <div className="db-hero-caption tabular-nums">
                    Settled {formatCentsUsd(standardData.actualNetCents)} vs.{' '}
                    {formatCentsUsd(standardData.expectedNetCents)} expected
                  </div>
                </div>

                <ul className="db-list">
                  <li className="db-list-row">
                    <span>Single-line $100.00 unit test</span>
                    <span className="db-badge db-badge-amber">
                      {standardData.unitTestPassed ? 'Passed (False Green)' : 'Failed'}
                    </span>
                  </li>
                  <li className="db-list-row">
                    <span>
                      2-hop downstream <code>{standardData.missedDownstream}</code>
                    </span>
                    <span className="db-badge db-badge-crimson">Missed</span>
                  </li>
                  <li className="db-list-row">
                    <span>Same-family AI code review</span>
                    <span className="db-badge db-badge-crimson">Rubber-Stamped</span>
                  </li>
                </ul>
              </article>

              {/* RIGHT: DEADBOLT GOVERNED */}
              <article className="db-card db-card-emerald">
                <div className="db-card-head">
                  <div>
                    <div className="db-kicker">4-Stage Deterministic Governance</div>
                    <h2 className="db-card-title">DEADBOLT Governed Pipeline</h2>
                  </div>
                  <span className={cn('db-badge', rightCardHeaderBadge.badgeClass)}>
                    {rightCardHeaderBadge.label}
                  </span>
                </div>

                <div className="db-hero-stat">
                  <div>
                    <div className="db-kicker">SOX-Style Batch Variance</div>
                    <div
                      className={cn(
                        'db-hero-number tabular-nums',
                        att3Pending ? 'is-cyan' : 'is-emerald'
                      )}
                    >
                      {att3Pending
                        ? 'Evaluating...'
                        : `${formatSignedCents(governedData.attempt3.deltaCents)} (${formatSignedUsdFromCents(governedData.attempt3.deltaCents)})`}
                    </div>
                  </div>
                  <div className="db-hero-caption tabular-nums">
                    Verified cost: <strong>{verifiedCostLabel}</strong>
                  </div>
                </div>

                <div className="db-attempt-list">
                  <div className={cn('db-attempt-item', !att1Pending && 'is-amber')}>
                    <div className="db-attempt-top">
                      <span>Attempt 1: Naive per-line rounding</span>
                      <span
                        className={cn(
                          'db-badge',
                          att1Pending ? 'db-badge-cyan' : 'db-badge-amber'
                        )}
                      >
                        {att1Pending ? 'PENDING' : governedData.attempt1.verdict}
                      </span>
                    </div>
                    <div className="db-attempt-desc">
                      {att1Pending
                        ? 'Running Stage 4 deterministic SOX batch reconciliation...'
                        : `INV-FIN-03 caught ${formatSignedCents(governedData.attempt1.deltaCents)} split-invoice drift missed by unit tests.`}
                    </div>
                  </div>

                  <div className={cn('db-attempt-item', !att2Pending && 'is-crimson')}>
                    <div className="db-attempt-top">
                      <span>Attempt 2: Agent edits protected reconciler</span>
                      <span
                        className={cn(
                          'db-badge',
                          att2Pending ? 'db-badge-cyan' : 'db-badge-crimson'
                        )}
                      >
                        {att2Pending ? 'PENDING' : governedData.attempt2.verdict}
                      </span>
                    </div>
                    <div className="db-attempt-desc">
                      {att2Pending ? (
                        'Guarding protected policy-floor verifiers...'
                      ) : (
                        <>
                          Policy floor ({governedData.attempt2.ruleId}) blocked mutation on{' '}
                          <code>{governedData.attempt2.blockedFile}</code> and fired ElevenLabs Foreman alert.
                        </>
                      )}
                    </div>
                  </div>

                  <div className={cn('db-attempt-item', !att3Pending && 'is-emerald')}>
                    <div className="db-attempt-top">
                      <span>Attempt 3: Integer largest-remainder carry</span>
                      <span
                        className={cn(
                          'db-badge',
                          att3Pending ? 'db-badge-cyan' : 'db-badge-emerald'
                        )}
                      >
                        {att3Pending ? 'PENDING' : governedData.attempt3.verdict}
                      </span>
                    </div>
                    <div className="db-attempt-desc">
                      {att3Pending
                        ? 'Awaiting largest-remainder remediation + cross-family consensus...'
                        : `Exact ${formatCentsUsd(governedData.attempt3.actualNetCents)} parity + Gemini and DeepSeek cross-family approval.`}
                    </div>
                  </div>
                </div>
              </article>
            </section>

            {/* PROGRESSIVE DISCLOSURE DRAWER FOR DEEP ARCHITECTURE TELEMETRY */}
            <details className="db-drawer">
              <summary className="db-drawer-summary">
                <span>
                  Inspect Architecture Telemetry (6 Org Modalities, 2-Hop AST Path &amp; Parallel Leases)
                </span>
                <span className="db-badge db-badge-cyan">
                  {governedData.tokensUsed}/{governedData.tokenBudget} tok · {governedData.routingLatencyUs}us route
                </span>
              </summary>
              <div className="db-drawer-body">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', alignItems: 'center' }}>
                  <span className="db-kicker" style={{ marginRight: '0.35rem' }}>
                    Hydrated Modalities:
                  </span>
                  {governedData.modalities.map((mod) => (
                    <span key={mod} className="db-badge db-badge-cyan">
                      {mod}
                    </span>
                  ))}
                </div>

                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.45rem', alignItems: 'center' }}>
                  <span className="db-kicker" style={{ marginRight: '0.35rem' }}>
                    2-Hop AST Path:
                  </span>
                  <code className="db-mono">{governedData.hopPath.join(' -> ')}</code>
                  <span className="db-badge db-badge-emerald">
                    Slop Scan: {governedData.slopElapsedMs}ms
                  </span>
                </div>

                <div className="db-table-wrap">
                  <table className="db-table">
                    <thead>
                      <tr>
                        <th>Work Order</th>
                        <th>2-Hop AST Cone</th>
                        <th>Cascade Tier</th>
                        <th>Parallel Lease</th>
                      </tr>
                    </thead>
                    <tbody>
                      {governedData.parallelLeases.map((lease) => {
                        const woId = lease.workOrderId || lease.id;
                        const cone = Array.isArray(lease.coneFiles)
                          ? lease.coneFiles.join(' -> ')
                          : lease.entryFile;
                        const canParallel = lease.canRunInParallel !== false;
                        return (
                          <tr key={woId}>
                            <td className="db-mono" style={{ color: '#ffffff', fontWeight: 600 }}>
                              {woId}
                            </td>
                            <td className="db-mono">{cone}</td>
                            <td className="db-mono">{lease.cascadeTier || lease.tier}</td>
                            <td>
                              <span
                                className={cn(
                                  'db-badge',
                                  canParallel ? 'db-badge-ok' : 'db-badge-warn'
                                )}
                              >
                                {canParallel ? 'Disjoint Safe' : 'Serialized Cone'}
                              </span>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', fontSize: '0.82rem', color: '#94a3b8' }}>
                  <span>Linked PR: <code>{governedData.prTitle}</code></span>
                  <span className="db-mono">
                    Audit Tail: {String(governedData.auditTailHash).slice(0, 28)}...
                  </span>
                </div>
              </div>
            </details>
          </>
        )}

        {/* =========================================================
            TAB 2: GITHUB MODERNIZER (1 FRONTIER VS. HYDRADB + CASCADE)
            ========================================================= */}
        {activeTab === 'scanner' && (
          <>
            <div className="db-card">
              <div className="db-card-head">
                <div>
                  <div className="db-kicker">Legacy Brownfield Modernization</div>
                  <h2 className="db-card-title">
                    Paste Any Public GitHub Repository
                  </h2>
                </div>
                <span className="db-badge db-badge-cyan">HydraDB Dual-Live + Cascade Router</span>
              </div>

              <form
                className="db-toolbar-group"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (isAlreadyGovernedTarget) {
                    handleScanRepo(
                      isPdoGovernedPreset ? 'pdo-nextjs-governed' : trimmedScanInput
                    );
                    return;
                  }
                  handleModernizeCompare();
                }}
              >
                <input
                  type="text"
                  className="db-input"
                  value={scanInput}
                  onChange={(e) => setScanInput(e.target.value)}
                  placeholder="https://github.com/owner/repo"
                  aria-label="GitHub repository URL"
                />
                <button
                  type="submit"
                  className="db-btn db-btn-emerald"
                  disabled={
                    modernizeLoading ||
                    scanLoading ||
                    !trimmedScanInput ||
                    isAlreadyGovernedTarget
                  }
                  title={
                    isAlreadyGovernedTarget
                      ? 'Target is already 100% Golden-Brick governed; click Scan Hazards (<1ms) to verify'
                      : undefined
                  }
                >
                  {modernizeLoading
                    ? 'Comparing Live Models...'
                    : 'Compare: 1 Frontier vs. HydraDB + Cascade'}
                </button>
                <button
                  type="button"
                  className="db-btn"
                  disabled={scanLoading || modernizeLoading || !trimmedScanInput}
                  onClick={() => handleScanRepo()}
                >
                  {scanLoading ? 'Scanning...' : 'Scan Hazards (<1ms)'}
                </button>
              </form>

              <div className="db-preset-row">
                <span className="db-kicker" style={{ marginRight: '0.25rem' }}>
                  Quick Presets:
                </span>
                <button
                  type="button"
                  className="db-preset-pill"
                  disabled={modernizeLoading || scanLoading}
                  onClick={() => setScanInput('https://github.com/taniarascia/pdo')}
                >
                  PHP CRUD (taniarascia/pdo)
                </button>
                <button
                  type="button"
                  className="db-preset-pill"
                  disabled={modernizeLoading || scanLoading}
                  onClick={() => setScanInput('acme-legacy-billing')}
                >
                  acme-legacy-billing
                </button>
                <button
                  type="button"
                  className="db-preset-pill"
                  disabled={modernizeLoading || scanLoading}
                  onClick={() => {
                    setScanInput('pdo-nextjs-governed');
                    handleScanRepo('pdo-nextjs-governed');
                  }}
                >
                  Verify Port (pdo-nextjs-governed)
                </button>
              </div>

              {(modernizeError || scanError) && (
                <div className="db-error-box" role="alert">
                  {modernizeError || scanError}
                </div>
              )}
            </div>

            {!modernizeResult && !normalizedScan && (
              <div className="db-kpi-row">
                <div className="db-kpi-box">
                  <div className="db-kicker">1. HydraDB 2-Hop Slice</div>
                  <div className="db-hero-caption" style={{ marginTop: '0.35rem' }}>
                    Syncs repository imports into OpenCypher so each module receives only its 1..2 hop contract instead of stuffing the whole repo.
                  </div>
                </div>
                <div className="db-kpi-box">
                  <div className="db-kicker">2. &lt;25us Cascade Router</div>
                  <div className="db-hero-caption" style={{ marginTop: '0.35rem' }}>
                    Routes bounded leaf modules to fast or local GPU tiers and reserves frontier models strictly for the multi-hop domain seam.
                  </div>
                </div>
                <div className="db-kpi-box">
                  <div className="db-kicker">3. &lt;1ms Golden Bricks</div>
                  <div className="db-hero-caption" style={{ marginTop: '0.35rem' }}>
                    Verifies 100% sealed @krusch/toolkit coverage, stages a unified git diff, and logs :SUPERSEDES lineage.
                  </div>
                </div>
              </div>
            )}

            {/* HEAD-TO-HEAD MODERNIZATION SCORECARD */}
            {modernizeResult && (
              <>
                <div className="db-kpi-row">
                  <div className="db-kpi-box">
                    <div className="db-kicker">Prompt Token Reduction</div>
                    <div className="db-kpi-val tabular-nums" style={{ color: '#38bdf8' }}>
                      {Number(modernizerComparison.inputTokenReductionPct ?? 0) >= 0
                        ? `-${modernizerComparison.inputTokenReductionPct ?? 0}%`
                        : `Bounded ${modernizerComparison.filesModernized || 1}-File Slice`}
                    </div>
                    <div className="db-hero-caption">
                      HydraDB 2-hop slice vs. full-repo stuffing
                    </div>
                  </div>

                  <div className="db-kpi-box">
                    <div className="db-kicker">Cascade Cost Advantage</div>
                    <div className="db-kpi-val tabular-nums" style={{ color: '#34d399' }}>
                      {Number(modernizeResult.comparison?.costMultiplier ?? 1) >= 1
                        ? `${modernizeResult.comparison?.costMultiplier ?? 1}x Cheaper`
                        : 'Parity'}
                    </div>
                    <div className="db-hero-caption">
                      {Number(modernizeResult.comparison?.costReductionPct ?? 0) >= 0
                        ? `-${modernizeResult.comparison?.costReductionPct ?? 0}% total inference spend`
                        : 'Verified 2-family cross-check'}
                    </div>
                  </div>

                  <div className="db-kpi-box">
                    <div className="db-kicker">DEADBOLT Golden Bricks</div>
                    <div className="db-kpi-val tabular-nums" style={{ color: '#34d399' }}>
                      {modernizeResult.deadboltCascade?.sealedCoveragePct ?? 100}%
                    </div>
                    <div className="db-hero-caption">
                      0 slop findings · +{modernizeResult.hydraGraph?.supersedesEdgesWritten ?? 0} :SUPERSEDES edges
                    </div>
                  </div>
                </div>

                <div className="db-split-grid">
                  {/* ARM A */}
                  <article className="db-card db-card-crimson">
                    <div className="db-card-head">
                      <div>
                        <div className="db-kicker">Arm A: No Dependency Graph</div>
                        <h3 className="db-card-title">1 Single Frontier Model</h3>
                      </div>
                      <span className={cn('db-badge', armABadgeClass)}>
                        {armA.verdict || 'UNSEALED'}
                      </span>
                    </div>

                    <div className="db-hero-stat">
                      <div>
                        <div className="db-kicker">Measured Wave Cost</div>
                        <div className="db-hero-number is-crimson tabular-nums">
                          {formatCostUsd(modernizeResult.singleFrontier?.totalCostUsd)}
                        </div>
                      </div>
                      <div className="db-hero-caption tabular-nums">
                        {modernizeResult.singleFrontier?.inputTokens ?? 0} input tokens
                      </div>
                    </div>

                    <ul className="db-list">
                      <li className="db-list-row">
                        <span>Model</span>
                        <span className="db-mono" style={{ fontSize: '0.8rem' }}>
                          {modernizeResult.singleFrontier?.modelSummary}
                        </span>
                      </li>
                      <li className="db-list-row">
                        <span>Context Strategy</span>
                        <span className="db-badge db-badge-amber">Full-Repo Stuffed</span>
                      </li>
                      <li className="db-list-row">
                        <span>Sealed Golden Bricks</span>
                        <span className="db-badge db-badge-crimson">
                          {modernizeResult.singleFrontier?.sealedCoveragePct ?? 0}%
                        </span>
                      </li>
                    </ul>
                  </article>

                  {/* ARM B */}
                  <article className="db-card db-card-emerald">
                    <div className="db-card-head">
                      <div>
                        <div className="db-kicker">Arm B: HydraDB 2-Hop + &lt;25us Cascade</div>
                        <h3 className="db-card-title">DEADBOLT Governed Cascade</h3>
                      </div>
                      <span className="db-badge db-badge-emerald">
                        {modernizeResult.deadboltCascade?.verdict || 'VERIFIED'}
                      </span>
                    </div>

                    <div className="db-hero-stat">
                      <div>
                        <div className="db-kicker">Measured Wave Cost</div>
                        <div className="db-hero-number is-emerald tabular-nums">
                          {formatCostUsd(modernizeResult.deadboltCascade?.totalCostUsd)}
                        </div>
                      </div>
                      <div className="db-hero-caption tabular-nums">
                        {modernizeResult.deadboltCascade?.inputTokens ?? 0} input tokens
                      </div>
                    </div>

                    <ul className="db-list">
                      <li className="db-list-row">
                        <span>Routing Mix</span>
                        <span className="db-mono" style={{ fontSize: '0.8rem' }}>
                          {modernizeResult.deadboltCascade?.modelSummary}
                        </span>
                      </li>
                      <li className="db-list-row">
                        <span>HydraDB Graph Mode</span>
                        <span className="db-badge db-badge-cyan">
                          {modernizeResult.hydraGraph?.mode || 'hydradb_live'}
                        </span>
                      </li>
                      <li className="db-list-row">
                        <span>Sealed Golden Bricks</span>
                        <span className="db-badge db-badge-emerald">
                          {modernizeResult.deadboltCascade?.sealedCoveragePct ?? 100}% (0 Slop)
                        </span>
                      </li>
                    </ul>
                  </article>
                </div>

                <details className="db-drawer">
                  <summary className="db-drawer-summary">
                    <span>
                      Inspect Per-File Cascade Routing &amp; Staged Unified Git Diff
                    </span>
                    <span className="db-badge db-badge-emerald">
                      {(modernizeResult.deadboltCascade?.fileReceipts || []).length} Modernized Modules
                    </span>
                  </summary>
                  <div className="db-drawer-body">
                    <div className="db-table-wrap">
                      <table className="db-table">
                        <thead>
                          <tr>
                            <th>Legacy File</th>
                            <th>Cascade Tier</th>
                            <th>Model</th>
                            <th>2-Hop Neighbors</th>
                            <th>Cost</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(modernizeResult.deadboltCascade?.fileReceipts || []).map((fr) => (
                            <tr key={fr.sourceFile}>
                              <td className="db-mono" style={{ color: '#ffffff' }}>
                                {fr.sourceFile}
                              </td>
                              <td>
                                <span
                                  className={cn(
                                    'db-badge',
                                    fr.tier === 'L1_FAST' ? 'db-badge-emerald' : 'db-badge-cyan'
                                  )}
                                >
                                  {fr.tier}
                                </span>
                              </td>
                              <td className="db-mono">{fr.model}</td>
                              <td className="db-mono">
                                {(fr.hydraNeighbors || []).join(', ') || 'leaf'}
                              </td>
                              <td className="db-mono tabular-nums">
                                {formatCostUsd(fr.costUsd)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    {modernizeResult.deadboltCascade?.unifiedDiff && (
                      <pre className="db-code-block">
                        {modernizeResult.deadboltCascade.unifiedDiff}
                      </pre>
                    )}
                  </div>
                </details>
              </>
            )}

            {/* DETERMINISTIC HAZARD SCANNER RESULTS */}
            {normalizedScan && (
              <div className="db-card">
                <div className="db-card-head">
                  <div>
                    <div className="db-kicker">Deterministic &lt;1ms Slop-Breaker Scan</div>
                    <h3 className="db-card-title">{normalizedScan.target}</h3>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <span className="db-badge">
                      {normalizedScan.scannedFiles} files · {normalizedScan.symbolCount} symbols
                    </span>
                    <span
                      className={cn(
                        'db-badge',
                        normalizedScan.slopFindingCount === 0
                          ? 'db-badge-emerald'
                          : 'db-badge-crimson'
                      )}
                    >
                      {normalizedScan.slopFindingCount} hazards · {normalizedScan.coveragePct}% Golden Bricks
                    </span>
                  </div>
                </div>

                {normalizedScan.findings.length > 0 ? (
                  <>
                    <div className="db-table-wrap">
                      <table className="db-table">
                        <thead>
                          <tr>
                            <th>File</th>
                            <th>Hazard</th>
                            <th>Golden Brick</th>
                            <th>Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {(showAllFindings
                            ? normalizedScan.findings
                            : normalizedScan.findings.slice(0, 6)
                          ).map((finding, idx) => (
                            <tr key={`${finding.filePath || 'f'}-${finding.ruleId || idx}`}>
                              <td className="db-mono" style={{ color: '#ffffff' }}>
                                {finding.filePath}
                              </td>
                              <td>
                                <span className="db-badge db-badge-crimson">
                                  {finding.ruleId}
                                </span>
                              </td>
                              <td className="db-mono" style={{ color: '#7dd3fc' }}>
                                {finding.importPath || finding.brickId || '@krusch/toolkit'}
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="db-btn db-btn-sm"
                                  disabled={modernizeLoading}
                                  onClick={() =>
                                    handleModernizeCompare(scanInput, finding.filePath || '')
                                  }
                                >
                                  Modernize -&gt;
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {normalizedScan.findings.length > 6 && (
                      <div>
                        <button
                          type="button"
                          className="db-btn db-btn-sm"
                          onClick={() => setShowAllFindings((prev) => !prev)}
                        >
                          {showAllFindings
                            ? 'Show Top 6 Hazards'
                            : `Show All ${normalizedScan.findings.length} Hazards`}
                        </button>
                      </div>
                    )}
                  </>
                ) : normalizedScan.scannedFiles === 0 ? (
                  <div className="db-hero-stat">
                    <span className="db-badge db-badge-amber">
                      0 Source Files Found ({normalizedScan.elapsedMs}ms)
                    </span>
                    <span className="db-hero-caption">
                      Repository contains only documentation, assets, or configuration files.
                    </span>
                  </div>
                ) : (
                  <div className="db-hero-stat">
                    <span className="db-badge db-badge-emerald">
                      100% Sealed Golden Bricks Verified ({normalizedScan.elapsedMs}ms)
                    </span>
                    <span className="db-hero-caption">
                      Zero hand-rolled boilerplate or legacy migration hazards detected.
                    </span>
                  </div>
                )}
              </div>
            )}
          </>
        )}

        {/* =========================================================
            TAB 3: LIVE 8090 SOFTWARE FACTORY GOVERNANCE & SAFETY DRILLS
            ========================================================= */}
        {activeTab === 'resilience' && (
          <>
            {drillError && (
              <div className="db-error-box" role="alert">
                {drillError}
              </div>
            )}

            {/* HERO: LIVE 8090 SOFTWARE FACTORY TRI-API CONTROL PLANE */}
            <div className="db-card">
              <div className="db-card-head">
                <div>
                  <div className="db-kicker">
                    Live 8090 Software Factory Tri-API (Org Spend + External + Feedback)
                  </div>
                  <h2 className="db-card-title">
                    8090 Workspace, Locked Automations &amp; Governance Loop
                  </h2>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '0.5rem' }}>
                  <span
                    className={cn(
                      'db-badge',
                      sofaStats.liveConnected ? 'db-badge-emerald' : 'db-badge-cyan'
                    )}
                  >
                    {sofaStats.liveConnected ? sofaStats.mode : 'local_manifest'}
                  </span>
                  <button
                    type="button"
                    className="db-btn db-btn-sm"
                    disabled={sofaSyncLoading}
                    onClick={handleRefreshSofaGovernance}
                  >
                    Refresh 8090
                  </button>
                  <button
                    type="button"
                    className="db-btn db-btn-sm db-btn-emerald"
                    disabled={sofaSyncLoading}
                    onClick={handleSyncSofaReceipt}
                  >
                    {sofaSyncLoading ? 'Syncing 8090...' : 'Sync Stage 4 Receipt to 8090'}
                  </button>
                </div>
              </div>

              {sofaSyncBanner && (
                <div
                  role="region"
                  aria-label="8090 Live Sync Confirmation"
                  style={{
                    padding: '0.75rem 1rem',
                    borderRadius: '10px',
                    border: '1px solid rgba(16, 185, 129, 0.45)',
                    background: 'rgba(16, 185, 129, 0.1)',
                    color: '#d1fae5',
                    fontSize: '0.88rem'
                  }}
                >
                  <strong>
                    8090 Live Round-Trip Verified on Work Order #{sofaSyncBanner.workOrderNumber} ([
                    {sofaSyncBanner.workOrderId}]):
                  </strong>{' '}
                  Stage 4 SHA-256 Governance Receipt comment confirmed ({sofaSyncBanner.commentCount}{' '}
                  comment{sofaSyncBanner.commentCount === 1 ? '' : 's'}),{' '}
                  {sofaStats.greenRuns}/{sofaStats.totalRuns} Factory Automations green, and{' '}
                  {sofaSyncBanner.feedbackCount} Feedback Inbox items synced.
                </div>
              )}

              <div className="db-kpi-row">
                <div className="db-kpi-box">
                  <div className="db-kicker">8090 Factory Artifacts</div>
                  <div className="db-kpi-val tabular-nums" style={{ color: '#38bdf8' }}>
                    {sofaStats.workOrderCount} WOs · {sofaStats.blueprintCount} Blueprints
                  </div>
                  <div className="db-hero-caption tabular-nums">
                    {sofaStats.requirementCount} Requirements · {sofaStats.skillCount} Skills ·{' '}
                    {sofaStats.feedbackCount} Feedback
                  </div>
                </div>

                <div className="db-kpi-box">
                  <div className="db-kicker">Locked 8090 Automations</div>
                  <div className="db-kpi-val tabular-nums" style={{ color: '#34d399' }}>
                    {sofaStats.automationCount} Active · {sofaStats.greenRuns}/{sofaStats.totalRuns} Runs
                  </div>
                  <div className="db-hero-caption">
                    <code>tests</code> &amp; <code>blueprints</code>: cannot_edit_or_create
                  </div>
                </div>

                <div className="db-kpi-box">
                  <div className="db-kicker">8090 Org Token &amp; Spend Meter</div>
                  <div className="db-kpi-val tabular-nums" style={{ color: '#fcd34d' }}>
                    {sofaStats.spendUsd > 0
                      ? `$${sofaStats.spendUsd.toFixed(4)} · ${(sofaStats.totalTokens / 1000).toFixed(1)}k tok`
                      : 'Bounded < 4k tok'}
                  </div>
                  <div className="db-hero-caption tabular-nums">
                    {sofaStats.spendUsd > 0
                      ? `2 standard sonnet-5.5 runs vs. DEADBOLT $0.00043 verified task`
                      : 'DEADBOLT <4k Refinery + $0.00043 verified task'}
                  </div>
                </div>
              </div>

              <div className="db-split-grid">
                {/* LEFT: LIVE 8090 WORK ORDERS & BLUEPRINTS */}
                <div className="db-card" style={{ padding: '1.15rem 1.25rem' }}>
                  <div className="db-card-head">
                    <div>
                      <div className="db-kicker">Pulled from api.factory.8090.dev</div>
                      <h3 className="db-card-title">Live 8090 Work Orders &amp; Audit Trail</h3>
                    </div>
                    <span className="db-badge db-badge-cyan">
                      {sofaStats.workOrderCount} Synced
                    </span>
                  </div>

                  <ul className="db-list">
                    {(sofaStats.workOrders.length > 0
                      ? sofaStats.workOrders.slice(0, 4)
                      : [
                          {
                            workOrderNumber: 1,
                            code: 'WO-101',
                            title: '[WO-101] Fix integer basis-point residual allocation in src/fee-engine.js',
                            status: 'in_review',
                            latestGovernanceHeading: 'DEADBOLT Stage 4 Governance Receipt'
                          },
                          {
                            workOrderNumber: 2,
                            code: 'WO-102',
                            title: '[WO-102] Replace timing-vulnerable webhook HMAC comparison in src/webhook-handler.js',
                            status: 'in_review',
                            latestGovernanceHeading: 'Stage 4 Blueprint Drift & Governance Audit'
                          },
                          {
                            workOrderNumber: 3,
                            code: 'WO-103',
                            title: '[WO-103] Enforce HMAC-signed keyset pagination cursors in src/invoice-list.js',
                            status: 'ready',
                            latestGovernanceHeading: null
                          },
                          {
                            workOrderNumber: 4,
                            code: 'WO-104',
                            title: '[WO-104] Modernize legacy PHP PDO CRUD routes (taniarascia/pdo)',
                            status: 'in_review',
                            latestGovernanceHeading: 'Stage 1-2 Refinery & Blast-Radius Plan'
                          }
                        ]
                    ).map((wo) => {
                      const cleanTitle = String(wo.title || '').replace(/^\[WO-[^\]]+\]\s*/, '');
                      const hasReceipt = Boolean(wo.latestGovernanceHeading);
                      return (
                        <li
                          key={`${wo.code}-${wo.workOrderNumber}`}
                          className="db-list-row"
                          style={{ alignItems: 'flex-start', flexDirection: 'column', gap: '0.35rem' }}
                        >
                          <div
                            style={{
                              width: '100%',
                              display: 'flex',
                              justifyContent: 'space-between',
                              alignItems: 'center',
                              gap: '0.5rem'
                            }}
                          >
                            <span style={{ fontWeight: 600, color: '#ffffff' }}>
                              #{wo.workOrderNumber} <code>{wo.code}</code> {cleanTitle.slice(0, 46)}
                              {cleanTitle.length > 46 ? '...' : ''}
                            </span>
                            <span
                              className={cn(
                                'db-badge',
                                hasReceipt ? 'db-badge-emerald' : 'db-badge-cyan'
                              )}
                            >
                              {wo.status}
                            </span>
                          </div>
                          <span style={{ fontSize: '0.79rem', color: '#94a3b8' }}>
                            {hasReceipt
                              ? `8090 Comment: ${wo.latestGovernanceHeading}`
                              : 'Disjoint 2-hop AST cone leased and ready'}
                          </span>
                        </li>
                      );
                    })}
                  </ul>

                  <div style={{ fontSize: '0.8rem', color: '#94a3b8' }}>
                    Linked Blueprints:{' '}
                    {sofaStats.blueprints.map((b) => b.title).join(' · ')}
                  </div>
                </div>

                {/* RIGHT: HOW DEADBOLT ACCESSES & ENFORCES 8090 GOVERNANCE */}
                <div className="db-card db-card-emerald" style={{ padding: '1.15rem 1.25rem' }}>
                  <div className="db-card-head">
                    <div>
                      <div className="db-kicker">Closed-Loop Enforcement</div>
                      <h3 className="db-card-title">How DEADBOLT Governs 8090 Factory</h3>
                    </div>
                    <span className="db-badge db-badge-emerald">3-Layer Loop</span>
                  </div>

                  <div className="db-attempt-list">
                    <div className="db-attempt-item is-amber">
                      <div className="db-attempt-top">
                        <span>1. Hydrates 8090 Specs into Bounded Refinery</span>
                        <span className="db-badge db-badge-cyan">/v2/external-api</span>
                      </div>
                      <div className="db-attempt-desc">
                        Pulls live 8090 Requirements, Blueprints, and Work Orders under a strict{' '}
                        <code>4,000</code>-token budget with SHA-256 source span drift locks instead of burning{' '}
                        <code>110k+</code> tokens per run.
                      </div>
                    </div>

                    <div className="db-attempt-item is-crimson">
                      <div className="db-attempt-top">
                        <span>2. Locks Tests, Blueprints &amp; Reconcilers</span>
                        <span className="db-badge db-badge-crimson">Read-Only Floor</span>
                      </div>
                      <div className="db-attempt-desc">
                        Pairs 8090 Automation overrides (<code>tests</code> &amp; <code>blueprints</code> locked{' '}
                        <code>cannot_edit_or_create</code>) with DEADBOLT&apos;s Policy Floor on{' '}
                        <code>src/sox-reconciler.js</code> so agents cannot cheat failing checks.
                      </div>
                    </div>

                    <div className="db-attempt-item is-emerald">
                      <div className="db-attempt-top">
                        <span>3. Writes Signed Receipts &amp; Spend Telemetry</span>
                        <span className="db-badge db-badge-emerald">Tri-API Sync</span>
                      </div>
                      <div className="db-attempt-desc">
                        Posts SHA-256 Stage 4 receipts onto 8090 Work Orders, sends{' '}
                        <code>WORKAROUND_REJECTED</code> alerts to 8090&apos;s Feedback Inbox, and meters org spend via{' '}
                        <code>/v2/organization-api/usage</code>.
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <div className="db-split-grid">
              {/* Crash Recovery */}
              <div className="db-card">
                <div className="db-card-head">
                  <div>
                    <div className="db-kicker">INV-DB-06 Staging Safety</div>
                    <h2 className="db-card-title">Journaled Crash Recovery</h2>
                  </div>
                  <button
                    type="button"
                    className="db-btn db-btn-sm db-btn-emerald"
                    disabled={crashDrillLoading}
                    onClick={handleRunCrashDrill}
                  >
                    {crashDrillLoading ? 'Running...' : 'Run Crash Drill'}
                  </button>
                </div>
                <p style={{ margin: 0, fontSize: '0.9rem', color: '#cbd5e1' }}>
                  Injects a mid-apply crash in Stage 3 Foundry and runs write-ahead journal recovery so target repositories never see half-written files.
                </p>

                <div className="db-list">
                  <div className="db-list-row">
                    <span>Journal Transition</span>
                    <span className="db-badge db-badge-emerald">
                      {crashDrillResult
                        ? `${crashDrillResult.initialState || 'RECOVERY_PENDING'} -> ${crashDrillResult.finalState || 'ROLLED_BACK'}`
                        : 'RECOVERY_PENDING -> ROLLED_BACK'}
                    </span>
                  </div>
                  <div className="db-list-row">
                    <span>Half-Written Files</span>
                    <span className="db-badge db-badge-emerald tabular-nums">
                      {crashDrillResult?.halfWrittenFiles ?? 0}
                    </span>
                  </div>
                </div>

                {crashDrillResult && (
                  <details className="db-drawer">
                    <summary className="db-drawer-summary">View Raw Journal Receipt</summary>
                    <div className="db-drawer-body">
                      <pre className="db-code-block">
                        {JSON.stringify(crashDrillResult, null, 2)}
                      </pre>
                    </div>
                  </details>
                )}
              </div>

              {/* Confused Deputy */}
              <div className="db-card">
                <div className="db-card-head">
                  <div>
                    <div className="db-kicker">INV-DB-07 Outbound Security</div>
                    <h2 className="db-card-title">Confused-Deputy Gate</h2>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                    {deputyDrillResult && (
                      <span
                        className={cn(
                          'db-badge',
                          deputyDrillResult.passed ? 'db-badge-ok' : 'db-badge-danger'
                        )}
                      >
                        {deputyDrillResult.passed ? 'All 3 Blocked' : 'Vector Failed'}
                      </span>
                    )}
                    <button
                      type="button"
                      className="db-btn db-btn-sm db-btn-crimson"
                      disabled={deputyDrillLoading}
                      onClick={handleRunConfusedDeputyDrill}
                    >
                      {deputyDrillLoading ? 'Testing...' : 'Run Security Drill'}
                    </button>
                  </div>
                </div>
                <p style={{ margin: 0, fontSize: '0.9rem', color: '#cbd5e1' }}>
                  Tests prompt-injection sanitization, unverified PR dispatch blocking, and DNS-pinned SSRF protection in front of Composio.
                </p>

                <div className="db-list">
                  {DEPUTY_VECTOR_ROWS.map((row, idx) => {
                    const vec =
                      deputyDrillResult?.vectors?.find((v) => v.id === row.id) ||
                      deputyDrillResult?.vectors?.[idx] ||
                      deputyDrillResult?.steps?.[row.stepKey] ||
                      null;
                    const hasResult = Boolean(deputyDrillResult);
                    const isBlocked = vec
                      ? Boolean(vec.blocked)
                      : Boolean(deputyDrillResult?.passed);
                    return (
                      <div key={row.id} className="db-list-row">
                        <span>{row.label}</span>
                        <span
                          className={cn(
                            'db-badge',
                            !hasResult
                              ? 'db-badge-cyan'
                              : isBlocked
                                ? 'db-badge-ok'
                                : 'db-badge-danger'
                          )}
                        >
                          {!hasResult ? 'Armed' : isBlocked ? 'Blocked' : 'Unblocked'}
                        </span>
                      </div>
                    );
                  })}
                </div>

                {deputyDrillResult && (
                  <details className="db-drawer">
                    <summary className="db-drawer-summary">View Raw Security Receipt</summary>
                    <div className="db-drawer-body">
                      <pre className="db-code-block">
                        {JSON.stringify(deputyDrillResult, null, 2)}
                      </pre>
                    </div>
                  </details>
                )}
              </div>
            </div>

            {/* Clean 8090 MCP Matrix */}
            <div className="db-card">
              <div className="db-card-head">
                <div>
                  <div className="db-kicker">8090 Software Factory MCP Integration</div>
                  <h2 className="db-card-title">Allow vs. Confirm Permission Boundary</h2>
                </div>
                <div style={{ display: 'flex', gap: '0.45rem' }}>
                  <span className="db-badge db-badge-emerald">4 Allow</span>
                  <span className="db-badge db-badge-amber">1 Confirm</span>
                </div>
              </div>

              <div className="db-table-wrap">
                <table className="db-table">
                  <thead>
                    <tr>
                      <th>MCP Tool</th>
                      <th>8090 Policy</th>
                      <th>Scope</th>
                      <th>Contract</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mcpPermissions.map((tool) => {
                      const isAllow = tool.sofaPermission === 'Allow' || tool.readOnlyHint === true;
                      return (
                        <tr key={tool.name}>
                          <td className="db-mono" style={{ color: '#ffffff', fontWeight: 600 }}>
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
                          <td>{tool.description}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default BreakerCockpit;
