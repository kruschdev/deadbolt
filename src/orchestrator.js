/**
 * @module orchestrator
 * @description Central choke-point orchestrator for DEADBOLT wiring:
 * - Stage 1 Refinery (6-modality bounded context + INV-12 SHA-256 span locks + superseding lineage)
 * - Stage 2 Planner (2-hop AST call graph + <25us Cascade routing + parallel disjoint leases + repo scanner)
 * - Stage 3 Foundry (<1ms Golden Brick Slop Breaker + isolated staging + journaled crash recovery)
 * - Stage 4 Validator (import-frozen Policy Floor + SOX-style penny reconciliation + cross-family review + SHA-256 audit log)
 * - Sponsor & Ecosystem Hub (8090 Software Factory, HydraDB v2 & v0.4.0 OpenCypher, Composio Confused-Deputy gate, ElevenLabs Foreman)
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createKruschStack } from 'krusch-stack';
import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';
import { createHydraDbClient } from '@krusch/toolkit/hydradb';
import { createKruschGitClient } from '@krusch/toolkit/krusch-git';
import { config as defaultConfig } from './config.js';
import {
    BILLING_REPO_SNAPSHOT,
    BILLING_WORK_ORDERS,
    ORG_CONTEXT_MODALITIES,
    CANDIDATE_PATCHES,
    materializeBillingRepo,
    getLegacySlopSamples
} from './fixtures/billing-scenario.js';
import { createRefineryEngine } from './engines/refinery-context.js';
import { initTreeSitterRuntime } from './engines/treesitter-ast.js';
import { createPlannerEngine } from './engines/planner-graph.js';
import { createFoundryEngine } from './engines/foundry-staging.js';
import { createValidatorEngine } from './engines/validator-gate.js';
import { createModernizerBenchmarkEngine } from './engines/modernizer-benchmark.js';
import { createHydraGraphClient } from './connectors/hydradb-graph.js';
import { createSponsorHub } from './connectors/sponsors.js';
import { DEADBOLT_MCP_PERMISSION_TABLE } from './mcp/deadbolt-mcp.js';

function resolvePresetEdits(mode = 'remediated') {
    const normalized = String(mode ?? 'remediated').trim().toLowerCase();
    if (!normalized || normalized === 'remediated' || normalized === 'attempt3') {
        return {
            resolvedMode: 'remediated',
            attemptLabel: 'attempt_3_verified_remediation',
            edits: CANDIDATE_PATCHES.verifiedRemediationPatch
        };
    }
    if (normalized === 'naive' || normalized === 'attempt1') {
        return {
            resolvedMode: 'naive',
            attemptLabel: 'attempt_1_naive_rounding',
            edits: CANDIDATE_PATCHES.naiveAgentPatch
        };
    }
    if (normalized === 'workaround' || normalized === 'sneaky' || normalized === 'attempt2') {
        return {
            resolvedMode: 'workaround',
            attemptLabel: 'attempt_2_sneaky_workaround',
            edits: CANDIDATE_PATCHES.sneakyWorkaroundPatch
        };
    }
    return null;
}

function resolveUntrustedTicketSnippet() {
    const untrustedChat = (ORG_CONTEXT_MODALITIES.chats || []).find(
        (item) => item.trust === 'untrusted'
    );
    return untrustedChat ? String(untrustedChat.content || '') : '';
}

function isLoopbackBindHost(host) {
    const clean = String(host || '127.0.0.1').trim().toLowerCase();
    return clean === '127.0.0.1' || clean === 'localhost' || clean === '::1' || clean === '[::1]';
}

function isProtectedInternalHostTarget(candidatePath, projectRoot) {
    const resolved = path.resolve(String(candidatePath || ''));
    const homeEnv = path.join(os.homedir(), '.evolve.env');
    if (resolved === homeEnv) return true;
    const base = path.basename(resolved);
    if (base === '.env' || base.startsWith('.env.') || base.endsWith('.hmac')) return true;
    if (projectRoot) {
        const rootResolved = path.resolve(projectRoot);
        const dataDir = path.join(rootResolved, 'data');
        const logsDir = path.join(rootResolved, 'logs');
        if (
            resolved === dataDir ||
            resolved.startsWith(dataDir + path.sep) ||
            resolved === logsDir ||
            resolved.startsWith(logsDir + path.sep)
        ) {
            return true;
        }
    }
    return false;
}

function looksLikeRemoteGitHubInput(rawTarget = '') {
    const clean = String(rawTarget || '').trim();
    if (!clean) return false;
    if (/^(?:https?:\/\/|git@|ssh:\/\/)/i.test(clean)) return true;
    if (/^(?:www\.)?github\.com\//i.test(clean)) return true;
    if (
        !clean.startsWith('/') &&
        !clean.startsWith('./') &&
        !clean.startsWith('../') &&
        !clean.startsWith('~') &&
        /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/.*)?$/.test(clean) &&
        !fs.existsSync(path.resolve(clean))
    ) {
        return true;
    }
    return false;
}

function waitAbortable(delayMs, signal = null) {
    const ms = Number(delayMs);
    if (!Number.isFinite(ms) || ms <= 0) {
        return Promise.resolve();
    }
    if (signal?.aborted) {
        return Promise.resolve();
    }
    return new Promise((resolve) => {
        let onAbort = null;
        const timer = setTimeout(() => {
            if (onAbort && signal) {
                signal.removeEventListener('abort', onAbort);
            }
            resolve();
        }, Math.min(1000, Math.trunc(ms)));
        timer.unref?.();
        if (signal && typeof signal.addEventListener === 'function') {
            onAbort = () => {
                clearTimeout(timer);
                resolve();
            };
            signal.addEventListener('abort', onAbort, { once: true });
        }
    });
}

/**
 * Create a self-contained DEADBOLT 4-stage orchestrator instance.
 *
 * @param {object} [options={}]
 * @param {object} [options.config] - Runtime configuration overrides
 * @param {string} [options.stackDbPath] - SQLite path for krusch-stack (`:memory:` supported)
 * @param {string} [options.auditDbPath] - SQLite path for tamper-evident audit ledger (`:memory:` supported)
 * @param {boolean} [options.ephemeral=false] - Use ephemeral temp workspace + in-memory DBs
 * @param {object|null} [options.hydraClient=null] - Optional injected HydraDB v2 client
 * @param {object|null} [options.hydraGraphClient=null] - Optional injected HydraDB v0.4.0 OpenCypher client
 * @param {object|null} [options.kruschGitClient=null] - Optional injected remote KruschGit client
 */
export async function createDeadboltOrchestrator(options = {}) {
    const ephemeralOfflineDefaults =
        options.ephemeral === true
            ? {
                  sofaApiKey: '',
                  sofaAdminApiKey: '',
                  sofaReportingApiKey: '',
                  hydradbApiKey: '',
                  hydradbGraphUrl: '',
                  hydradbGraphToken: '',
                  composioApiKey: '',
                  elevenlabsApiKey: '',
                  kruschGitUrl: '',
                  ollamaUrl: '',
                  enableLiveReviewers: false
              }
            : {};

    const activeConfig = {
        ...defaultConfig,
        ...ephemeralOfflineDefaults,
        ...(options.config && typeof options.config === 'object' ? options.config : {})
    };

    const isMemoryMode =
        options.ephemeral === true ||
        options.stackDbPath === ':memory:' ||
        options.auditDbPath === ':memory:';

    const resolvedStackDbPath =
        options.stackDbPath ||
        (isMemoryMode ? ':memory:' : activeConfig.stackDbPath);

    const resolvedAuditDbPath =
        options.auditDbPath ||
        (isMemoryMode ? ':memory:' : activeConfig.auditDbPath);

    if (resolvedStackDbPath !== ':memory:') {
        fs.mkdirSync(path.dirname(path.resolve(resolvedStackDbPath)), { recursive: true });
    }
    if (resolvedAuditDbPath !== ':memory:') {
        fs.mkdirSync(path.dirname(path.resolve(resolvedAuditDbPath)), { recursive: true });
    }

    const scratchWorkspaceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deadbolt-factory-ws-'));
    let stack = null;
    let hydraClient = null;
    let hydraGraphClient = null;
    let kruschGitClient = null;
    let refinery = null;
    let planner = null;
    let foundry = null;
    let validator = null;
    let sponsors = null;
    let modernizer = null;
    const billingRepoDir = path.join(scratchWorkspaceDir, 'acme-legacy-billing');

    let seededOnce = false;
    let seedInFlight = null;
    async function ensureSeeded() {
        if (seededOnce) return;
        if (!seedInFlight) {
            seedInFlight = refinery
                .seedOrganizationalContext({ repoDir: billingRepoDir })
                .then(() => {
                    seededOnce = true;
                })
                .finally(() => {
                    seedInFlight = null;
                });
        }
        return seedInFlight;
    }

    try {
        await initTreeSitterRuntime();
        materializeBillingRepo(billingRepoDir);

        stack = createKruschStack({
            workspaceRoot: scratchWorkspaceDir,
            dbPath: resolvedStackDbPath,
            ephemeral: resolvedStackDbPath === ':memory:',
            autoEmbed: false
        });

        hydraClient = (() => {
            if (options.hydraClient) return options.hydraClient;
            const created = createHydraDbClient({
                apiKey: activeConfig.hydradbApiKey || '',
                baseUrl: activeConfig.hydradbBaseUrl || 'https://api.hydradb.com',
                database: activeConfig.hydradbDatabase || 'default-tenant',
                collection: activeConfig.hydradbCollection || 'work_orders',
                timeoutMs: 2500,
                maxRetries: 0
            });
            if (!activeConfig.hydradbApiKey) {
                created.apiKey = '';
            }
            return created;
        })();

        hydraGraphClient =
            options.hydraGraphClient ||
            createHydraGraphClient({
                baseUrl: activeConfig.hydradbGraphUrl || '',
                token: activeConfig.hydradbGraphToken || '',
                graphId: activeConfig.hydradbGraphId || 'deadbolt-factory',
                cellId: activeConfig.hydradbCellId || 'cell-0',
                namespace: activeConfig.hydradbNamespace || 'default',
                allowPrivateLan: Boolean(activeConfig.hydradbAllowLan),
                allowTailscale: Boolean(activeConfig.hydradbAllowLan),
                timeoutMs: 2000
            });

        kruschGitClient =
            options.kruschGitClient !== undefined
                ? options.kruschGitClient
                : activeConfig.kruschGitUrl
                  ? createKruschGitClient({
                        baseUrl: activeConfig.kruschGitUrl,
                        apiKey: '',
                        timeoutMs: 1200
                    })
                  : null;

        refinery = createRefineryEngine({
            stack,
            hydraClient,
            workspaceRoot: scratchWorkspaceDir
        });

        planner = createPlannerEngine({
            stack,
            kruschGitClient
        });

        foundry = createFoundryEngine({
            stack
        });

        const llmConfig = {
            enableLiveReviewers: Boolean(activeConfig.enableLiveReviewers),
            geminiApiKey: activeConfig.geminiApiKey || '',
            openRouterApiKey: activeConfig.openRouterApiKey || '',
            ollamaUrl: activeConfig.ollamaUrl || '',
            chatImpl: options.chatImpl || activeConfig.chatImpl || null
        };

        validator = createValidatorEngine({
            auditDbPath: resolvedAuditDbPath,
            hmacSecret: activeConfig.auditHmacSecret,
            llmConfig
        });

        sponsors = createSponsorHub({
            config: activeConfig,
            hydraClient,
            hydraGraphClient
        });

        modernizer = createModernizerBenchmarkEngine({
            planner,
            foundry,
            validator,
            hydraClient,
            hydraGraphClient,
            sponsors,
            llmConfig: {
                ...llmConfig,
                ollamaFastModel: activeConfig.ollamaFastModel || 'qwen2.5-coder:7b',
                frontierBenchmarkModel:
                    activeConfig.frontierBenchmarkModel || 'anthropic/claude-sonnet-5.5',
                preferCloudFastTier: Boolean(activeConfig.preferCloudFastTier),
                chatImpl: options.chatImpl || activeConfig.chatImpl || null
            }
        });

        // Seed organizational context once at startup (cap startup network wait at 1500ms so listen/MCP never hangs)
        await Promise.race([
            ensureSeeded().catch(() => {
                /* handled lazily on next hydrate call */
            }),
            waitAbortable(1500)
        ]);
    } catch (initErr) {
        try {
            stack?.db?.close?.();
        } catch {
            /* ignore cleanup error */
        }
        try {
            fs.rmSync(scratchWorkspaceDir, { recursive: true, force: true });
        } catch {
            /* ignore cleanup error */
        }
        throw initErr;
    }

    const MAX_VERIFIED_TASKS = 64;
    /** @type {Map<string, { workOrderId: string, validationData: object, unifiedDiff: string }>} */
    const verifiedTasks = new Map();
    function rememberVerifiedTask(taskId, entry) {
        while (verifiedTasks.size >= MAX_VERIFIED_TASKS) {
            const oldestId = verifiedTasks.keys().next().value;
            if (!oldestId) break;
            verifiedTasks.delete(oldestId);
            try {
                foundry.releaseStage?.(oldestId);
            } catch {
                /* ignore stage cleanup error */
            }
        }
        verifiedTasks.set(taskId, entry);
    }
    let lastRunReceipt = null;
    let closed = false;

    function buildAliasedConnectors() {
        const statusEnv = sponsors.getConnectorStatuses();
        const base = statusEnv.data?.connectors || {};
        return {
            ...base,
            context: base.kruschContextMcp,
            git: base.kruschGit,
            sofa: base.softwareFactory8090
        };
    }

    /**
     * Stage 1: Hydrate bounded organizational context for a Work Order.
     */
    async function hydrateWorkOrder({
        workOrderId = 'WO-101',
        query = 'INV-FIN-03 fee rounding batch settlement reconciliation',
        tokenBudget = 4000
    } = {}) {
        await ensureSeeded();
        return refinery.hydrateWorkOrderContext({
            workOrderId,
            query,
            tokenBudget
        });
    }

    /**
     * Stage 2: Map 2-hop AST call-graph blast radius, <25us Cascade tier routes, and parallel WO leases.
     */
    async function mapBlastRadius({
        workOrderId = 'WO-101',
        entryFile = undefined,
        repoDir = undefined,
        repoName = 'acme-legacy-billing'
    } = {}) {
        const targetWo =
            BILLING_WORK_ORDERS.find((wo) => wo.id === workOrderId) || BILLING_WORK_ORDERS[0];
        const resolvedEntry =
            entryFile || targetWo.targetFiles?.[0] || 'src/fee-engine.js';
        const resolvedRepoDir = repoDir ? path.resolve(repoDir) : billingRepoDir;
        if (repoDir && resolvedRepoDir !== billingRepoDir) {
            if (isProtectedInternalHostTarget(resolvedRepoDir, activeConfig.projectRoot)) {
                return errorEnvelope(
                    'PATH_BLOCKED',
                    'Mapping blast radius on internal runtime data or secret paths is forbidden.',
                    null,
                    'deadbolt.planner.blast_radius'
                );
            }
            if (
                !isLoopbackBindHost(activeConfig.host) &&
                !activeConfig.allowLocalRepoPaths &&
                process.env.NODE_ENV !== 'test' &&
                !resolvedRepoDir.startsWith(scratchWorkspaceDir + path.sep)
            ) {
                return errorEnvelope(
                    'PATH_BLOCKED',
                    'Custom local repository paths are disabled when bound to a non-loopback network interface.',
                    null,
                    'deadbolt.planner.blast_radius'
                );
            }
        }
        const resolvedRepoName =
            typeof repoName === 'string' && repoName.trim()
                ? repoName.trim()
                : 'acme-legacy-billing';

        const plannerEnv = await planner.analyzeBlastRadius({
            repoDir: resolvedRepoDir,
            repoName: resolvedRepoName,
            entryFile: resolvedEntry,
            workOrders: BILLING_WORK_ORDERS
        });
        if (!plannerEnv.ok) {
            return plannerEnv;
        }

        const hydraBlastEnv = await hydraGraphClient.queryTwoHopBlastRadius({
            entryFile: resolvedEntry
        });

        const rawHopPath = plannerEnv.data?.hopPath;
        const normalizedHopPath = Array.isArray(rawHopPath)
            ? rawHopPath
            : typeof rawHopPath === 'string' && rawHopPath.trim()
              ? rawHopPath
                    .split(/\s*->\s*/)
                    .map((seg) => seg.trim())
                    .filter(Boolean)
              : [resolvedEntry, ...(plannerEnv.data?.hop1Files || []), ...(plannerEnv.data?.hop2Files || [])];

        const rawParallel = plannerEnv.data?.parallelLeases;
        const routeByWo = new Map(
            (plannerEnv.data?.cascadeRoutes || []).map((route) => [route.workOrderId, route])
        );
        const normalizedParallelLeases = Array.isArray(rawParallel)
            ? rawParallel
            : Array.isArray(rawParallel?.leases)
              ? rawParallel.leases.map((lease) => {
                    const route = routeByWo.get(lease.workOrderId);
                    return {
                        workOrderId: lease.workOrderId,
                        title: lease.title,
                        entryFile: lease.targetFiles?.[0] || resolvedEntry,
                        coneFiles: Array.isArray(lease.leaseCone)
                            ? lease.leaseCone
                            : lease.targetFiles || [resolvedEntry],
                        cascadeTier: route?.selectedTier || 'L1_FAST',
                        canRunInParallel: rawParallel.canRunInParallel !== false,
                        reservedChokePoint: lease.reservedChokePoints?.[0] || 'src/server.js',
                        wave: lease.wave ?? 1
                    };
                })
              : [];

        return okEnvelope(
            'deadbolt.planner.blast_radius',
            plannerEnv.summary,
            {
                workOrderId: targetWo.id,
                ...plannerEnv.data,
                hopPath: normalizedHopPath,
                hopPathLabel: typeof rawHopPath === 'string' ? rawHopPath : normalizedHopPath.join(' -> '),
                parallelLeases: normalizedParallelLeases,
                parallelLeaseMatrix: rawParallel && !Array.isArray(rawParallel) ? rawParallel : null,
                hydraGraph: hydraBlastEnv.ok ? hydraBlastEnv.data : null
            }
        );
    }

    /**
     * Stage 4: Validate either a preset candidate (`naive` | `workaround` | `remediated`) or custom edits,
     * automatically staging verified candidates in Foundry so `deadbolt_apply_verified_stage` can promote them.
     */
    async function validateModeOrEdits({
        workOrderId = 'WO-101',
        mode = 'remediated',
        edits = undefined,
        runCrossModel = true
    } = {}) {
        const cleanWoId = String(workOrderId || 'WO-101').trim() || 'WO-101';
        const hasCustomEdits = Array.isArray(edits) && edits.length > 0;
        const preset = resolvePresetEdits(mode);
        if (!hasCustomEdits && !preset) {
            return errorEnvelope(
                'INVALID_VALIDATION_MODE',
                `Unsupported validation mode "${String(mode)}". Expected naive, workaround, or remediated.`,
                { mode },
                'deadbolt.validator.validate'
            );
        }
        if (!hasCustomEdits && cleanWoId.toUpperCase() !== 'WO-101') {
            return errorEnvelope(
                'WORK_ORDER_MISMATCH',
                `Preset billing candidate mode "${preset.resolvedMode}" applies strictly to WO-101; provide explicit custom edits for ${cleanWoId}.`,
                { workOrderId: cleanWoId, mode: preset.resolvedMode },
                'deadbolt.validator.validate'
            );
        }
        const matchedWo = BILLING_WORK_ORDERS.find(
            (wo) => wo.id.toUpperCase() === cleanWoId.toUpperCase()
        );
        const candidateEdits = hasCustomEdits ? edits : preset.edits;
        const attemptLabel = hasCustomEdits ? 'custom_candidate_edits' : preset.attemptLabel;

        const valEnv = await validator.validateCandidate({
            workOrderId: cleanWoId,
            attemptLabel,
            repoDir: billingRepoDir,
            edits: candidateEdits,
            allowedTargetFiles: matchedWo?.targetFiles || null,
            runCrossModel: Boolean(runCrossModel)
        });

        if (!valEnv.ok) {
            return valEnv;
        }

        let stagedTaskId = null;
        if (valEnv.data.verdict === 'VERIFIED') {
            const stageEnv = foundry.stageWorkOrderEdits({
                workOrderId: cleanWoId,
                goal: `Verified remediation for ${cleanWoId}`,
                repoDir: billingRepoDir,
                edits: candidateEdits
            });
            if (stageEnv.ok) {
                stagedTaskId = stageEnv.data.taskId;
                rememberVerifiedTask(stagedTaskId, {
                    workOrderId: cleanWoId,
                    validationData: valEnv.data,
                    unifiedDiff: stageEnv.data.unifiedDiff || '',
                    appliedStageData: null
                });
            }
        }

        return okEnvelope(
            'deadbolt.validator.validate',
            valEnv.summary,
            {
                ...valEnv.data,
                mode: hasCustomEdits ? 'custom' : preset.resolvedMode,
                stagedTaskId
            }
        );
    }

    /**
     * Query and cryptographically verify the tamper-evident SHA-256 audit chain.
     */
    function getAuditStatus({ limit = 50 } = {}) {
        return validator.getAuditTrail({ limit });
    }

    /**
     * Atomically apply a Stage-4-VERIFIED task and issue a [WO-*]-linked PR receipt via Composio Gate.
     */
    async function applyVerifiedTask({ taskId, workOrderId = '' } = {}) {
        const cleanTaskId = String(taskId || '').trim();
        if (!cleanTaskId) {
            return errorEnvelope(
                'MISSING_TASK_ID',
                'taskId is required to apply a verified stage.',
                null,
                'deadbolt.orchestrator.apply'
            );
        }

        const verifiedRecord = verifiedTasks.get(cleanTaskId);
        if (!verifiedRecord || verifiedRecord.validationData?.verdict !== 'VERIFIED') {
            return errorEnvelope(
                'UNVERIFIED_STAGE_BLOCKED',
                `Refusing to apply task "${cleanTaskId}": candidate has not passed Stage 4 Validator with VERIFIED verdict.`,
                { taskId: cleanTaskId, workOrderId: workOrderId || 'WO-101' },
                'deadbolt.orchestrator.apply'
            );
        }

        const callerWo = String(workOrderId || '').trim();
        if (
            callerWo &&
            verifiedRecord.workOrderId &&
            callerWo.toUpperCase() !== verifiedRecord.workOrderId.toUpperCase()
        ) {
            return errorEnvelope(
                'WORK_ORDER_MISMATCH',
                `Staged task "${cleanTaskId}" belongs to ${verifiedRecord.workOrderId}, not ${callerWo}.`,
                {
                    taskId: cleanTaskId,
                    expectedWorkOrderId: verifiedRecord.workOrderId,
                    requestedWorkOrderId: callerWo
                },
                'deadbolt.orchestrator.apply'
            );
        }

        const effectiveWoId = verifiedRecord.workOrderId || callerWo || 'WO-101';
        const targetWo =
            BILLING_WORK_ORDERS.find((wo) => wo.id === effectiveWoId) || BILLING_WORK_ORDERS[0];

        let appliedStageData = verifiedRecord.appliedStageData || null;
        if (!appliedStageData) {
            const applyEnv = foundry.applyVerifiedStage({
                taskId: cleanTaskId,
                applyToRepoDir: false
            });
            if (!applyEnv.ok) {
                return applyEnv;
            }
            appliedStageData = applyEnv.data;
            verifiedRecord.appliedStageData = appliedStageData;
        }

        const auditEnv = validator.getAuditTrail({ limit: 10 });
        const sofaEnv = await sponsors.syncSoftwareFactoryWorkOrder({
            workOrder: {
                ...targetWo,
                status: 'VERIFIED',
                phase: '4_VALIDATOR'
            },
            repoDir: billingRepoDir
        });

        const prEnv = await sponsors.dispatchVerifiedPullRequest({
            workOrderId: effectiveWoId,
            title: targetWo.title,
            validatorVerdict: 'VERIFIED',
            auditChainValid: auditEnv.ok && auditEnv.data.valid === true,
            auditReceipt: verifiedRecord.validationData.auditReceipt,
            diffSummary: verifiedRecord.unifiedDiff.slice(0, 1200)
        });
        if (!prEnv.ok) {
            return prEnv;
        }

        verifiedTasks.delete(cleanTaskId);
        try {
            foundry.releaseStage?.(cleanTaskId);
        } catch {
            /* ignore cleanup error */
        }

        return okEnvelope(
            'deadbolt.orchestrator.apply',
            `Applied verified task ${cleanTaskId} and dispatched linked PR receipt for [${effectiveWoId}].`,
            {
                taskId: cleanTaskId,
                workOrderId: effectiveWoId,
                appliedStage: appliedStageData,
                sofaSync: sofaEnv.data,
                prReceipt: prEnv.data,
                auditChainValid: auditEnv.ok && auditEnv.data.valid === true
            }
        );
    }

    /**
     * Execute the full head-to-head Ticket-to-PR comparison:
     * Left column: Standard Single-Model Agent (rubber-stamped +1c SOX-style batch discrepancy -> UNSAFE MERGE)
     * Right column: DEADBOLT 4-Stage Factory Governance (Refinery -> Planner -> Foundry -> 3-Attempt Self-Rejection & Verified PR)
     */
    async function runHeadToHead({
        workOrderId = 'WO-101',
        onStageEvent = null,
        beatDelayMs = 0,
        signal = null
    } = {}) {
        const startedNs = process.hrtime.bigint();
        const targetWo =
            BILLING_WORK_ORDERS.find((wo) => wo.id === workOrderId) || BILLING_WORK_ORDERS[0];

        const emitBeat = async (eventName, envelope) => {
            if (typeof onStageEvent === 'function' && !signal?.aborted) {
                onStageEvent(eventName, envelope);
                if (beatDelayMs > 0) {
                    await waitAbortable(beatDelayMs, signal);
                }
            }
        };

        // Isolated clean target copy per head-to-head run so concurrent or repeated stage runs stay idempotent
        const runScratchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'deadbolt-run-'));
        const runRepoName = `acme-legacy-billing-${path.basename(runScratchDir)}`;
        let stagedHeadToHeadTaskId = null;
        const makeAbortResult = () =>
            errorEnvelope(
                'RUN_ABORTED',
                `Head-to-head governance stream for ${targetWo.id} was aborted by caller.`,
                { workOrderId: targetWo.id },
                'deadbolt.orchestrator.run'
            );
        try {
            if (signal?.aborted) return makeAbortResult();
            materializeBillingRepo(runScratchDir);

            // Baseline column: Standard Single-Model Agent (modifies fee-engine.js with naive per-line Math.round)
            const baselineReconcileEnv = await validator.runSoxReconciliationCheck({
                repoDir: runScratchDir,
                candidateEdits: CANDIDATE_PATCHES.naiveAgentPatch
            });
            const baselineRecon = baselineReconcileEnv.data || {};
            const standardAgent = {
                workOrderId: targetWo.id,
                modifiedFile: 'src/fee-engine.js',
                unitTestPassed: Boolean(baselineRecon.unitTestPassed),
                missedDownstreamFile: 'src/sox-reconciler.js',
                reviewerVerdict: 'APPROVED (Same-Family Model)',
                reconciliation: baselineRecon,
                expectedNetCents: baselineRecon.batchCheck?.expectedNetCents ?? 9750,
                actualNetCents: baselineRecon.batchCheck?.actualNetCents ?? 9751,
                deltaCents: baselineRecon.batchCheck?.deltaCents ?? 1,
                invariantId: baselineRecon.invariantId || 'INV-FIN-03',
                outcome: 'UNSAFE MERGE',
                costPerVerifiedTaskUsd: null
            };

            if (signal?.aborted) return makeAbortResult();

            // Stage 1: REFINERY
            const refineryEnv = await hydrateWorkOrder({
                workOrderId: targetWo.id,
                tokenBudget: 4000
            });
            const refineryBeat = okEnvelope('deadbolt.run.refinery', refineryEnv.summary, {
                stage: 'refinery',
                ...refineryEnv.data
            });
            await emitBeat('refinery', refineryBeat);
            if (signal?.aborted) return makeAbortResult();

            // Stage 2: PLANNER (2-hop AST + <25us Cascade + parallel leases + HydraDB OpenCypher sync)
            const plannerEnv = await mapBlastRadius({
                workOrderId: targetWo.id,
                entryFile: targetWo.targetFiles?.[0] || 'src/fee-engine.js',
                repoDir: runScratchDir,
                repoName: runRepoName
            });
            if (signal?.aborted) return makeAbortResult();
            const hydraSyncEnv = await sponsors.syncHydraLineage({
                workOrderId: targetWo.id,
                hopFiles: plannerEnv.data?.hopPath || [
                    'src/fee-engine.js',
                    'src/settlement-service.js',
                    'src/sox-reconciler.js'
                ]
            });
            const plannerBeat = okEnvelope('deadbolt.run.planner', plannerEnv.summary, {
                stage: 'planner',
                ...plannerEnv.data,
                hydraLineageSync: hydraSyncEnv.data
            });
            await emitBeat('planner', plannerBeat);
            if (signal?.aborted) return makeAbortResult();

            // Stage 3: FOUNDRY (<1ms Slop Breaker on candidate + brownfield comparison + isolated staging)
            const candidateSlopEnv = foundry.auditWithSlopBreaker({
                files: CANDIDATE_PATCHES.verifiedRemediationPatch,
                label: 'verified-remediation-candidate'
            });
            const brownfieldSlopEnv = foundry.auditWithSlopBreaker({
                files: getLegacySlopSamples(),
                label: 'legacy-brownfield-baseline'
            });
            const stageEnv = foundry.stageWorkOrderEdits({
                workOrderId: targetWo.id,
                goal: targetWo.title,
                repoDir: runScratchDir,
                edits: CANDIDATE_PATCHES.verifiedRemediationPatch
            });
            if (stageEnv.ok) {
                stagedHeadToHeadTaskId = stageEnv.data.taskId;
            }

            const foundryBeat = okEnvelope(
                'deadbolt.run.foundry',
                candidateSlopEnv.summary,
                {
                    stage: 'foundry',
                    elapsedMs: candidateSlopEnv.data?.elapsedMs ?? 0,
                    slopAudit: candidateSlopEnv.data,
                    legacyBrownfieldAudit: brownfieldSlopEnv.data,
                    stagedTask: stageEnv.ok
                        ? {
                              taskId: stageEnv.data.taskId,
                              status: stageEnv.data.status,
                              files: stageEnv.data.files,
                              unifiedDiff: stageEnv.data.unifiedDiff
                          }
                        : null
                }
            );
            await emitBeat('foundry', foundryBeat);
            if (signal?.aborted) return makeAbortResult();

            // Stage 4: VALIDATOR (3-Attempt Self-Rejection & Remediation Loop)
            const allowedWoFiles = [
                ...new Set([...(targetWo.targetFiles || []), 'src/fee-engine.js'])
            ];
            // Attempt 1: Naive per-line Math.round -> GATE_REJECTED (+1 cent batch discrepancy)
            const attempt1Env = await validator.validateCandidate({
                workOrderId: targetWo.id,
                attemptLabel: 'attempt_1_naive_rounding',
                repoDir: runScratchDir,
                edits: CANDIDATE_PATCHES.naiveAgentPatch,
                allowedTargetFiles: allowedWoFiles,
                runCrossModel: false,
                signal
            });
            if (signal?.aborted || attempt1Env.error?.code === 'VALIDATION_ABORTED') {
                return makeAbortResult();
            }
            const attempt1Beat = okEnvelope('deadbolt.run.attempt1', attempt1Env.summary, {
                stage: 'validator',
                attempt: 1,
                ...attempt1Env.data
            });
            await emitBeat('validator.attempt1', attempt1Beat);
            if (signal?.aborted) return makeAbortResult();

            // Attempt 2: Supervised agent attempts sneaky workaround editing src/sox-reconciler.js -> WORKAROUND_REJECTED!
            const attempt2Env = await validator.validateCandidate({
                workOrderId: targetWo.id,
                attemptLabel: 'attempt_2_sneaky_workaround',
                repoDir: runScratchDir,
                edits: CANDIDATE_PATCHES.sneakyWorkaroundPatch,
                allowedTargetFiles: allowedWoFiles,
                runCrossModel: false,
                signal
            });
            if (signal?.aborted || attempt2Env.error?.code === 'VALIDATION_ABORTED') {
                return makeAbortResult();
            }
            const attempt2Beat = okEnvelope(
                'deadbolt.run.workaround_blocked',
                attempt2Env.summary,
                {
                    stage: 'validator',
                    attempt: 2,
                    ...attempt2Env.data
                }
            );
            await emitBeat('validator.workaround_blocked', attempt2Beat);
            if (signal?.aborted) return makeAbortResult();

            // Attempt 3: Legitimate integer basis-point largest-remainder fix in src/fee-engine.js -> VERIFIED (or ESCALATE_TO_HUMAN)
            const attempt3Env = await validator.validateCandidate({
                workOrderId: targetWo.id,
                attemptLabel: 'attempt_3_verified_remediation',
                repoDir: runScratchDir,
                edits: CANDIDATE_PATCHES.verifiedRemediationPatch,
                allowedTargetFiles: allowedWoFiles,
                runCrossModel: true,
                signal
            });
            if (signal?.aborted || attempt3Env.error?.code === 'VALIDATION_ABORTED') {
                return makeAbortResult();
            }
            const finalVerdict = attempt3Env.data?.verdict || 'GATE_REJECTED';
            const isVerified = finalVerdict === 'VERIFIED';
            const attempt3Beat = okEnvelope(
                isVerified ? 'deadbolt.run.verified' : 'deadbolt.run.escalated',
                attempt3Env.summary,
                {
                    stage: 'validator',
                    attempt: 3,
                    ...attempt3Env.data,
                    verdict: finalVerdict
                }
            );
            await emitBeat('validator.verified', attempt3Beat);
            if (signal?.aborted) return makeAbortResult();

            // Apply verified stage to isolated run target + sync 8090 Work Order + Composio PR receipt
            let appliedStage = null;
            if (stageEnv.ok && isVerified) {
                const applyRes = foundry.applyVerifiedStage({
                    taskId: stageEnv.data.taskId,
                    applyToRepoDir: true
                });
                if (applyRes.ok) {
                    appliedStage = applyRes.data;
                }
            }

            const auditEnv = validator.getAuditTrail({ limit: 25 });
            const sofaEnv = await sponsors.syncSoftwareFactoryWorkOrder({
                workOrder: {
                    ...targetWo,
                    status: isVerified ? 'VERIFIED' : finalVerdict,
                    phase: '4_VALIDATOR'
                },
                repoDir: runScratchDir,
                signal
            });

            const prEnv = await sponsors.dispatchVerifiedPullRequest({
                workOrderId: targetWo.id,
                title: 'Fix integer basis-point residual allocation in fee-engine',
                validatorVerdict: attempt3Env.data?.verdict,
                auditChainValid: auditEnv.ok && auditEnv.data?.valid === true,
                auditReceipt: attempt3Env.data?.auditReceipt,
                diffSummary: stageEnv.data?.unifiedDiff?.slice(0, 1200) || '',
                untrustedContext: resolveUntrustedTicketSnippet(),
                forceUntrustedOverride: false
            });

            const prBeat = okEnvelope(
                'deadbolt.run.pr_dispatched',
                prEnv.ok ? prEnv.summary : 'PR dispatch evaluated',
                {
                    stage: 'pr_dispatched',
                    ...(prEnv.ok ? prEnv.data : { blocked: true, error: prEnv.error }),
                    sofaSync: sofaEnv.data
                }
            );
            await emitBeat('pr.dispatched', prBeat);

            const [hydraFeedbackEnv] = await Promise.race([
                Promise.all([
                    sponsors.submitHydraTaskFeedback({
                        requestId: refineryEnv.data?.hydraSync?.requestId || '',
                        workOrderId: targetWo.id,
                        rating: isVerified ? 'positive' : 'neutral'
                    }),
                    typeof sponsors.reportValidatorFeedback === 'function'
                        ? sponsors.reportValidatorFeedback({
                              workOrderId: targetWo.id,
                              verdict: finalVerdict
                          })
                        : Promise.resolve(null)
                ]),
                waitAbortable(1800, signal).then(() => [{ data: { submitted: false, reason: 'timeout' } }, null])
            ]);

            const totalElapsedMs = Number(
                (Number(process.hrtime.bigint() - startedNs) / 1e6).toFixed(2)
            );
            const measuredReviewerCost =
                (attempt1Env.data?.telemetry?.totalCostUsd || 0) +
                (attempt2Env.data?.telemetry?.totalCostUsd || 0) +
                (attempt3Env.data?.telemetry?.totalCostUsd || 0);
            const costPerVerifiedTaskUsd = isVerified
                ? Number(measuredReviewerCost.toFixed(8))
                : null;

            const telemetry = {
                workOrderId: targetWo.id,
                verified: isVerified,
                finalVerdict,
                attemptsExecuted: 3,
                retries: 2,
                workaroundsBlocked: 1,
                tokensHydrated: refineryEnv.data?.tokensUsed ?? 0,
                tokenBudget: refineryEnv.data?.tokenBudget ?? 4000,
                routingLatencyUs: plannerEnv.data?.routingLatencyUs ?? 0,
                slopScanMs: candidateSlopEnv.data?.elapsedMs ?? 0,
                totalElapsedMs,
                reviewerInputTokens: attempt3Env.data?.telemetry?.inputTokens ?? 0,
                reviewerOutputTokens: attempt3Env.data?.telemetry?.outputTokens ?? 0,
                costPerVerifiedTaskUsd
            };

            const receiptData = {
                workOrderId: targetWo.id,
                standardAgent,
                deadbolt: {
                    refinery: refineryEnv.data,
                    planner: plannerBeat.data,
                    foundry: foundryBeat.data,
                    attempts: [attempt1Env.data, attempt2Env.data, attempt3Env.data],
                    appliedStage,
                    sofaSync: sofaEnv.data,
                    hydraSync: hydraSyncEnv.data,
                    hydraFeedback: hydraFeedbackEnv.data,
                    prReceipt: prEnv.ok ? prEnv.data : null,
                    audit: auditEnv.ok ? auditEnv.data : null,
                    telemetry
                },
                attempts: [attempt1Env.data, attempt2Env.data, attempt3Env.data],
                prReceipt: prEnv.ok ? prEnv.data : null,
                telemetry
            };

            lastRunReceipt = receiptData;
            const deadboltOutcomeLabel = isVerified
                ? 'VERIFIED 0c'
                : `${finalVerdict} (promotion halted)`;
            return okEnvelope(
                'deadbolt.orchestrator.run',
                `Completed head-to-head governance run for ${targetWo.id} in ${totalElapsedMs}ms (Standard Agent: UNSAFE MERGE +1c vs DEADBOLT: ${deadboltOutcomeLabel} after blocking 1 policy-floor workaround).`,
                receiptData
            );
        } catch (runErr) {
            if (signal?.aborted || runErr?.name === 'AbortError') {
                return makeAbortResult();
            }
            throw runErr;
        } finally {
            if (stack?.db?.prepare) {
                try {
                    stack.db.prepare('DELETE FROM git_symbols WHERE repo_name = ?').run(runRepoName);
                    stack.db.prepare('DELETE FROM git_edges WHERE repo_name = ?').run(runRepoName);
                    stack.db.prepare('DELETE FROM git_repositories WHERE name = ?').run(runRepoName);
                } catch {
                    /* best-effort ephemeral git index cleanup */
                }
            }
            if (stagedHeadToHeadTaskId) {
                verifiedTasks.delete(stagedHeadToHeadTaskId);
                try {
                    foundry.releaseStage?.(stagedHeadToHeadTaskId);
                } catch {
                    /* ignore stage cleanup error */
                }
            }
            try {
                fs.rmSync(runScratchDir, { recursive: true, force: true });
            } catch {
                /* best-effort scratch cleanup */
            }
        }
    }

    /**
     * Scan any GitHub repository URL (`https://github.com/<owner>/<repo>`) or local directory,
     * with built-in quick-select support for `acme-legacy-billing` on stage.
     */
    async function scanRepository({ repoUrlOrPath = 'acme-legacy-billing', maxFiles = 60 } = {}) {
        const cleanTarget = String(repoUrlOrPath || '').trim();
        if (!cleanTarget) {
            return errorEnvelope(
                'EMPTY_SCAN_TARGET',
                'Please provide a GitHub repository URL or local directory path to scan.',
                null,
                'deadbolt.orchestrator.repo_scan'
            );
        }

        if (cleanTarget.toLowerCase() === 'acme-legacy-billing') {
            const tempBrownfieldDir = fs.mkdtempSync(
                path.join(os.tmpdir(), 'deadbolt-acme-brownfield-')
            );
            try {
                materializeBillingRepo(tempBrownfieldDir);
                for (const sample of getLegacySlopSamples()) {
                    const absSample = path.join(tempBrownfieldDir, sample.filePath);
                    fs.mkdirSync(path.dirname(absSample), { recursive: true });
                    fs.writeFileSync(absSample, sample.content, 'utf8');
                }
                const scanEnv = await planner.scanExternalRepository({
                    repoUrlOrPath: tempBrownfieldDir,
                    maxFiles
                });
                if (!scanEnv.ok) {
                    return scanEnv;
                }
                return okEnvelope(
                    'deadbolt.planner.repo_scan',
                    `Scanned ${scanEnv.data.scannedFiles} file(s) and ${scanEnv.data.symbolCount} AST symbol(s) in acme-legacy-billing (${scanEnv.data.slopAudit?.slopFindingCount ?? 0} slop finding(s), ${scanEnv.data.elapsedMs}ms).`,
                    {
                        ...scanEnv.data,
                        target: 'acme-legacy-billing'
                    }
                );
            } finally {
                try {
                    fs.rmSync(tempBrownfieldDir, { recursive: true, force: true });
                } catch {
                    /* ignore temp cleanup errors */
                }
            }
        }

        if (cleanTarget.toLowerCase() === 'pdo-nextjs-governed') {
            const tempPortDir = fs.mkdtempSync(
                path.join(os.tmpdir(), 'deadbolt-pdo-nextjs-governed-')
            );
            try {
                const portFiles = BILLING_REPO_SNAPSHOT.governedNextjsPdoFiles || {};
                for (const [relPath, fileContent] of Object.entries(portFiles)) {
                    const normalizedRel = String(relPath).replace(/\\/g, '/').replace(/^\/+/, '');
                    const destAbs = path.resolve(tempPortDir, normalizedRel);
                    if (destAbs !== tempPortDir && !destAbs.startsWith(tempPortDir + path.sep)) {
                        continue;
                    }
                    fs.mkdirSync(path.dirname(destAbs), { recursive: true });
                    fs.writeFileSync(destAbs, String(fileContent), 'utf8');
                }
                const scanEnv = await planner.scanExternalRepository({
                    repoUrlOrPath: tempPortDir,
                    maxFiles
                });
                if (!scanEnv.ok) {
                    return scanEnv;
                }
                return okEnvelope(
                    'deadbolt.planner.repo_scan',
                    `Scanned ${scanEnv.data.scannedFiles} file(s) and ${scanEnv.data.symbolCount} AST symbol(s) in pdo-nextjs-governed (${scanEnv.data.slopAudit?.slopFindingCount ?? 0} slop finding(s), ${scanEnv.data.elapsedMs}ms).`,
                    {
                        ...scanEnv.data,
                        target: 'pdo-nextjs-governed'
                    }
                );
            } finally {
                try {
                    fs.rmSync(tempPortDir, { recursive: true, force: true });
                } catch {
                    /* ignore temp cleanup errors */
                }
            }
        }

        if (!looksLikeRemoteGitHubInput(cleanTarget)) {
            if (isProtectedInternalHostTarget(cleanTarget, activeConfig.projectRoot)) {
                return errorEnvelope(
                    'PATH_BLOCKED',
                    'Scanning internal runtime data or secret paths is forbidden.',
                    null,
                    'deadbolt.orchestrator.repo_scan'
                );
            }
            if (
                !isLoopbackBindHost(activeConfig.host) &&
                !activeConfig.allowLocalRepoPaths &&
                process.env.NODE_ENV !== 'test'
            ) {
                return errorEnvelope(
                    'PATH_BLOCKED',
                    'Local filesystem repository paths are disabled when bound to a non-loopback network interface. Use a public GitHub URL or built-in preset.',
                    null,
                    'deadbolt.orchestrator.repo_scan'
                );
            }
        }

        return planner.scanExternalRepository({
            repoUrlOrPath: cleanTarget,
            maxFiles
        });
    }

    /**
     * Run Head-to-Head Legacy Software Modernization Benchmark on any public GitHub repo or preset:
     * Arm A (1 Single All-Frontier Model, full-repo prompt stuffing) vs.
     * Arm B (DEADBOLT: HydraDB Dual-Live 2-Hop Graph + <25us Cascade Router + <1ms Golden Brick Slop Breaker + 2-Family Review).
     */
    async function modernizeRepository({
        repoUrlOrPath = 'https://github.com/taniarascia/pdo',
        targetFile = '',
        maxFiles = 60
    } = {}) {
        const cleanTarget = String(repoUrlOrPath || '').trim();
        if (!cleanTarget) {
            return errorEnvelope(
                'EMPTY_MODERNIZE_TARGET',
                'Please provide a GitHub repository URL or local directory path to modernize.',
                null,
                'deadbolt.orchestrator.repo_modernize'
            );
        }

        if (cleanTarget.toLowerCase() === 'acme-legacy-billing') {
            const tempBrownfieldDir = fs.mkdtempSync(
                path.join(os.tmpdir(), 'deadbolt-mod-acme-')
            );
            try {
                materializeBillingRepo(tempBrownfieldDir);
                for (const sample of getLegacySlopSamples()) {
                    const absSample = path.join(tempBrownfieldDir, sample.filePath);
                    fs.mkdirSync(path.dirname(absSample), { recursive: true });
                    fs.writeFileSync(absSample, sample.content, 'utf8');
                }
                return await modernizer.runModernizationComparison({
                    repoUrlOrPath: 'acme-legacy-billing',
                    targetFile,
                    maxFiles,
                    materializedOverride: okEnvelope(
                        'deadbolt.modernizer.preset',
                        'Materialized acme-legacy-billing',
                        {
                            repoDir: tempBrownfieldDir,
                            ownedTempDir: null,
                            repoSlug: 'acme-legacy-billing',
                            displayTarget: 'acme-legacy-billing',
                            maxFiles
                        }
                    )
                });
            } finally {
                try {
                    fs.rmSync(tempBrownfieldDir, { recursive: true, force: true });
                } catch {
                    /* ignore temp cleanup errors */
                }
            }
        }

        if (cleanTarget.toLowerCase() === 'pdo-nextjs-governed') {
            const tempPortDir = fs.mkdtempSync(
                path.join(os.tmpdir(), 'deadbolt-mod-pdo-nextjs-')
            );
            try {
                const portFiles = BILLING_REPO_SNAPSHOT.governedNextjsPdoFiles || {};
                for (const [relPath, fileContent] of Object.entries(portFiles)) {
                    const normalizedRel = String(relPath).replace(/\\/g, '/').replace(/^\/+/, '');
                    const destAbs = path.resolve(tempPortDir, normalizedRel);
                    if (destAbs !== tempPortDir && !destAbs.startsWith(tempPortDir + path.sep)) {
                        continue;
                    }
                    fs.mkdirSync(path.dirname(destAbs), { recursive: true });
                    fs.writeFileSync(destAbs, String(fileContent), 'utf8');
                }
                return await modernizer.runModernizationComparison({
                    repoUrlOrPath: 'pdo-nextjs-governed',
                    targetFile,
                    maxFiles,
                    materializedOverride: okEnvelope(
                        'deadbolt.modernizer.preset',
                        'Materialized pdo-nextjs-governed',
                        {
                            repoDir: tempPortDir,
                            ownedTempDir: null,
                            repoSlug: 'pdo-nextjs-governed',
                            displayTarget: 'pdo-nextjs-governed',
                            maxFiles
                        }
                    )
                });
            } finally {
                try {
                    fs.rmSync(tempPortDir, { recursive: true, force: true });
                } catch {
                    /* ignore temp cleanup errors */
                }
            }
        }

        if (!looksLikeRemoteGitHubInput(cleanTarget)) {
            if (isProtectedInternalHostTarget(cleanTarget, activeConfig.projectRoot)) {
                return errorEnvelope(
                    'PATH_BLOCKED',
                    'Modernizing internal runtime data or secret paths is forbidden.',
                    null,
                    'deadbolt.orchestrator.repo_modernize'
                );
            }
            if (
                !isLoopbackBindHost(activeConfig.host) &&
                !activeConfig.allowLocalRepoPaths &&
                process.env.NODE_ENV !== 'test'
            ) {
                return errorEnvelope(
                    'PATH_BLOCKED',
                    'Local filesystem repository paths are disabled when bound to a non-loopback network interface. Use a public GitHub URL or built-in preset.',
                    null,
                    'deadbolt.orchestrator.repo_modernize'
                );
            }
        }

        return modernizer.runModernizationComparison({
            repoUrlOrPath: cleanTarget,
            targetFile,
            maxFiles
        });
    }

    /**
     * Execute Stage 3 Foundry multi-process worker SIGKILL & cold fresh-process journal recovery drill (`INV-DB-06`).
     */
    async function runCrashDrill() {
        const drillEnv = await foundry.runCrashRecoveryDrill({ repoDir: billingRepoDir });
        if (!drillEnv.ok) return drillEnv;
        return okEnvelope(drillEnv.tool, drillEnv.summary, {
            ...drillEnv.data,
            initialState: drillEnv.data?.journalStateBefore || 'APPLYING',
            finalState: drillEnv.data?.journalStateAfter || 'ROLLED_BACK'
        });
    }

    /**
     * Execute Stage 4 Composio 3-vector Confused-Deputy prompt-injection & SSRF drill (`INV-DB-07`).
     */
    async function runDeputyDrill() {
        return sponsors.runConfusedDeputyDrill();
    }

    /**
     * Synthesize Factory Foreman audio telemetry (ElevenLabs live TTS or offline 22050 Hz PCM16 WAV chime).
     */
    async function speakForeman(payload = {}) {
        const safePayload = payload && typeof payload === 'object' ? payload : {};
        const eventType = String(
            safePayload.eventType || safePayload.event || 'WORKAROUND_REJECTED'
        );
        const text = typeof safePayload.text === 'string' && safePayload.text.trim()
            ? safePayload.text
            : typeof safePayload.reason === 'string' && safePayload.reason.trim()
              ? safePayload.reason
              : '';
        return sponsors.synthesizeForemanAlert({ text, eventType });
    }

    /**
     * Retrieve live 8090 Software Factory Tri-API governance state (Org Usage, Work Orders, Blueprints,
     * Requirements, Automations with `tests`/`blueprints` permission locks, and Agent run receipts).
     */
    async function getSofaGovernance({ forceRefresh = false } = {}) {
        return sponsors.getSoftwareFactoryGovernanceSnapshot({ forceRefresh: Boolean(forceRefresh) });
    }

    /**
     * Verify or post a Stage 4 Governance Receipt onto the live 8090 Work Order + Feedback Inbox (`INV-DB-09`).
     */
    async function syncSofaGovernanceReceipt({ workOrderId = 'WO-101' } = {}) {
        const safeWoId = String(workOrderId || 'WO-101').trim() || 'WO-101';
        const upperWo = safeWoId.toUpperCase();
        const aliasMap = {
            'WO-101': ['WO-101', 'WO-1'],
            'WO-1': ['WO-101', 'WO-1'],
            'WO-102': ['WO-102', 'WO-2'],
            'WO-2': ['WO-102', 'WO-2'],
            'WO-103': ['WO-103', 'WO-3'],
            'WO-3': ['WO-103', 'WO-3'],
            'WO-104': ['WO-104', 'WO-4'],
            'WO-4': ['WO-104', 'WO-4']
        };
        const candidateWoCodes = new Set(aliasMap[upperWo] || [upperWo]);

        let chainValid = false;
        let matchedEntry = null;
        if (typeof validator.findLatestVerifiedEntry === 'function') {
            const lookup = validator.findLatestVerifiedEntry({
                resourceCodes: [...candidateWoCodes]
            });
            chainValid = Boolean(lookup?.ok && lookup?.valid);
            matchedEntry = lookup?.matchedEntry || null;
        } else {
            const auditEnv = validator.getAuditTrail({ limit: 200 });
            chainValid = Boolean(auditEnv.ok && auditEnv.data?.valid);
            const entries = Array.isArray(auditEnv.data?.entries) ? auditEnv.data.entries : [];
            matchedEntry =
                entries.find((entry) => {
                    if (
                        entry?.action !== 'validator.verified' ||
                        entry?.actor !== 'deadbolt-validator-gate' ||
                        entry?.outcome !== 'SUCCESS'
                    ) {
                        return false;
                    }
                    const resourceCode = String(entry?.resource || '').trim().toUpperCase();
                    return candidateWoCodes.has(resourceCode);
                }) || null;
        }

        if (!chainValid) {
            return errorEnvelope(
                'AUDIT_TAMPERED',
                'Cannot sync governance receipt: SHA-256 audit chain verification failed.',
                { workOrderId: safeWoId },
                'deadbolt.orchestrator.sofa_sync'
            );
        }

        if (!matchedEntry) {
            const knownLocal = BILLING_WORK_ORDERS.some((wo) =>
                candidateWoCodes.has(String(wo.id || '').trim().toUpperCase())
            );
            let knownInFactory = knownLocal;
            if (!knownInFactory) {
                const snapEnv = await sponsors.getSoftwareFactoryGovernanceSnapshot({
                    forceRefresh: false
                });
                const factoryWos = Array.isArray(snapEnv?.data?.workOrders)
                    ? snapEnv.data.workOrders
                    : [];
                knownInFactory = factoryWos.some((item) => {
                    const code = String(item?.code || '').trim().toUpperCase();
                    const id = String(item?.id || '').trim().toUpperCase();
                    return candidateWoCodes.has(code) || candidateWoCodes.has(id);
                });
            }
            if (!knownInFactory) {
                return errorEnvelope(
                    'WORK_ORDER_NOT_FOUND',
                    `Work Order "${safeWoId}" was not found in the 8090 project.`,
                    { workOrderId: safeWoId },
                    'deadbolt.orchestrator.sofa_sync'
                );
            }
            return errorEnvelope(
                'UNVERIFIED_STAGE_BLOCKED',
                `Run Stage 4 Validator on ${safeWoId} first to mint a signed VERIFIED SHA-256 receipt before syncing to 8090.`,
                { workOrderId: safeWoId },
                'deadbolt.orchestrator.sofa_sync'
            );
        }

        const entryHash = String(matchedEntry.entryHash || matchedEntry.hash || '').trim();
        if (!/^[0-9a-f]{64}$/i.test(entryHash)) {
            return errorEnvelope(
                'UNVERIFIED_STAGE_BLOCKED',
                `Missing valid 64-hex cryptographic SHA-256 entry hash for ${safeWoId}.`,
                { workOrderId: safeWoId },
                'deadbolt.orchestrator.sofa_sync'
            );
        }

        const entryCost = matchedEntry.metadata?.costPerVerifiedTaskUsd;
        const verifiedCostUsd =
            typeof entryCost === 'number' && Number.isFinite(entryCost)
                ? entryCost
                : candidateWoCodes.has(String(lastRunReceipt?.workOrderId || '').toUpperCase()) &&
                    typeof lastRunReceipt?.telemetry?.costPerVerifiedTaskUsd === 'number'
                  ? lastRunReceipt.telemetry.costPerVerifiedTaskUsd
                  : 0;

        return sponsors.syncGovernanceReceiptTo8090({
            workOrderId: safeWoId,
            auditTailHash: entryHash,
            verifiedCostUsd
        });
    }

    /**
     * Return complete dashboard status, 6 connector telemetry pills, Work Orders, audit chain, and 8090 MCP matrix.
     */
    async function getStatus() {
        const connectors = buildAliasedConnectors();
        const auditEnv = validator.getAuditTrail({ limit: 15 });
        return okEnvelope(
            'deadbolt.orchestrator.status',
            'DEADBOLT 4-stage Software Factory governance armed.',
            {
                service: activeConfig.serviceName || 'deadbolt',
                version: '0.1.0',
                connectors,
                workOrders: BILLING_WORK_ORDERS,
                mcpPermissionTable: DEADBOLT_MCP_PERMISSION_TABLE,
                audit: auditEnv.ok ? auditEnv.data : { valid: true, verifiedCount: 0, entries: [] },
                lastRun: lastRunReceipt
            }
        );
    }

    /**
     * Deterministically close all SQLite handles and remove scratch workspaces.
     */
    function close() {
        if (closed) return;
        closed = true;
        try {
            foundry.close();
        } catch {
            /* ignore close error */
        }
        try {
            validator.close();
        } catch {
            /* ignore close error */
        }
        try {
            refinery.cleanupMirrorAnchors();
        } catch {
            /* ignore cleanup error */
        }
        try {
            stack.db?.close?.();
        } catch {
            /* ignore close error */
        }
        try {
            fs.rmSync(scratchWorkspaceDir, { recursive: true, force: true });
        } catch {
            /* ignore temp dir cleanup error */
        }
    }

    return Object.freeze({
        config: activeConfig,
        billingRepoDir,
        stack,
        hydraClient,
        hydraGraphClient,
        kruschGitClient,
        getStatus,
        hydrateWorkOrder,
        mapBlastRadius,
        validateModeOrEdits,
        getAuditStatus,
        applyVerifiedTask,
        runHeadToHead,
        scanRepository,
        modernizeRepository,
        runCrashDrill,
        runDeputyDrill,
        speakForeman,
        getSofaGovernance,
        syncSofaGovernanceReceipt,
        close
    });
}

export default createDeadboltOrchestrator;
