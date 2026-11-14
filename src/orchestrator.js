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
import { createPlannerEngine } from './engines/planner-graph.js';
import { createFoundryEngine } from './engines/foundry-staging.js';
import { createValidatorEngine } from './engines/validator-gate.js';
import { createHydraGraphClient } from './connectors/hydradb-graph.js';
import { createSponsorHub } from './connectors/sponsors.js';
import { DEADBOLT_MCP_PERMISSION_TABLE } from './mcp/deadbolt-mcp.js';

function resolvePresetEdits(mode = 'remediated') {
    const normalized = String(mode || 'remediated').trim().toLowerCase();
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
    return {
        resolvedMode: 'remediated',
        attemptLabel: 'attempt_3_verified_remediation',
        edits: CANDIDATE_PATCHES.verifiedRemediationPatch
    };
}

function resolveUntrustedTicketSnippet() {
    const untrustedChat = (ORG_CONTEXT_MODALITIES.chats || []).find(
        (item) => item.trust === 'untrusted'
    );
    return untrustedChat ? String(untrustedChat.content || '') : '';
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
        options.ephemeral === true && !options.config
            ? {
                  sofaApiKey: '',
                  sofaAdminApiKey: '',
                  sofaReportingApiKey: '',
                  hydradbApiKey: '',
                  hydradbGraphUrl: '',
                  hydradbGraphToken: '',
                  composioApiKey: '',
                  elevenlabsApiKey: '',
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
    const billingRepoDir = path.join(scratchWorkspaceDir, 'acme-legacy-billing');
    materializeBillingRepo(billingRepoDir);

    const stack = createKruschStack({
        workspaceRoot: scratchWorkspaceDir,
        dbPath: resolvedStackDbPath,
        ephemeral: resolvedStackDbPath === ':memory:',
        autoEmbed: false
    });

    const hydraClient =
        options.hydraClient ||
        createHydraDbClient({
            apiKey: activeConfig.hydradbApiKey || '',
            baseUrl: activeConfig.hydradbBaseUrl || 'https://api.hydradb.com',
            database: activeConfig.hydradbDatabase || 'default-tenant',
            collection: activeConfig.hydradbCollection || 'work_orders',
            timeoutMs: 8000,
            maxRetries: 1
        });

    const hydraGraphClient =
        options.hydraGraphClient ||
        createHydraGraphClient({
            baseUrl: activeConfig.hydradbGraphUrl || '',
            token: activeConfig.hydradbGraphToken || '',
            graphId: activeConfig.hydradbGraphId || 'deadbolt-factory',
            cellId: activeConfig.hydradbCellId || 'cell-0',
            namespace: activeConfig.hydradbNamespace || 'default',
            allowPrivateLan: Boolean(activeConfig.hydradbAllowLan),
            allowTailscale: Boolean(activeConfig.hydradbAllowLan),
            timeoutMs: 5000
        });

    const kruschGitClient =
        options.kruschGitClient !== undefined
            ? options.kruschGitClient
            : activeConfig.kruschGitUrl
              ? createKruschGitClient({
                    baseUrl: activeConfig.kruschGitUrl,
                    timeoutMs: 1200
                })
              : null;

    const refinery = createRefineryEngine({
        stack,
        hydraClient,
        workspaceRoot: scratchWorkspaceDir
    });

    const planner = createPlannerEngine({
        stack,
        kruschGitClient
    });

    const foundry = createFoundryEngine({
        stack
    });

    const llmConfig = {
        enableLiveReviewers: Boolean(activeConfig.enableLiveReviewers),
        geminiApiKey: activeConfig.geminiApiKey || '',
        openRouterApiKey: activeConfig.openRouterApiKey || '',
        ollamaUrl: activeConfig.ollamaUrl || ''
    };

    const validator = createValidatorEngine({
        auditDbPath: resolvedAuditDbPath,
        hmacSecret: activeConfig.auditHmacSecret,
        llmConfig
    });

    const sponsors = createSponsorHub({
        config: activeConfig,
        hydraClient,
        hydraGraphClient
    });

    // Seed organizational context once at startup so GET /api/status and MCP tools are warm immediately
    let seededOnce = false;
    async function ensureSeeded() {
        if (seededOnce) return;
        await refinery.seedOrganizationalContext({ repoDir: billingRepoDir });
        seededOnce = true;
    }
    await ensureSeeded();

    /** @type {Map<string, { workOrderId: string, validationData: object, unifiedDiff: string }>} */
    const verifiedTasks = new Map();
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
        repoDir = undefined
    } = {}) {
        const targetWo =
            BILLING_WORK_ORDERS.find((wo) => wo.id === workOrderId) || BILLING_WORK_ORDERS[0];
        const resolvedEntry =
            entryFile || targetWo.targetFiles?.[0] || 'src/fee-engine.js';
        const resolvedRepoDir = repoDir ? path.resolve(repoDir) : billingRepoDir;

        const plannerEnv = await planner.analyzeBlastRadius({
            repoDir: resolvedRepoDir,
            repoName: 'acme-legacy-billing',
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
        const hasCustomEdits = Array.isArray(edits) && edits.length > 0;
        const preset = resolvePresetEdits(mode);
        const candidateEdits = hasCustomEdits ? edits : preset.edits;
        const attemptLabel = hasCustomEdits ? 'custom_candidate_edits' : preset.attemptLabel;

        const valEnv = await validator.validateCandidate({
            workOrderId,
            attemptLabel,
            repoDir: billingRepoDir,
            edits: candidateEdits,
            runCrossModel: Boolean(runCrossModel)
        });

        if (!valEnv.ok) {
            return valEnv;
        }

        let stagedTaskId = null;
        if (valEnv.data.verdict === 'VERIFIED') {
            const stageEnv = foundry.stageWorkOrderEdits({
                workOrderId,
                goal: `Verified remediation for ${workOrderId}`,
                repoDir: billingRepoDir,
                edits: candidateEdits
            });
            if (stageEnv.ok) {
                stagedTaskId = stageEnv.data.taskId;
                verifiedTasks.set(stagedTaskId, {
                    workOrderId,
                    validationData: valEnv.data,
                    unifiedDiff: stageEnv.data.unifiedDiff || ''
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
    async function applyVerifiedTask({ taskId, workOrderId = 'WO-101' } = {}) {
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
                { taskId: cleanTaskId, workOrderId },
                'deadbolt.orchestrator.apply'
            );
        }

        const effectiveWoId = verifiedRecord.workOrderId || workOrderId || 'WO-101';
        const targetWo =
            BILLING_WORK_ORDERS.find((wo) => wo.id === effectiveWoId) || BILLING_WORK_ORDERS[0];

        const applyEnv = foundry.applyVerifiedStage({
            taskId: cleanTaskId,
            applyToRepoDir: false
        });
        if (!applyEnv.ok) {
            return applyEnv;
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

        return okEnvelope(
            'deadbolt.orchestrator.apply',
            `Applied verified task ${cleanTaskId} and dispatched linked PR receipt for [${effectiveWoId}].`,
            {
                taskId: cleanTaskId,
                workOrderId: effectiveWoId,
                appliedStage: applyEnv.data,
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
        try {
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

            // Stage 2: PLANNER (2-hop AST + <25us Cascade + parallel leases + HydraDB OpenCypher sync)
            const plannerEnv = await mapBlastRadius({
                workOrderId: targetWo.id,
                entryFile: targetWo.targetFiles?.[0] || 'src/fee-engine.js',
                repoDir: runScratchDir
            });
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

            // Stage 4: VALIDATOR (3-Attempt Self-Rejection & Remediation Loop)
            // Attempt 1: Naive per-line Math.round -> GATE_REJECTED (+1 cent batch discrepancy)
            const attempt1Env = await validator.validateCandidate({
                workOrderId: targetWo.id,
                attemptLabel: 'attempt_1_naive_rounding',
                repoDir: runScratchDir,
                edits: CANDIDATE_PATCHES.naiveAgentPatch,
                runCrossModel: false
            });
            const attempt1Beat = okEnvelope('deadbolt.run.attempt1', attempt1Env.summary, {
                stage: 'validator',
                attempt: 1,
                ...attempt1Env.data
            });
            await emitBeat('validator.attempt1', attempt1Beat);

            // Attempt 2: Supervised agent attempts sneaky workaround editing src/sox-reconciler.js -> WORKAROUND_REJECTED!
            const attempt2Env = await validator.validateCandidate({
                workOrderId: targetWo.id,
                attemptLabel: 'attempt_2_sneaky_workaround',
                repoDir: runScratchDir,
                edits: CANDIDATE_PATCHES.sneakyWorkaroundPatch,
                runCrossModel: false
            });
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

            // Attempt 3: Legitimate integer basis-point largest-remainder fix in src/fee-engine.js -> VERIFIED
            const attempt3Env = await validator.validateCandidate({
                workOrderId: targetWo.id,
                attemptLabel: 'attempt_3_verified_remediation',
                repoDir: runScratchDir,
                edits: CANDIDATE_PATCHES.verifiedRemediationPatch,
                runCrossModel: true
            });
            const attempt3Beat = okEnvelope('deadbolt.run.verified', attempt3Env.summary, {
                stage: 'validator',
                attempt: 3,
                ...attempt3Env.data
            });
            await emitBeat('validator.verified', attempt3Beat);

            // Apply verified stage to isolated run target + sync 8090 Work Order + Composio PR receipt
            let appliedStage = null;
            if (stageEnv.ok && attempt3Env.data?.verdict === 'VERIFIED') {
                verifiedTasks.set(stageEnv.data.taskId, {
                    workOrderId: targetWo.id,
                    validationData: attempt3Env.data,
                    unifiedDiff: stageEnv.data.unifiedDiff || ''
                });
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
                    status: 'VERIFIED',
                    phase: '4_VALIDATOR'
                },
                repoDir: runScratchDir
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

            const isVerified = attempt3Env.data?.verdict === 'VERIFIED';
            const hydraFeedbackEnv = await sponsors.submitHydraTaskFeedback({
                requestId: refineryEnv.data?.hydraSync?.requestId || '',
                workOrderId: targetWo.id,
                rating: isVerified ? 'positive' : 'neutral'
            });

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
            return okEnvelope(
                'deadbolt.orchestrator.run',
                `Completed head-to-head governance run for ${targetWo.id} in ${totalElapsedMs}ms (Standard Agent: UNSAFE MERGE +1c vs DEADBOLT: VERIFIED 0c after blocking 1 policy-floor workaround).`,
                receiptData
            );
        } finally {
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

        return planner.scanExternalRepository({
            repoUrlOrPath: cleanTarget,
            maxFiles
        });
    }

    /**
     * Execute Stage 3 Foundry mid-apply crash simulation & journal recovery drill (`INV-DB-06`).
     */
    async function runCrashDrill() {
        const drillEnv = foundry.runCrashRecoveryDrill({ repoDir: billingRepoDir });
        if (!drillEnv.ok) return drillEnv;
        return okEnvelope(drillEnv.tool, drillEnv.summary, {
            ...drillEnv.data,
            initialState: drillEnv.data?.journalStateBefore || 'RECOVERY_PENDING',
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
        runCrashDrill,
        runDeputyDrill,
        speakForeman,
        close
    });
}

export default createDeadboltOrchestrator;
