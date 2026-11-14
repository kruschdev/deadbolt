import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scoreLegoBrickCoverage } from '@krusch/toolkit/catalog';
import {
    decodeHydraCell,
    decodeHydraQueryResult,
    createHydraGraphClient
} from '../src/connectors/hydradb-graph.js';
import { createSponsorHub } from '../src/connectors/sponsors.js';
import { createDeadboltOrchestrator } from '../src/orchestrator.js';
import {
    DEADBOLT_MCP_TOOLS,
    DEADBOLT_MCP_PERMISSION_TABLE,
    createDeadboltMcp
} from '../src/mcp/deadbolt-mcp.js';
import { buildServer } from '../src/server.js';

const TEST_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(TEST_DIR, '..');

function collectSourceFiles(dirPath, relPrefix = '') {
    const out = [];
    if (!fs.existsSync(dirPath)) return out;
    for (const entry of fs.readdirSync(dirPath, { withFileTypes: true })) {
        if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name.startsWith('.')) {
            continue;
        }
        const full = path.join(dirPath, entry.name);
        const rel = relPrefix ? `${relPrefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) {
            out.push(...collectSourceFiles(full, rel));
        } else if (/\.(js|jsx|mjs)$/.test(entry.name)) {
            out.push({
                filePath: rel,
                content: fs.readFileSync(full, 'utf8')
            });
        }
    }
    return out;
}

test('INV-DB-02 & INV-SOLO-VOICE-01: zero boilerplate slop and zero em dashes across DEADBOLT source & docs', () => {
    const srcFiles = [
        ...collectSourceFiles(path.join(PROJECT_ROOT, 'src'), 'src'),
        ...collectSourceFiles(path.join(PROJECT_ROOT, 'client', 'src'), 'client/src')
    ];
    assert.ok(srcFiles.length >= 10, 'Expected DEADBOLT source & client files');

    const coverage = scoreLegoBrickCoverage(srcFiles);
    assert.equal(coverage.ok, true);
    assert.equal(
        coverage.data.slopFindingCount,
        0,
        `Expected 0 slop findings, got: ${JSON.stringify(coverage.data.findings)}`
    );
    assert.equal(coverage.data.sealedCoverageRatio, 1);

    const proseTargets = [
        path.join(PROJECT_ROOT, 'README.md'),
        path.join(PROJECT_ROOT, 'spec.md'),
        path.join(PROJECT_ROOT, 'client', 'src', 'components', 'BreakerCockpit.jsx')
    ];
    for (const file of proseTargets) {
        const text = fs.readFileSync(file, 'utf8');
        assert.equal(
            text.includes('\u2014'),
            false,
            `Found forbidden em dash in ${path.basename(file)}`
        );
    }
});

test('HydraDB v0.4.0 OpenCypher client: cell decoding, /healthz, MERGE seeding, and 2-hop blast radius', async () => {
    assert.equal(decodeHydraCell({ type: 'vertex_id', value: 1001 }), 1001);
    assert.equal(decodeHydraCell({ type: 'null' }), null);
    assert.equal(decodeHydraCell({ type: 'bool' }), null);
    assert.deepEqual(
        decodeHydraCell({
            type: 'list',
            value: [{ type: 'vertex_id', value: 1002 }, { type: 'null' }]
        }),
        [1002, null]
    );

    const decoded = decodeHydraQueryResult({
        columns: ['vertexId', 'filePath', 'isProtected'],
        rows: [
            [
                { type: 'vertex_id', value: 1002 },
                { type: 'string', value: 'src/settlement-service.js' },
                { type: 'bool' }
            ],
            [
                { type: 'vertex_id', value: 1003 },
                { type: 'string', value: 'src/sox-reconciler.js' },
                { type: 'bool', value: true }
            ]
        ]
    });
    assert.equal(decoded.records.length, 2);
    assert.equal(decoded.records[0].vertexId, 1002);
    assert.equal(decoded.records[0].isProtected, null);
    assert.equal(decoded.records[1].vertexId, 1003);
    assert.equal(decoded.records[1].isProtected, true);

    // Offline fallback when unconfigured
    const unconfiguredClient = createHydraGraphClient({});
    assert.equal(unconfiguredClient.isConfigured(), false);
    const offlineSeed = await unconfiguredClient.seedWorkOrderLineageGraph({ workOrderId: 'WO-101' });
    assert.equal(offlineSeed.ok, true);
    assert.equal(offlineSeed.data.liveSynced, false);

    // Live v0.4.0 protocol simulation over safeFetch
    const capturedRequests = [];
    const mockFetch = async (url, init = {}) => {
        const parsedUrl = new URL(String(url));
        const bodyObj = init.body ? JSON.parse(String(init.body)) : null;
        capturedRequests.push({
            pathname: parsedUrl.pathname,
            method: init.method || 'GET',
            headers: init.headers || {},
            body: bodyObj
        });

        if (parsedUrl.pathname === '/healthz') {
            return new Response(JSON.stringify({ status: 'ok' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        if (parsedUrl.pathname === '/v1/graphs/deadbolt-factory/query') {
            const cypher = String(bodyObj?.query || '');
            if (cypher.includes('DEPENDED_ON_BY*1..2')) {
                return new Response(
                    JSON.stringify({
                        columns: ['vertexId', 'filePath', 'isProtected'],
                        rows: [
                            [
                                { type: 'vertex_id', value: 1002 },
                                { type: 'string', value: 'src/settlement-service.js' },
                                { type: 'null' }
                            ],
                            [
                                { type: 'vertex_id', value: 1003 },
                                { type: 'string', value: 'src/sox-reconciler.js' },
                                { type: 'bool', value: true }
                            ]
                        ]
                    }),
                    { status: 200, headers: { 'Content-Type': 'application/json' } }
                );
            }

            return new Response(
                JSON.stringify({
                    columns: ['woVertexId', 'activeInvVertexId', 'supersededInvVertexId'],
                    rows: [
                        [
                            { type: 'vertex_id', value: 9001 },
                            { type: 'vertex_id', value: 8003 },
                            { type: 'vertex_id', value: 8002 }
                        ]
                    ]
                }),
                { status: 200, headers: { 'Content-Type': 'application/json' } }
            );
        }

        return new Response(JSON.stringify({ error: 'not found' }), { status: 404 });
    };

    const liveHydra = createHydraGraphClient({
        baseUrl: 'https://hydradb-edge.example.com:8443',
        token: 'hydra-test-token-v040',
        graphId: 'deadbolt-factory',
        cellId: 'cell-0',
        namespace: 'default',
        lookupFn: async () => [{ address: '93.184.216.34', family: 4 }],
        fetchImpl: mockFetch
    });

    assert.equal(liveHydra.isConfigured(), true);
    const healthRes = await liveHydra.healthz();
    assert.equal(healthRes.ok, true);
    assert.equal(healthRes.data.healthy, true);

    const seedRes = await liveHydra.seedWorkOrderLineageGraph({ workOrderId: 'WO-101' });
    assert.equal(seedRes.ok, true);
    assert.equal(seedRes.data.liveSynced, true);
    assert.equal(seedRes.data.lineageRecord.woVertexId, 9001);

    const blastRes = await liveHydra.queryTwoHopBlastRadius({ entryFile: 'src/fee-engine.js' });
    assert.equal(blastRes.ok, true);
    assert.equal(blastRes.data.dependents.length, 2);
    assert.equal(blastRes.data.dependents[0].vertexId, 1002);
    assert.equal(blastRes.data.dependents[0].isProtected, false);
    assert.equal(blastRes.data.dependents[1].vertexId, 1003);
    assert.equal(blastRes.data.dependents[1].isProtected, true);

    const queryReqs = capturedRequests.filter(
        (req) => req.pathname === '/v1/graphs/deadbolt-factory/query'
    );
    assert.ok(queryReqs.length >= 4);
    assert.equal(queryReqs[0].body.cell_id, 'cell-0');
    assert.equal(queryReqs[0].headers['X-Graph-Namespace'], 'default');
    assert.equal(queryReqs[0].headers.Authorization, 'Bearer hydra-test-token-v040');
    const twoHopReq = queryReqs.find((req) => req.body.query.includes('DEPENDED_ON_BY*1..2'));
    assert.ok(twoHopReq.body.query.includes('WHERE dst.id <> $start'));
});

test('Orchestrator end-to-end invariants (INV-DB-01..08, INV-FIN-03) and 5-tool MCP server', async (t) => {
    const orchestrator = await createDeadboltOrchestrator({
        ephemeral: true,
        stackDbPath: ':memory:',
        auditDbPath: ':memory:',
        kruschGitClient: null
    });
    t.after(() => orchestrator.close());

    // Stage 1: Refinery bounded 6-modality hydration + INV-12 span lock
    const hydrateEnv = await orchestrator.hydrateWorkOrder({
        workOrderId: 'WO-101',
        tokenBudget: 4000
    });
    assert.equal(hydrateEnv.ok, true);
    assert.equal(hydrateEnv.data.modalitiesHydrated.length, 6);
    assert.ok(hydrateEnv.data.tokensUsed > 0 && hydrateEnv.data.tokensUsed <= 4000);
    assert.equal(hydrateEnv.data.spanIntegrity.status, 'VALID');
    assert.equal(hydrateEnv.data.untrustedGuard.blocked, true);

    // Stage 2: Planner 2-hop AST subway + <25us Cascade routing + parallel WO leases + scanner
    const blastEnv = await orchestrator.mapBlastRadius({ workOrderId: 'WO-101' });
    assert.equal(blastEnv.ok, true);
    assert.deepEqual(blastEnv.data.hopPath.slice(0, 3), [
        'src/fee-engine.js',
        'src/settlement-service.js',
        'src/sox-reconciler.js'
    ]);
    assert.equal(blastEnv.data.parallelLeases.length, 3);
    assert.ok(blastEnv.data.parallelLeases.every((lease) => lease.canRunInParallel === true));

    const scanEnv = await orchestrator.scanRepository({ repoUrlOrPath: 'acme-legacy-billing' });
    assert.equal(scanEnv.ok, true);
    assert.equal(scanEnv.data.target, 'acme-legacy-billing');
    assert.ok(scanEnv.data.scannedFiles >= 10);
    assert.ok(scanEnv.data.slopAudit.slopFindingCount >= 4);

    // Stage 3: Crash-Recovery Drill (INV-DB-06)
    const crashEnv = await orchestrator.runCrashDrill();
    assert.equal(crashEnv.ok, true);
    assert.equal(crashEnv.data.converged, true);
    assert.equal(crashEnv.data.halfWrittenFiles, 0);
    assert.equal(crashEnv.data.orphanedTempCleaned, true);

    // Stage 4: Validator fixed order, self-rejection & SOX-style reconciliation (INV-FIN-03, INV-DB-04..05, INV-DB-08)
    const naiveEnv = await orchestrator.validateModeOrEdits({
        workOrderId: 'WO-101',
        mode: 'naive',
        runCrossModel: false
    });
    assert.equal(naiveEnv.ok, true);
    assert.equal(naiveEnv.data.verdict, 'GATE_REJECTED');
    assert.equal(naiveEnv.data.reconciliation.unitTestPassed, true);
    assert.equal(naiveEnv.data.reconciliation.batchCheck.expectedNetCents, 9750);
    assert.equal(naiveEnv.data.reconciliation.batchCheck.actualNetCents, 9751);
    assert.equal(naiveEnv.data.reconciliation.batchCheck.deltaCents, 1);
    assert.equal(naiveEnv.data.telemetry.costPerVerifiedTaskUsd, null);

    const workaroundEnv = await orchestrator.validateModeOrEdits({
        workOrderId: 'WO-101',
        mode: 'workaround',
        runCrossModel: false
    });
    assert.equal(workaroundEnv.ok, true);
    assert.equal(workaroundEnv.data.verdict, 'WORKAROUND_REJECTED');
    assert.equal(workaroundEnv.data.telemetry.costPerVerifiedTaskUsd, null);

    // Unverified taskId must be blocked from promotion
    const blockedApply = await orchestrator.applyVerifiedTask({
        taskId: 'task-unverified-fake',
        workOrderId: 'WO-101'
    });
    assert.equal(blockedApply.ok, false);
    assert.equal(blockedApply.error.code, 'UNVERIFIED_STAGE_BLOCKED');

    // Confused-Deputy 3-vector drill (INV-DB-07) & Foreman audio
    const deputyEnv = await orchestrator.runDeputyDrill();
    assert.equal(deputyEnv.ok, true);
    assert.equal(deputyEnv.data.passed, true);
    assert.equal(deputyEnv.data.vectors.length, 3);

    const foremanEnv = await orchestrator.speakForeman({
        event: 'WORKAROUND_REJECTED'
    });
    assert.equal(foremanEnv.ok, true);
    assert.equal(foremanEnv.data.mimeType, 'audio/wav');
    assert.ok(foremanEnv.data.audioBase64.length > 200);

    // 8090-Aligned 5-Tool MCP Server (4 Allow + 1 Confirm)
    assert.equal(DEADBOLT_MCP_TOOLS.length, 5);
    const allowTools = DEADBOLT_MCP_PERMISSION_TABLE.filter((x) => x.sofaPermission === 'Allow');
    const confirmTools = DEADBOLT_MCP_PERMISSION_TABLE.filter((x) => x.sofaPermission === 'Confirm');
    assert.equal(allowTools.length, 4);
    assert.equal(confirmTools.length, 1);
    assert.equal(confirmTools[0].name, 'deadbolt_apply_verified_stage');

    const mcpHandle = await createDeadboltMcp({ orchestrator, connect: false });
    const listed = await mcpHandle.listTools();
    assert.equal(listed.tools.length, 5);

    const mcpValRes = await mcpHandle.callTool({
        params: {
            name: 'deadbolt_validate_reconciliation',
            arguments: { workOrderId: 'WO-101', mode: 'remediated', runCrossModel: true }
        }
    });
    const mcpValEnvelope = JSON.parse(mcpValRes.content[0].text);
    assert.equal(mcpValEnvelope.ok, true);
    assert.equal(mcpValEnvelope.data.verdict, 'VERIFIED');
    assert.ok(mcpValEnvelope.data.stagedTaskId);

    const mcpApplyRes = await mcpHandle.callTool({
        params: {
            name: 'deadbolt_apply_verified_stage',
            arguments: {
                taskId: mcpValEnvelope.data.stagedTaskId,
                workOrderId: 'WO-101'
            }
        }
    });
    const mcpApplyEnvelope = JSON.parse(mcpApplyRes.content[0].text);
    assert.equal(mcpApplyEnvelope.ok, true);
    assert.match(mcpApplyEnvelope.data.prReceipt.prTitle, /^\[WO-101\]/);

    const mcpAuditRes = await mcpHandle.callTool({
        params: {
            name: 'deadbolt_verify_audit_chain',
            arguments: { limit: 20 }
        }
    });
    const mcpAuditEnvelope = JSON.parse(mcpAuditRes.content[0].text);
    assert.equal(mcpAuditEnvelope.ok, true);
    assert.equal(mcpAuditEnvelope.data.valid, true);
    assert.ok(mcpAuditEnvelope.data.verifiedCount >= 3);
});

test('HTTP + SSE + Static Breaker Panel server routes (/health, /api/status, /api/run/stream, drills, static UI)', async (t) => {
    const orchestrator = await createDeadboltOrchestrator({
        ephemeral: true,
        stackDbPath: ':memory:',
        auditDbPath: ':memory:',
        kruschGitClient: null
    });
    const { server, close } = buildServer({
        dbPath: ':memory:',
        orchestrator
    });
    await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => {
        await new Promise((resolve) => server.close(resolve));
        close();
        orchestrator.close();
    });

    const { port } = server.address();
    const baseUrl = `http://127.0.0.1:${port}`;

    // Health + static assets
    const healthRes = await fetch(`${baseUrl}/health`);
    assert.equal(healthRes.status, 200);
    const healthJson = await healthRes.json();
    assert.equal(healthJson.ok, true);
    assert.equal(healthJson.data.governanceArmed, true);

    const indexRes = await fetch(`${baseUrl}/`);
    assert.equal(indexRes.status, 200);
    assert.match(indexRes.headers.get('content-type') || '', /text\/html/);
    const indexHtml = await indexRes.text();
    assert.ok(indexHtml.includes('DEADBOLT'));

    const favRes = await fetch(`${baseUrl}/favicon.svg`);
    assert.equal(favRes.status, 200);
    assert.match(favRes.headers.get('content-type') || '', /image\/svg\+xml/);

    // GET /api/status
    const statusRes = await fetch(`${baseUrl}/api/status`);
    assert.equal(statusRes.status, 200);
    const statusJson = await statusRes.json();
    assert.equal(statusJson.ok, true);
    assert.equal(statusJson.data.workOrders.length, 3);
    assert.equal(statusJson.data.mcpPermissionTable.length, 5);

    // POST /api/run/stream SSE stage beats
    const sseRes = await fetch(`${baseUrl}/api/run/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workOrderId: 'WO-101', beatDelayMs: 0 })
    });
    assert.equal(sseRes.status, 200);
    assert.match(sseRes.headers.get('content-type') || '', /text\/event-stream/);
    const sseRaw = await sseRes.text();

    for (const expectedEvent of [
        'event: refinery',
        'event: planner',
        'event: foundry',
        'event: validator.attempt1',
        'event: validator.workaround_blocked',
        'event: validator.verified',
        'event: pr.dispatched',
        'event: done'
    ]) {
        assert.ok(
            sseRaw.includes(expectedEvent),
            `Missing expected SSE frame "${expectedEvent}"`
        );
    }

    // POST /api/run synchronous fallback
    const runRes = await fetch(`${baseUrl}/api/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ workOrderId: 'WO-101' })
    });
    assert.equal(runRes.status, 200);
    const runJson = await runRes.json();
    assert.equal(runJson.ok, true);
    assert.equal(runJson.data.standardAgent.outcome, 'UNSAFE MERGE');
    assert.equal(runJson.data.standardAgent.deltaCents, 1);
    assert.equal(runJson.data.deadbolt.attempts[0].verdict, 'GATE_REJECTED');
    assert.equal(runJson.data.deadbolt.attempts[1].verdict, 'WORKAROUND_REJECTED');
    assert.equal(runJson.data.deadbolt.attempts[2].verdict, 'VERIFIED');

    // GET /api/audit
    const auditRes = await fetch(`${baseUrl}/api/audit?limit=20`);
    assert.equal(auditRes.status, 200);
    const auditJson = await auditRes.json();
    assert.equal(auditJson.ok, true);
    assert.equal(auditJson.data.valid, true);
});

test('8090 Software Factory v2 Organization Admin (sofa-admin-*) and External API (sofa-ext-*) connectors', async () => {
    const captured = [];
    const mockSofaFetch = async (url, init = {}) => {
        const parsed = new URL(url);
        captured.push({
            pathname: parsed.pathname,
            search: parsed.search,
            headers: init.headers || {}
        });

        if (parsed.pathname === '/v2/organization-api/spend-status') {
            return new Response(
                JSON.stringify({
                    current_period_spend_usd: '4.18',
                    on_demand_limit_usd: '50.00'
                }),
                { status: 200, headers: { 'Content-Type': 'application/json' } }
            );
        }

        if (parsed.pathname === '/v2/external-api/health') {
            return new Response(JSON.stringify({ status: 'healthy' }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        if (parsed.pathname === '/v2/external-api/work_orders') {
            return new Response(
                JSON.stringify({
                    items: [{ id: 'wo-uuid-101', title: 'WO-101 Fee Residual' }],
                    total: 3,
                    page: 1,
                    page_size: 5,
                    total_pages: 1
                }),
                { status: 200, headers: { 'Content-Type': 'application/json' } }
            );
        }

        return new Response(JSON.stringify({ detail: 'not found' }), { status: 404 });
    };

    const sponsorHub = createSponsorHub({
        config: {
            sofaApiBaseUrl: 'https://api.factory.8090.dev',
            sofaAdminApiKey: 'sofa-admin-unit-fixture',
            sofaApiKey: 'sofa-ext-unit-fixture'
        },
        lookupFn: async () => [{ address: '93.184.216.34', family: 4 }],
        fetchImpl: mockSofaFetch
    });

    const statusEnv = sponsorHub.getConnectorStatuses();
    assert.equal(statusEnv.ok, true);
    assert.equal(statusEnv.data.connectors.softwareFactory8090.liveConfigured, true);
    assert.equal(statusEnv.data.connectors.softwareFactory8090.mode, 'sofa_dual_api_live');

    const syncEnv = await sponsorHub.syncSoftwareFactoryWorkOrder({
        workOrder: { id: 'WO-101', title: 'Fix fee residual allocation' }
    });
    assert.equal(syncEnv.ok, true);
    assert.equal(syncEnv.data.liveMcpSync.connected, true);
    assert.equal(syncEnv.data.liveMcpSync.mode, 'sofa_dual_api_live');
    assert.equal(syncEnv.data.liveMcpSync.externalApiHealthy, true);
    assert.equal(syncEnv.data.liveMcpSync.externalWorkOrderCount, 3);
    assert.equal(syncEnv.data.liveMcpSync.orgSpendStatus.current_period_spend_usd, '4.18');

    const orgReq = captured.find((r) => r.pathname === '/v2/organization-api/spend-status');
    assert.ok(orgReq);
    assert.equal(orgReq.headers['X-API-Key'], 'sofa-admin-unit-fixture');

    const extReq = captured.find((r) => r.pathname === '/v2/external-api/health');
    assert.ok(extReq);
    assert.equal(extReq.headers.Authorization, 'Bearer sofa-ext-unit-fixture');
});
