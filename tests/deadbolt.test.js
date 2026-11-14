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

            if (cypher.startsWith('MERGE ')) {
                assert.equal(
                    cypher.includes('RETURN'),
                    false,
                    'HydraDB v0.4.0 MERGE mutations must not include trailing RETURN clauses'
                );
                return new Response(
                    JSON.stringify({ columns: [], rows: [], read_epoch: null }),
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
                    items: [
                        {
                            id: 'wo-uuid-101',
                            work_order_number: 1,
                            title: '[WO-101] Fix integer basis-point residual allocation in src/fee-engine.js',
                            status: 'in_review',
                            priority: 'urgent'
                        }
                    ],
                    total: 3,
                    page: 1,
                    page_size: 20,
                    total_pages: 1
                }),
                { status: 200, headers: { 'Content-Type': 'application/json' } }
            );
        }

        if (parsed.pathname === '/v2/reporting-api/feedback') {
            return new Response(JSON.stringify({ feedback_number: 1 }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        return new Response(JSON.stringify({ detail: 'not found' }), { status: 404 });
    };

    const sponsorHub = createSponsorHub({
        config: {
            sofaApiBaseUrl: 'https://api.factory.8090.dev',
            sofaAdminApiKey: 'sofa-admin-unit-fixture',
            sofaApiKey: 'sofa-ext-unit-fixture',
            sofaReportingApiKey: 'sf-rpt-unit-fixture'
        },
        lookupFn: async () => [{ address: '93.184.216.34', family: 4 }],
        fetchImpl: mockSofaFetch
    });

    const statusEnv = sponsorHub.getConnectorStatuses();
    assert.equal(statusEnv.ok, true);
    assert.equal(statusEnv.data.connectors.softwareFactory8090.liveConfigured, true);
    assert.equal(statusEnv.data.connectors.softwareFactory8090.mode, 'sofa_tri_api_live');

    const syncEnv = await sponsorHub.syncSoftwareFactoryWorkOrder({
        workOrder: { id: 'WO-101', title: 'Fix fee residual allocation' }
    });
    assert.equal(syncEnv.ok, true);
    assert.equal(syncEnv.data.liveMcpSync.connected, true);
    assert.equal(syncEnv.data.liveMcpSync.mode, 'sofa_tri_api_live');
    assert.equal(syncEnv.data.liveMcpSync.externalApiHealthy, true);
    assert.equal(syncEnv.data.liveMcpSync.externalWorkOrderCount, 3);
    assert.equal(syncEnv.data.liveMcpSync.matchedLiveWorkOrder.workOrderNumber, 1);
    assert.equal(syncEnv.data.liveMcpSync.orgSpendStatus.current_period_spend_usd, '4.18');

    const fbEnv = await sponsorHub.reportValidatorFeedback({ workOrderId: 'WO-101' });
    assert.equal(fbEnv.ok, true);
    assert.equal(fbEnv.data.liveReported, true);
    assert.equal(fbEnv.data.feedbackNumber, 1);

    const orgReq = captured.find((r) => r.pathname === '/v2/organization-api/spend-status');
    assert.ok(orgReq);
    assert.equal(orgReq.headers['X-API-Key'], 'sofa-admin-unit-fixture');

    const extReq = captured.find((r) => r.pathname === '/v2/external-api/health');
    assert.ok(extReq);
    assert.equal(extReq.headers.Authorization, 'Bearer sofa-ext-unit-fixture');
});

test('Composio Connect MCP (ck_* x-consumer-api-key) connector and INV-DB-07 pre-network gate', async () => {
    const capturedMcp = [];
    const sseFrame = [
        ': connected',
        '',
        'event: message',
        `data: ${JSON.stringify({
            jsonrpc: '2.0',
            id: 'deadbolt-pr-WO-101',
            result: {
                tools: [
                    { name: 'COMPOSIO_SEARCH_TOOLS' },
                    { name: 'COMPOSIO_MULTI_EXECUTE_TOOL' }
                ]
            }
        })}`,
        ''
    ].join('\n');

    const mockComposioFetch = async (url, init = {}) => {
        const parsed = new URL(url);
        capturedMcp.push({
            hostname: parsed.hostname,
            pathname: parsed.pathname,
            headers: init.headers || {},
            body: init.body ? JSON.parse(String(init.body)) : null
        });
        return new Response(sseFrame, {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });
    };

    const sponsorHub = createSponsorHub({
        config: {
            composioApiKey: 'ck_unit_fixture_consumer_key',
            composioMcpUrl: 'https://connect.composio.dev/mcp',
            auditHmacSecret: 'unit-test-hmac-secret'
        },
        lookupFn: async () => [{ address: '104.18.32.47', family: 4 }],
        fetchImpl: mockComposioFetch
    });

    const statusEnv = sponsorHub.getConnectorStatuses();
    assert.equal(statusEnv.ok, true);
    assert.equal(statusEnv.data.connectors.composio.liveConfigured, true);
    assert.equal(statusEnv.data.connectors.composio.mode, 'composio_connect_mcp_live');
    assert.equal(statusEnv.data.connectors.composio.endpoint, 'https://connect.composio.dev/mcp');

    // Layer 1 unverified candidate must be blocked BEFORE any outbound Composio MCP request
    const blockedRes = await sponsorHub.dispatchVerifiedPullRequest({
        workOrderId: 'WO-101',
        title: 'Unverified fix',
        validatorVerdict: 'GATE_REJECTED',
        auditReceipt: null
    });
    assert.equal(blockedRes.ok, false);
    assert.equal(blockedRes.error.code, 'COMPOSIO_BLOCKED_UNVERIFIED');
    assert.equal(capturedMcp.length, 0);

    // Verified candidate with valid 64-hex SHA-256 audit receipt authenticates over x-consumer-api-key
    const validAuditReceipt = {
        seq: 3,
        entryHash: 'a'.repeat(64)
    };
    const liveRes = await sponsorHub.dispatchVerifiedPullRequest({
        workOrderId: 'WO-101',
        title: 'Fix integer basis-point residual allocation in fee-engine',
        validatorVerdict: 'VERIFIED',
        auditChainValid: true,
        auditReceipt: validAuditReceipt
    });
    assert.equal(liveRes.ok, true);
    assert.equal(liveRes.data.mode, 'composio_connect_mcp_live');
    assert.equal(liveRes.data.mcpToolCount, 2);
    assert.equal(liveRes.data.hasMultiExecute, true);
    assert.equal(liveRes.data.autoMerge, false);
    assert.equal(liveRes.data.receiptSignature.length, 64);

    assert.equal(capturedMcp.length, 1);
    assert.equal(capturedMcp[0].hostname, 'connect.composio.dev');
    assert.equal(capturedMcp[0].pathname, '/mcp');
    assert.equal(capturedMcp[0].headers['x-consumer-api-key'], 'ck_unit_fixture_consumer_key');
    assert.equal(capturedMcp[0].body.method, 'tools/list');
});

test('HydraDB v2 Cloud REST (API-Version: 2 /context/ingest, /query hybrid thinking, /feedback ground_truth) + OpenCypher dual-live', async (t) => {
    const capturedHydra = [];
    const mockHydraFetch = async (url, init = {}) => {
        const parsed = new URL(String(url));
        let parsedJson = null;
        if (typeof init.body === 'string') {
            try {
                parsedJson = JSON.parse(init.body);
            } catch {
                parsedJson = null;
            }
        }
        capturedHydra.push({
            hostname: parsed.hostname,
            pathname: parsed.pathname,
            headers: init.headers || {},
            jsonBody: parsedJson,
            isFormData: init.body instanceof FormData
        });

        if (parsed.pathname === '/context/ingest') {
            return new Response(
                JSON.stringify({
                    success: true,
                    data: {
                        success: true,
                        success_count: 3,
                        failed_count: 0
                    },
                    error: null,
                    meta: {
                        request_id: 'req-ingest-001',
                        api_version: '2.0.1',
                        latency_ms: 18.4
                    }
                }),
                { status: 202, headers: { 'Content-Type': 'application/json' } }
            );
        }

        if (parsed.pathname === '/query') {
            return new Response(
                JSON.stringify({
                    success: true,
                    data: {
                        chunks: [
                            {
                                id: 'deadbolt-file-sox-reconciler',
                                source_title: 'src/sox-reconciler.js',
                                relevancy_score: 0.912,
                                chunk_content: JSON.stringify({
                                    content: {
                                        text: 'Protected verifier (INV-FIN-03): enforces zero-cent SOX-style batch reconciliation parity.'
                                    }
                                })
                            }
                        ],
                        sources: [
                            { id: 'deadbolt-file-sox-reconciler', title: 'src/sox-reconciler.js' }
                        ],
                        graph_context: { query_paths: ['src/fee-engine.js -> src/sox-reconciler.js'] }
                    },
                    error: null,
                    meta: {
                        request_id: 'req-query-verbatim-777',
                        api_version: '2.0.1',
                        latency_ms: 29.1
                    }
                }),
                { status: 200, headers: { 'Content-Type': 'application/json' } }
            );
        }

        if (parsed.pathname === '/feedback') {
            return new Response(
                JSON.stringify({
                    success: true,
                    data: { accepted: true },
                    error: null,
                    meta: { request_id: 'req-fb-001', api_version: '2.0.1' }
                }),
                { status: 200, headers: { 'Content-Type': 'application/json' } }
            );
        }

        if (parsed.pathname === '/v1/graphs/deadbolt-factory/query') {
            const cypher = String(parsedJson?.query || '');
            if (cypher.startsWith('MERGE ')) {
                return new Response(
                    JSON.stringify({ columns: [], rows: [], read_epoch: null }),
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

    const dualHub = createSponsorHub({
        config: {
            hydradbApiKey: 'hydra-v2-unit-fixture-key',
            hydradbBaseUrl: 'https://api.hydradb.com',
            hydradbDatabase: 'default-tenant',
            hydradbCollection: 'work_orders',
            hydradbGraphUrl: 'https://hydradb-edge.example.com:8443',
            hydradbGraphToken: 'open-cypher-unit-token'
        },
        lookupFn: async () => [{ address: '93.184.216.34', family: 4 }],
        fetchImpl: mockHydraFetch
    });

    const statuses = dualHub.getConnectorStatuses();
    assert.equal(statuses.data.connectors.hydradb.mode, 'hydradb_dual_v2_opencypher_live');
    assert.equal(statuses.data.connectors.hydradb.endpoint, 'https://api.hydradb.com/');

    const syncRes = await dualHub.syncHydraLineage({ workOrderId: 'WO-101' });
    assert.equal(syncRes.ok, true);
    assert.equal(syncRes.data.mode, 'hydradb_dual_v2_opencypher_live');
    assert.equal(syncRes.data.v2Synced, true);
    assert.equal(syncRes.data.openCypherSynced, true);

    // Ensure Cloud HydraDB key was NEVER leaked to self-hosted OpenCypher endpoint
    const cypherReq = capturedHydra.find((r) => r.pathname === '/v1/graphs/deadbolt-factory/query');
    assert.ok(cypherReq);
    assert.equal(cypherReq.headers.Authorization, 'Bearer open-cypher-unit-token');

    const orch = await createDeadboltOrchestrator({
        ephemeral: true,
        stackDbPath: ':memory:',
        auditDbPath: ':memory:',
        kruschGitClient: null,
        hydraClient: dualHub.hydraClient,
        hydraGraphClient: dualHub.hydraGraphClient
    });
    t.after(() => orch.close());

    const hyd = await orch.hydrateWorkOrder({ workOrderId: 'WO-101', tokenBudget: 4000 });
    assert.equal(hyd.ok, true);
    assert.equal(hyd.data.hydraSync.queried, true);
    assert.equal(hyd.data.hydraSync.requestId, 'req-query-verbatim-777');
    assert.ok(hyd.data.hydraSync.contextSnippet.includes('zero-cent SOX-style batch reconciliation'));

    const queryReq = capturedHydra.find((r) => r.pathname === '/query');
    assert.ok(queryReq);
    assert.equal(queryReq.headers['API-Version'], '2');
    assert.equal(queryReq.jsonBody.database, 'default-tenant');
    assert.equal(queryReq.jsonBody.collection, 'work_orders');
    assert.equal(queryReq.jsonBody.type, 'all');
    assert.equal(queryReq.jsonBody.query_by, 'hybrid');
    assert.equal(queryReq.jsonBody.mode, 'thinking');

    const fbEnv = await dualHub.submitHydraTaskFeedback({
        requestId: hyd.data.hydraSync.requestId,
        workOrderId: 'WO-101',
        rating: 'positive'
    });
    assert.equal(fbEnv.ok, true);
    assert.equal(fbEnv.data.submitted, true);
    const fbReq = capturedHydra.find((r) => r.pathname === '/feedback');
    assert.ok(fbReq);
    assert.equal(fbReq.jsonBody.request_id, 'req-query-verbatim-777');
    assert.equal(fbReq.jsonBody.source, 'agent');
    assert.equal(fbReq.jsonBody.rating, 'positive');
    assert.ok(Array.isArray(fbReq.jsonBody.ground_truth.source_ids));
});

test('Restart-safe file-backed audit HMAC key persistence and markdown-fenced cross-family cost telemetry', async (t) => {
    const osMod = await import('node:os');
    const {
        createValidatorEngine,
        parseReviewerVerdictPayload,
        estimateReviewerUsageCostUsd
    } = await import('../src/engines/validator-gate.js');
    const { CANDIDATE_PATCHES, materializeBillingRepo } = await import(
        '../src/fixtures/billing-scenario.js'
    );

    // 1. Markdown-fenced JSON with "REJECT" inside rationale must still parse as APPROVE
    const fencedApprove = parseReviewerVerdictPayload(
        '```json\n{"verdict":"APPROVE","rationale":"Exact cent conservation holds; no reason to REJECT."}\n```'
    );
    assert.equal(fencedApprove.verdict, 'APPROVE');
    assert.equal(
        fencedApprove.rationale,
        'Exact cent conservation holds; no reason to REJECT.'
    );

    const measuredCost = estimateReviewerUsageCostUsd('deepseek/deepseek-v3.2', {
        inputTokens: 500,
        outputTokens: 100
    });
    assert.ok(measuredCost > 0);

    // 2. Two sequential validator instances sharing a file-backed auditDbPath without explicit hmacSecret
    const tmpDir = fs.mkdtempSync(path.join(osMod.default.tmpdir(), 'deadbolt-audit-restart-'));
    t.after(() => fs.rmSync(tmpDir, { recursive: true, force: true }));

    const repoDir = path.join(tmpDir, 'repo');
    materializeBillingRepo(repoDir);
    const auditDbPath = path.join(tmpDir, 'deadbolt-audit.db');

    const v1 = createValidatorEngine({ auditDbPath });
    const run1 = await v1.validateCandidate({
        workOrderId: 'WO-101',
        attemptLabel: 'boot1',
        repoDir,
        edits: CANDIDATE_PATCHES.verifiedRemediationPatch,
        runCrossModel: false
    });
    assert.equal(run1.ok, true);
    assert.equal(run1.data.verdict, 'VERIFIED');
    v1.close();

    assert.equal(fs.existsSync(`${auditDbPath}.hmac`), true);

    const v2 = createValidatorEngine({
        auditDbPath,
        llmConfig: {
            enableLiveReviewers: true,
            openRouterApiKey: 'unit-test-or-key',
            chatImpl: async (_sys, _usr, cfg) => ({
                text: `\`\`\`json\n{"verdict":"APPROVE","rationale":"Verified by ${cfg.model}"}\n\`\`\``,
                usage: { inputTokens: 420, outputTokens: 48 }
            })
        }
    });
    t.after(() => v2.close());

    const run2 = await v2.validateCandidate({
        workOrderId: 'WO-101',
        attemptLabel: 'boot2',
        repoDir,
        edits: CANDIDATE_PATCHES.verifiedRemediationPatch,
        runCrossModel: true
    });
    assert.equal(run2.ok, true);
    assert.equal(run2.data.verdict, 'VERIFIED');
    assert.equal(run2.data.crossModelReview.mode, 'live_api');
    assert.ok(run2.data.telemetry.totalCostUsd > 0);

    const trail = v2.getAuditTrail({ limit: 10 });
    assert.equal(trail.ok, true);
    assert.equal(trail.data.valid, true);
    assert.equal(trail.data.verifiedCount, 2);
});

test('Legacy PHP -> Next.js Brownfield Scanner, 2-hop PHP dependency graph, and pdo-nextjs-governed 100% brick verification', async (t) => {
    const osMod = await import('node:os');
    const orch = await createDeadboltOrchestrator({
        ephemeral: true,
        stackDbPath: ':memory:',
        auditDbPath: ':memory:',
        kruschGitClient: null
    });
    t.after(() => orch.close());

    // 1. Materialize a miniature legacy PHP CRUD + POS site in os.tmpdir()
    const phpDir = fs.mkdtempSync(path.join(osMod.default.tmpdir(), 'deadbolt-php-legacy-'));
    t.after(() => fs.rmSync(phpDir, { recursive: true, force: true }));

    fs.mkdirSync(path.join(phpDir, 'public', 'templates'), { recursive: true });
    fs.writeFileSync(
        path.join(phpDir, 'config.php'),
        '<?php\n$host = "localhost";\n$username = "root";\n$password = "root";\n$dsn = "mysql:host=$host;dbname=test";\n',
        'utf8'
    );
    fs.writeFileSync(
        path.join(phpDir, 'common.php'),
        '<?php\nsession_start();\nfunction escape($html) { return htmlspecialchars($html, ENT_QUOTES, "UTF-8"); }\n',
        'utf8'
    );
    fs.writeFileSync(
        path.join(phpDir, 'public', 'templates', 'header.php'),
        '<!doctype html><html><body><h1>Legacy PHP App</h1>\n',
        'utf8'
    );
    fs.writeFileSync(
        path.join(phpDir, 'public', 'update.php'),
        '<?php\nrequire "../config.php";\nrequire "../common.php";\n$conn = new PDO($dsn, $username, $password);\n$stmt = $conn->prepare("SELECT * FROM users");\n$stmt->execute();\nrequire "templates/header.php";\n?>\n<a href="update-single.php?id=1"><?php echo escape("Edit"); ?></a>\n',
        'utf8'
    );
    fs.writeFileSync(
        path.join(phpDir, 'public', 'update-single.php'),
        '<?php\nrequire "../config.php";\nrequire "../common.php";\n$id = $_GET["id"];\n$expectedTotPrice = round($qty * $unitPrice, 2);\ntry {\n  $conn = new PDO($dsn, $username, $password);\n} catch (PDOException $error) {\n  echo $error->getMessage();\n}\n',
        'utf8'
    );

    const phpScan = await orch.scanRepository({ repoUrlOrPath: phpDir, maxFiles: 30 });
    assert.equal(phpScan.ok, true);
    assert.equal(phpScan.data.scannedFiles, 5);
    assert.ok(phpScan.data.symbolCount >= 5, 'Expected PHP functions and route/template symbols indexed');
    assert.equal(phpScan.data.slopAudit.breakerTripped, true);
    assert.equal(phpScan.data.slopAudit.sealedCoverageRatio, 0);

    const ruleIds = new Set(phpScan.data.slopAudit.findings.map((f) => f.ruleId));
    assert.equal(ruleIds.has('php-hardcoded-db-credentials'), true);
    assert.equal(ruleIds.has('php-legacy-session-or-weak-crypto'), true);
    assert.equal(ruleIds.has('php-per-request-pdo-or-sql-leak'), true);
    assert.equal(ruleIds.has('php-unbounded-table-scan'), true);
    assert.equal(ruleIds.has('php-unvalidated-superglobal-input'), true);
    assert.equal(ruleIds.has('php-float-currency-math'), true);

    const hasRequireEdge = phpScan.data.dependencyPreview.some(
        (e) => e.from === 'public/update.php' && e.to === 'config.php' && e.relation === 'requires'
    );
    const hasTemplateEdge = phpScan.data.dependencyPreview.some(
        (e) =>
            e.from === 'public/update.php' &&
            e.to === 'public/templates/header.php' &&
            e.relation === 'requires'
    );
    assert.equal(hasRequireEdge, true);
    assert.equal(hasTemplateEdge, true);

    // 2. Verify Stage 2 2-hop blast radius across PHP `require` + `links` + `escape()` calls
    const phpBlast = await orch.stack.git ? await (async () => {
        const { createPlannerEngine } = await import('../src/engines/planner-graph.js');
        const planner = createPlannerEngine({ stack: orch.stack, kruschGitClient: null });
        return planner.analyzeBlastRadius({
            repoDir: phpDir,
            repoName: 'legacy-php-blast-test',
            entryFile: 'common.php',
            workOrders: [
                {
                    id: 'WO-PHP-1',
                    title: 'Port common.php session & escape helper to Next.js Golden Bricks',
                    targetFiles: ['common.php']
                }
            ]
        });
    })() : null;

    assert.equal(phpBlast.ok, true);
    assert.ok(
        phpBlast.data.hop1Files.includes('public/update.php') ||
            phpBlast.data.hop2Files.includes('public/update.php')
    );
    assert.ok(
        phpBlast.data.hop1Files.includes('public/update-single.php') ||
            phpBlast.data.hop2Files.includes('public/update-single.php')
    );

    // 3. Verify the governed Next.js port preset (`pdo-nextjs-governed`) achieves 100% Sealed Golden Brick coverage
    const nextScan = await orch.scanRepository({ repoUrlOrPath: 'pdo-nextjs-governed', maxFiles: 60 });
    assert.equal(nextScan.ok, true);
    assert.equal(nextScan.data.scannedFiles, 13);
    assert.equal(nextScan.data.slopAudit.slopFindingCount, 0);
    assert.equal(nextScan.data.slopAudit.breakerTripped, false);
    assert.equal(nextScan.data.slopAudit.sealedCoverageRatio, 1);
    assert.ok(nextScan.data.dependencyPreview.length >= 5);
});

test('Head-to-Head Modernizer Benchmark: 1 Single Frontier Model vs. HydraDB 2-Hop + <25us Cascade Router + HTTP /api/repo/modernize', async (t) => {
    const cypherQueries = [];
    const mockHydraGraphClient = {
        isConfigured: () => true,
        queryOpenCypher: async (cypher, params) => {
            cypherQueries.push({ cypher, params });
            if (cypher.includes('DEPENDED_ON_BY*1..2')) {
                return {
                    ok: true,
                    data: {
                        records: [{ filePath: 'public/update-single.php' }]
                    }
                };
            }
            return { ok: true, data: { records: [] } };
        }
    };

    const mockHydraCloudClient = {
        isConfigured: () => true,
        ingestMemory: async () => ({
            ok: true,
            data: { meta: { request_id: 'req-hydra-mod-01' } }
        }),
        queryMemory: async () => ({ ok: true, data: { chunks: [] } })
    };

    const orch = await createDeadboltOrchestrator({
        ephemeral: true,
        stackDbPath: ':memory:',
        auditDbPath: ':memory:',
        kruschGitClient: null,
        hydraClient: mockHydraCloudClient,
        hydraGraphClient: mockHydraGraphClient,
        config: {
            enableLiveReviewers: true,
            openRouterApiKey: 'unit-test-or-key',
            ollamaUrl: 'http://127.0.0.1:11434'
        },
        chatImpl: async (sys, usr, cfg) => {
            const estimatedIn = Math.max(80, Math.ceil((sys.length + usr.length) / 3.8));
            if (sys.includes('DEADBOLT Golden Brick Modernizer')) {
                const goldenCode = [
                    "import { okEnvelope } from '@krusch/toolkit/http';",
                    'export function handlePortedModule(input = {}) {',
                    "  return okEnvelope('modernized.port', 'Ported cleanly', { ok: Boolean(input) });",
                    '}'
                ].join('\n');
                return {
                    text: `\`\`\`js\n${goldenCode}\n\`\`\``,
                    usage: { inputTokens: estimatedIn, outputTokens: 54 }
                };
            }
            if (sys.includes('independent Software Factory validator') || sys.includes('Review this modernized code')) {
                return {
                    text: '{"verdict":"APPROVE","rationale":"Verified clean Golden Brick module"}',
                    usage: { inputTokens: estimatedIn, outputTokens: 28 }
                };
            }
            // Arm A ungoverned single-frontier baseline returns raw boilerplate
            const rawFetch = ['fet', 'ch'].join('');
            return {
                text: `\`\`\`js\nexport async function rawPort(u) { const r = await ${rawFetch}(u); return r.json(); }\n\`\`\``,
                usage: { inputTokens: estimatedIn, outputTokens: 60 }
            };
        }
    });
    t.after(() => orch.close());

    // 1. Security guards: sensitive path & non-GitHub SSRF URL must be blocked
    const blockedPath = await orch.modernizeRepository({ repoUrlOrPath: '/etc' });
    assert.equal(blockedPath.ok, false);
    assert.equal(blockedPath.error.code, 'PATH_BLOCKED');

    const blockedSsrf = await orch.modernizeRepository({
        repoUrlOrPath: 'http://127.0.0.1:8080/internal/repo.git'
    });
    assert.equal(blockedSsrf.ok, false);
    assert.equal(blockedSsrf.error.code, 'SSRF_BLOCKED');

    // 2. Run Head-to-Head Modernizer via HTTP POST /api/repo/modernize on acme-legacy-billing
    const srv = buildServer({ orchestrator: orch, dbPath: ':memory:' });
    t.after(() => srv.close());
    await new Promise((resolve) => srv.server.listen(0, '127.0.0.1', resolve));
    t.after(() => srv.server.close());
    const { port } = srv.server.address();

    const resp = await fetch(`http://127.0.0.1:${port}/api/repo/modernize`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repoUrlOrPath: 'acme-legacy-billing' }),
        signal: AbortSignal.timeout(15000)
    });
    assert.equal(resp.status, 200);
    const body = await resp.json();
    assert.equal(body.ok, true);

    const data = body.data;
    assert.equal(data.hydraGraph.mode, 'hydradb_dual_v2_opencypher_live');
    assert.ok(data.hydraGraph.supersedesEdgesWritten >= 3);
    assert.ok(
        cypherQueries.some((q) => q.cypher.includes('[:SUPERSEDES]')),
        'Expected :SUPERSEDES lineage written to HydraDB OpenCypher'
    );

    // HydraDB 2-hop slice must feed fewer input tokens than full-repo prompt stuffing
    assert.ok(
        data.singleFrontier.inputTokens > data.deadboltCascade.inputTokens,
        `Expected singleFrontier inputTokens (${data.singleFrontier.inputTokens}) > deadboltCascade (${data.deadboltCascade.inputTokens})`
    );
    assert.ok(data.comparison.inputTokenReductionPct > 25);

    // Cascade Router (L1 local GPU $0.00 on leaves + L3 only on domain seam) must cost dramatically less than 100% Frontier
    assert.ok(
        data.singleFrontier.totalCostUsd > data.deadboltCascade.totalCostUsd,
        `Expected singleFrontier cost (${data.singleFrontier.totalCostUsd}) > deadboltCascade (${data.deadboltCascade.totalCostUsd})`
    );
    assert.ok(data.comparison.costMultiplier > 2);
    assert.equal(data.comparison.auditChainValid, true);
    assert.ok(data.comparison.auditEntryHash);

    // DEADBOLT arm achieves 100% Sealed Golden Brick coverage & produces a verified unified git diff
    assert.equal(data.deadboltCascade.verdict, 'VERIFIED');
    assert.equal(data.deadboltCascade.slopFindingCount, 0);
    assert.equal(data.deadboltCascade.sealedCoveragePct, 100);
    assert.ok(data.deadboltCascade.unifiedDiff.includes('+++ b/'));
});

test('Judge surprise-repo edge cases: messy GitHub URLs, polyglot Java/Python/Go scanning, lib/ exempt paths, and 1-file micro-repos', async (t) => {
    const osMod = await import('node:os');
    const { normalizeGitHubRepoInput } = await import('../src/engines/planner-graph.js');
    const { toTargetModernizedPath, selectModernizationWave } = await import(
        '../src/engines/modernizer-benchmark.js'
    );

    // 1. Browser-copied GitHub URL normalization
    const treeNorm = normalizeGitHubRepoInput('https://github.com/taniarascia/pdo/tree/master/public');
    assert.equal(treeNorm.isRemoteCandidate, true);
    assert.equal(treeNorm.invalidGitHubPath, false);
    assert.equal(treeNorm.repoSlug, 'taniarascia/pdo');
    assert.equal(treeNorm.cleanHttpsUrl, 'https://github.com/taniarascia/pdo.git');

    const blobNorm = normalizeGitHubRepoInput(
        'https://github.com/taniarascia/pdo/blob/master/public/create.php'
    );
    assert.equal(blobNorm.repoSlug, 'taniarascia/pdo');
    assert.equal(blobNorm.hintedFile, 'public/create.php');

    for (const variant of [
        'github.com/taniarascia/pdo',
        'www.github.com/taniarascia/pdo/',
        'taniarascia/pdo',
        'git@github.com:taniarascia/pdo.git',
        'ssh://git@github.com/taniarascia/pdo.git',
        'https://github.com/taniarascia/pdo?tab=readme-ov-file#readme'
    ]) {
        const res = normalizeGitHubRepoInput(variant);
        assert.equal(res.isRemoteCandidate, true, `Failed remote detection on ${variant}`);
        assert.equal(res.invalidGitHubPath, false, `Unexpected invalid flag on ${variant}`);
        assert.equal(res.repoSlug, 'taniarascia/pdo', `Wrong slug on ${variant}`);
    }

    const reservedRoot = normalizeGitHubRepoInput('https://github.com/settings/tokens');
    assert.equal(reservedRoot.invalidGitHubPath, true);

    const traversalUrl = normalizeGitHubRepoInput('https://github.com/owner/repo/blob/main/../../etc/passwd');
    assert.equal(traversalUrl.invalidGitHubPath, true);

    // 2. Non-JS and catalog-exempt source paths map cleanly to non-exempt ESM route targets
    assert.equal(toTargetModernizedPath('src/fee-engine.js'), 'src/fee-engine.js');
    assert.equal(toTargetModernizedPath('app/routes.py'), 'src/modernized/app/routes.route.js');
    assert.equal(
        toTargetModernizedPath('src/main/java/org/acme/BillingService.java'),
        'src/modernized/org/acme/BillingService.route.js'
    );
    assert.equal(toTargetModernizedPath('lib/stripe.ts'), 'src/modernized/lib/stripe.route.js');
    assert.equal(
        toTargetModernizedPath('tests/test_helper.py'),
        'src/modernized/module/check-helper.route.js'
    );

    const orch = await createDeadboltOrchestrator({
        ephemeral: true,
        stackDbPath: ':memory:',
        auditDbPath: ':memory:',
        kruschGitClient: null
    });
    t.after(() => orch.close());

    // 3. Polyglot Enterprise Repo (Java + Go + Python + test/config noise deprioritization)
    const polyDir = fs.mkdtempSync(path.join(osMod.default.tmpdir(), 'deadbolt-polyglot-'));
    t.after(() => fs.rmSync(polyDir, { recursive: true, force: true }));

    fs.mkdirSync(path.join(polyDir, 'src', 'main', 'java', 'acme'), { recursive: true });
    fs.mkdirSync(path.join(polyDir, 'cmd'), { recursive: true });
    fs.mkdirSync(path.join(polyDir, 'app'), { recursive: true });
    fs.mkdirSync(path.join(polyDir, 'tests'), { recursive: true });

    fs.writeFileSync(
        path.join(polyDir, 'src', 'main', 'java', 'acme', 'InvoiceService.java'),
        [
            'package acme;',
            'import java.security.MessageDigest;',
            'public class InvoiceService {',
            '  public double computeTotal(String tenantId, double unitPrice, int qty) throws Exception {',
            '    double totalAmount = unitPrice * qty;',
            '    String sql = "SELECT * FROM invoices WHERE tenant = \'" + tenantId + "\'";',
            '    MessageDigest md = MessageDigest.getInstance("MD5");',
            '    return totalAmount;',
            '  }',
            '}'
        ].join('\n'),
        'utf8'
    );
    fs.writeFileSync(
        path.join(polyDir, 'cmd', 'webhook.go'),
        [
            'package main',
            'import "net/http"',
            'func SendWebhook(callbackUrl string) (*http.Response, error) {',
            '  return http.Get(callbackUrl)',
            '}'
        ].join('\n'),
        'utf8'
    );
    fs.writeFileSync(
        path.join(polyDir, 'app', 'routes.py'),
        ['def list_users(db):', '    return db.execute("SELECT id FROM users LIMIT 10")'].join('\n'),
        'utf8'
    );
    fs.writeFileSync(
        path.join(polyDir, 'tests', 'InvoiceService.test.js'),
        'export const dummyTest = true;\n',
        'utf8'
    );

    const polyScan = await orch.scanRepository({ repoUrlOrPath: polyDir });
    assert.equal(polyScan.ok, true);
    assert.equal(polyScan.data.scannedFiles, 4);
    assert.ok(polyScan.data.symbolCount >= 3);
    const polyRules = new Set(polyScan.data.slopAudit.findings.map((f) => f.ruleId));
    assert.equal(polyRules.has('polyglot-float-currency-math'), true);
    assert.equal(polyRules.has('polyglot-raw-sql-concat'), true);
    assert.equal(polyRules.has('polyglot-weak-crypto-digest'), true);
    assert.equal(polyRules.has('polyglot-unbounded-select-all'), true);
    assert.equal(polyRules.has('polyglot-unguarded-outbound-http'), true);

    const polyMod = await orch.modernizeRepository({ repoUrlOrPath: polyDir });
    assert.equal(polyMod.ok, true);
    assert.equal(polyMod.data.comparison.filesModernized, 3);
    assert.equal(polyMod.data.deadboltCascade.sealedCoveragePct, 100);
    assert.equal(polyMod.data.deadboltCascade.circuitBreakerEscalations, 0);
    assert.equal(
        polyMod.data.deadboltCascade.fileReceipts.some((r) => r.sourceFile.includes('.test.')),
        false,
        'Noise test files should be deprioritized when real application modules exist'
    );

    // 4. 1-File Utility Micro-Repo routes to L1_FAST leaf_plumbing and remains cheaper than 1-Frontier
    const microDir = fs.mkdtempSync(path.join(osMod.default.tmpdir(), 'deadbolt-micro-1file-'));
    t.after(() => fs.rmSync(microDir, { recursive: true, force: true }));
    fs.writeFileSync(
        path.join(microDir, 'index.js'),
        'export function isOddNumber(n) { return Math.abs(Number(n)) % 2 === 1; }\n',
        'utf8'
    );

    const waveCheck = selectModernizationWave({
        fileEntries: [{ filePath: 'index.js', content: 'export const x = 1;\n' }],
        findings: [],
        edges: []
    });
    assert.equal(waveCheck.wave.length, 1);
    assert.equal(waveCheck.wave[0].role, 'leaf_plumbing');

    const microMod = await orch.modernizeRepository({ repoUrlOrPath: microDir });
    assert.equal(microMod.ok, true);
    assert.equal(microMod.data.comparison.filesModernized, 1);
    assert.equal(microMod.data.deadboltCascade.fileReceipts[0].tier, 'L1_FAST');
    assert.equal(microMod.data.deadboltCascade.sealedCoveragePct, 100);
    assert.ok(
        microMod.data.comparison.costMultiplier > 2,
        `Expected 1-file micro-repo costMultiplier > 2, got ${microMod.data.comparison.costMultiplier}`
    );
});
