/**
 * @module server
 * @description DEADBOLT HTTP + SSE + Static Breaker Panel Server (`:4090`) built on
 * `@krusch/toolkit/http` (`createApiServer`, `attachGracefulShutdown`, `okEnvelope`, `errorEnvelope`)
 * and `@krusch/toolkit/streaming` (`sseResponse`).
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    createApiServer,
    attachGracefulShutdown,
    okEnvelope,
    errorEnvelope
} from '@krusch/toolkit/http';
import { sseResponse } from '@krusch/toolkit/streaming';
import { openSqliteDb } from '@krusch/toolkit/sqlite';
import { setupLogging } from '@krusch/toolkit/log';
import { config } from './config.js';
import { createDeadboltOrchestrator } from './orchestrator.js';

const MODULE_DIR = path.dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = path.resolve(MODULE_DIR, '..');
const CLIENT_DIST_DIR = path.join(PROJECT_ROOT, 'client', 'dist');
const CLIENT_PUBLIC_DIR = path.join(PROJECT_ROOT, 'client', 'public');

const FALLBACK_FAVICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 -2 132 218" width="64" height="104"><polygon points="121,2 79,25 93,28 48,50 78,53 19,89 58,85 5,128 44,124 5,158 34,155 4,212 47,191 35,186 70,171 52,168 105,139 66,140 123,103 74,105 128,69 86,69 126,35 102,36" fill="#37e1ff" stroke="#ffffff" stroke-width="2.6" stroke-linejoin="round"/></svg>`;

const FALLBACK_INDEX_HTML = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>DEADBOLT | Software Factory Governance</title>
    <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
  </head>
  <body style="background:#07090E;color:#F8FAFC;font-family:system-ui,sans-serif;padding:2rem;">
    <h1>DEADBOLT Breaker Panel</h1>
    <p>Run <code>npm run build</code> to compile the Vite cockpit bundle, or query <code>/api/status</code>.</p>
  </body>
</html>`;

function sendStaticAsset(res, content, contentType, cacheControl = 'no-cache') {
    if (!res || res.writableEnded || res.destroyed || res.headersSent) return;
    const buf = Buffer.isBuffer(content) ? content : Buffer.from(String(content), 'utf8');
    res.statusCode = 200;
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Length', String(buf.byteLength));
    res.setHeader('Cache-Control', cacheControl);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.end(buf);
}

function serveDistFileOrFallback(res, relPath, contentType, fallbackContent = null) {
    const safeRel = path.normalize(relPath).replace(/^(\.\.(\/|\\|$))+/, '');
    const candidateDist = path.resolve(CLIENT_DIST_DIR, safeRel);
    if (
        candidateDist.startsWith(CLIENT_DIST_DIR + path.sep) &&
        fs.existsSync(candidateDist) &&
        fs.statSync(candidateDist).isFile()
    ) {
        const bytes = fs.readFileSync(candidateDist);
        sendStaticAsset(res, bytes, contentType);
        return;
    }

    const candidatePublic = path.resolve(CLIENT_PUBLIC_DIR, safeRel);
    if (
        candidatePublic.startsWith(CLIENT_PUBLIC_DIR + path.sep) &&
        fs.existsSync(candidatePublic) &&
        fs.statSync(candidatePublic).isFile()
    ) {
        const bytes = fs.readFileSync(candidatePublic);
        sendStaticAsset(res, bytes, contentType);
        return;
    }

    if (fallbackContent !== null) {
        sendStaticAsset(res, fallbackContent, contentType);
        return;
    }

    const notFound = JSON.stringify(
        errorEnvelope('ASSET_NOT_FOUND', `Static asset not found: /${safeRel}`, null, 'deadbolt.static')
    );
    res.statusCode = 404;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.setHeader('Content-Length', String(Buffer.byteLength(notFound, 'utf8')));
    res.end(notFound);
}

function resolveErrorHttpStatus(envelope) {
    const code = String(envelope?.error?.code || '');
    if (
        code === 'PATH_BLOCKED' ||
        code === 'SSRF_BLOCKED' ||
        code.startsWith('COMPOSIO_BLOCKED')
    ) {
        return 403;
    }
    if (code === 'AUDIT_TAMPERED' || code === 'UNVERIFIED_STAGE_BLOCKED') {
        return 409;
    }
    if (code === 'GIT_CLONE_FAILED') {
        return 502;
    }
    return 400;
}

/**
 * Build the DEADBOLT HTTP + SSE + Static UI server.
 * Supports lazy or pre-injected `orchestrator` plus `:memory:` smoke tests.
 *
 * @param {object} [options={}]
 * @param {string} [options.dbPath] - SQLite path for telemetry events (`:memory:` supported)
 * @param {object|null} [options.orchestrator=null] - Optional pre-initialized Deadbolt orchestrator
 * @param {object|null} [options.logger=null] - Structured logger override
 */
export function buildServer({
    dbPath = config.dbPath,
    orchestrator = null,
    logger = null
} = {}) {
    const activeLogger =
        logger || setupLogging(config.serviceName, { logDir: config.logDir, console: false });

    if (dbPath !== ':memory:') {
        fs.mkdirSync(path.dirname(path.resolve(dbPath)), { recursive: true });
    }
    const telemetryDb = openSqliteDb(dbPath);
    telemetryDb.exec(`
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        );
    `);

    let resolvedOrchestrator = orchestrator;
    let orchestratorPromise = null;
    const ownsOrchestrator = !orchestrator;

    async function getOrchestrator() {
        if (resolvedOrchestrator) return resolvedOrchestrator;
        if (!orchestratorPromise) {
            const isEphemeral = dbPath === ':memory:';
            orchestratorPromise = createDeadboltOrchestrator({
                ephemeral: isEphemeral,
                ...(isEphemeral
                    ? { stackDbPath: ':memory:', auditDbPath: ':memory:' }
                    : {})
            })
                .then((instance) => {
                    resolvedOrchestrator = instance;
                    return instance;
                })
                .catch((err) => {
                    orchestratorPromise = null;
                    throw err;
                });
        }
        return orchestratorPromise;
    }

    const server = createApiServer({
        serviceName: config.serviceName,
        version: '0.1.0',
        logger: activeLogger,
        healthCheck: async () => {
            const orch = await getOrchestrator();
            const auditRes = orch.getAuditStatus({ limit: 5 });
            return {
                governanceArmed: true,
                auditChainValid: Boolean(auditRes.ok && auditRes.data?.valid)
            };
        },
        routes: {
            // Static Breaker Cockpit UI routes
            'GET /': (ctx) => {
                serveDistFileOrFallback(
                    ctx.res,
                    'index.html',
                    'text/html; charset=utf-8',
                    FALLBACK_INDEX_HTML
                );
            },
            'GET /index.html': (ctx) => {
                serveDistFileOrFallback(
                    ctx.res,
                    'index.html',
                    'text/html; charset=utf-8',
                    FALLBACK_INDEX_HTML
                );
            },
            'GET /assets/app.js': (ctx) => {
                serveDistFileOrFallback(
                    ctx.res,
                    'assets/app.js',
                    'application/javascript; charset=utf-8'
                );
            },
            'GET /assets/app.css': (ctx) => {
                serveDistFileOrFallback(
                    ctx.res,
                    'assets/app.css',
                    'text/css; charset=utf-8',
                    '/* no separate css bundle */'
                );
            },
            'GET /favicon.svg': (ctx) => {
                serveDistFileOrFallback(
                    ctx.res,
                    'favicon.svg',
                    'image/svg+xml; charset=utf-8',
                    FALLBACK_FAVICON_SVG
                );
            },

            // Core DEADBOLT Governance APIs
            'GET /api/status': async () => {
                const orch = await getOrchestrator();
                return orch.getStatus();
            },

            'POST /api/run': async (ctx) => {
                const orch = await getOrchestrator();
                const workOrderId = String(ctx.body?.workOrderId || 'WO-101').trim();
                telemetryDb.run('INSERT INTO events (label) VALUES (?)', [
                    `run:${workOrderId.slice(0, 64)}`
                ]);
                const result = await orch.runHeadToHead({
                    workOrderId,
                    beatDelayMs: 0
                });
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            'POST /api/run/stream': async (ctx) => {
                const orch = await getOrchestrator();
                const workOrderId = String(ctx.body?.workOrderId || 'WO-101').trim();
                const beatDelayMs = Number.isFinite(Number(ctx.body?.beatDelayMs))
                    ? Math.max(0, Math.min(500, Number(ctx.body.beatDelayMs)))
                    : 85;
                telemetryDb.run('INSERT INTO events (label) VALUES (?)', [
                    `stream:${workOrderId.slice(0, 64)}`
                ]);

                const sse = sseResponse(ctx.res, ctx.req, {
                    tool: 'deadbolt.orchestrator.run_stream',
                    heartbeatMs: 15000
                });
                if (sse.isClosed()) return;

                try {
                    const finalEnvelope = await orch.runHeadToHead({
                        workOrderId,
                        beatDelayMs,
                        signal: sse.signal,
                        onStageEvent: (eventName, stageEnvelope) => {
                            if (!sse.isClosed() && !sse.signal.aborted) {
                                sse.send(eventName, stageEnvelope);
                            }
                        }
                    });
                    if (!sse.isClosed() && !sse.signal.aborted) {
                        sse.done(finalEnvelope);
                    }
                } catch (err) {
                    if (!sse.isClosed() && !sse.signal.aborted) {
                        sse.error(err);
                    }
                }
            },

            'POST /api/repo/scan': async (ctx) => {
                const orch = await getOrchestrator();
                const repoUrlOrPath = String(
                    ctx.body?.repoUrlOrPath || ctx.body?.target || 'acme-legacy-billing'
                ).trim();
                const maxFiles = Number.isFinite(Number(ctx.body?.maxFiles))
                    ? Number(ctx.body.maxFiles)
                    : 60;
                const result = await orch.scanRepository({ repoUrlOrPath, maxFiles });
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            'POST /api/repo/modernize': async (ctx) => {
                const orch = await getOrchestrator();
                const repoUrlOrPath = String(
                    ctx.body?.repoUrlOrPath ||
                        ctx.body?.target ||
                        'https://github.com/taniarascia/pdo'
                ).trim();
                const targetFile = String(ctx.body?.targetFile || '').trim();
                const maxFiles = Number.isFinite(Number(ctx.body?.maxFiles))
                    ? Number(ctx.body.maxFiles)
                    : 60;
                telemetryDb.run('INSERT INTO events (label) VALUES (?)', [
                    `modernize:${repoUrlOrPath.slice(0, 64)}`
                ]);
                const result = await orch.modernizeRepository({
                    repoUrlOrPath,
                    targetFile,
                    maxFiles
                });
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            'POST /api/drills/crash-recovery': async (ctx) => {
                const orch = await getOrchestrator();
                telemetryDb.run('INSERT INTO events (label) VALUES (?)', ['drill:crash-recovery']);
                const result = await orch.runCrashDrill();
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            'POST /api/drills/confused-deputy': async (ctx) => {
                const orch = await getOrchestrator();
                telemetryDb.run('INSERT INTO events (label) VALUES (?)', ['drill:confused-deputy']);
                const result = await orch.runDeputyDrill();
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            'POST /api/foreman/speak': async (ctx) => {
                const orch = await getOrchestrator();
                const result = await orch.speakForeman(ctx.body || {});
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            'GET /api/audit': async (ctx) => {
                const orch = await getOrchestrator();
                const limit = Number.isFinite(Number(ctx.query?.limit))
                    ? Number(ctx.query.limit)
                    : 50;
                const result = await orch.getAuditStatus({ limit });
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            'GET /api/sofa/governance': async (ctx) => {
                const orch = await getOrchestrator();
                const forceRefresh =
                    ctx.query?.refresh === '1' || ctx.query?.refresh === 'true';
                const result = await orch.getSofaGovernance({ forceRefresh });
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            'POST /api/sofa/sync-receipt': async (ctx) => {
                const orch = await getOrchestrator();
                const workOrderId = String(ctx.body?.workOrderId || 'WO-101').trim();
                telemetryDb.run('INSERT INTO events (label) VALUES (?)', [
                    `sofa-sync:${workOrderId.slice(0, 48)}`
                ]);
                const result = await orch.syncSofaGovernanceReceipt({ workOrderId });
                if (!result.ok) {
                    ctx.sendJson(resolveErrorHttpStatus(result), result);
                    return;
                }
                return result;
            },

            // Baseline metrics + SSE smoke endpoints
            'GET /api/metrics': () => {
                const row = telemetryDb.query('SELECT COUNT(*) AS count FROM events')[0];
                return okEnvelope('metrics.read', 'Loaded dashboard metrics', {
                    service: config.serviceName,
                    eventCount: row?.count ?? 0
                });
            },

            'POST /api/stream': (ctx) => {
                const prompt = String(ctx.body?.prompt || 'ping').trim().slice(0, 256);
                telemetryDb.run('INSERT INTO events (label) VALUES (?)', [prompt]);
                const sse = sseResponse(ctx.res, ctx.req, { tool: 'stream.complete' });
                if (!sse.signal.aborted) {
                    sse.sendToken(`Processed: ${prompt}`);
                    sse.done(okEnvelope('stream.complete', 'SSE stream finished', { prompt }));
                }
            }
        }
    });

    const close = () => {
        if (ownsOrchestrator && resolvedOrchestrator) {
            try {
                resolvedOrchestrator.close();
            } catch {
                /* ignore orchestrator close error */
            }
        }
        try {
            telemetryDb.close();
        } catch {
            /* ignore telemetry db close error */
        }
    };

    return { server, close, getOrchestrator };
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1]);
if (isMain) {
    const logger = setupLogging(config.serviceName, { logDir: config.logDir });
    const orchestrator = await createDeadboltOrchestrator();
    const { server, close } = buildServer({ orchestrator, logger });
    const bindHost = config.host || '127.0.0.1';
    server.listen(config.port, bindHost, () => {
        logger.info(`${config.serviceName} listening on http://${bindHost}:${config.port}`);
    });
    attachGracefulShutdown(server, [close, () => orchestrator.close()], { logger });
}
