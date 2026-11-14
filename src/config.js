import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadProjectConfig, envOr, envInt, envBool } from '@krusch/toolkit/config';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function hydrateExternalEnvFile(filePath) {
    if (!fs.existsSync(filePath)) return;
    try {
        const raw = fs.readFileSync(filePath, 'utf8');
        for (const line of raw.split(/\r?\n/)) {
            const trimmed = line.trim().replace(/^export\s+/, '');
            if (!trimmed || trimmed.startsWith('#')) continue;
            const eqIdx = trimmed.indexOf('=');
            if (eqIdx <= 0) continue;
            const key = trimmed.slice(0, eqIdx).trim();
            const val = trimmed.slice(eqIdx + 1).trim().replace(/^['"]|['"]$/g, '');
            if (key && !(key in process.env)) {
                process.env[key] = val;
            }
        }
    } catch {
        /* ignore optional external env file errors */
    }
}

hydrateExternalEnvFile(path.join(projectRoot, '.env'));
if (process.env.DEADBOLT_LOAD_HOME_ENV !== 'false' && process.env.NODE_ENV !== 'test') {
    hydrateExternalEnvFile(path.join(os.homedir(), '.evolve.env'));
}

const PLACEHOLDER_HMAC_SECRETS = new Set([
    'deadbolt-local-dev-hmac-change-in-prod',
    'changeme',
    'replace-me'
]);

const baseConfig = await loadProjectConfig(projectRoot, {
    host: '127.0.0.1',
    port: 4090,
    serviceName: 'deadbolt',
    dbPath: path.join(projectRoot, 'data', 'deadbolt.db'),
    stackDbPath: path.join(projectRoot, 'data', 'krusch-stack.db'),
    auditDbPath: path.join(projectRoot, 'data', 'deadbolt-audit.db'),
    logDir: path.join(projectRoot, 'logs')
});

const resolvedAuditDbPath = path.resolve(
    projectRoot,
    envOr('AUDIT_DB_PATH', baseConfig.auditDbPath, './data/deadbolt-audit.db')
);

function resolvePersistentAuditHmacSecret(auditDbPath, explicitSecret) {
    const cleanExplicit = String(explicitSecret || '').trim();
    if (cleanExplicit && !PLACEHOLDER_HMAC_SECRETS.has(cleanExplicit)) {
        return cleanExplicit;
    }
    if (!auditDbPath || auditDbPath === ':memory:') {
        return crypto.randomBytes(32).toString('hex');
    }
    const keyFilePath = `${path.resolve(auditDbPath)}.hmac`;
    try {
        if (fs.existsSync(keyFilePath)) {
            const existing = fs.readFileSync(keyFilePath, 'utf8').trim();
            if (existing.length >= 32) return existing;
        }
        fs.mkdirSync(path.dirname(keyFilePath), { recursive: true });
        const generated = crypto.randomBytes(32).toString('hex');
        fs.writeFileSync(keyFilePath, `${generated}\n`, { mode: 0o600 });
        return generated;
    } catch {
        return crypto.randomBytes(32).toString('hex');
    }
}

const configuredHmac = envOr('AUDIT_HMAC_SECRET', baseConfig.auditHmacSecret, '');
const runtimeHmacSecret = resolvePersistentAuditHmacSecret(resolvedAuditDbPath, configuredHmac);
const resolvedGeminiApiKey = envOr('GEMINI_API_KEY', baseConfig.geminiApiKey, '');
const resolvedOpenRouterApiKey = envOr('OPENROUTER_API_KEY', baseConfig.openRouterApiKey, '');
const defaultEnableLiveReviewers = Boolean(resolvedOpenRouterApiKey || resolvedGeminiApiKey);

export const config = Object.freeze({
    projectRoot,
    host: envOr('HOST', baseConfig.host, '127.0.0.1'),
    port: envInt('PORT', baseConfig.port, 4090),
    serviceName: envOr('SERVICE_NAME', baseConfig.serviceName, 'deadbolt'),
    dbPath: path.resolve(projectRoot, envOr('DB_PATH', baseConfig.dbPath, './data/deadbolt.db')),
    stackDbPath: path.resolve(projectRoot, envOr('STACK_DB_PATH', baseConfig.stackDbPath, './data/krusch-stack.db')),
    auditDbPath: resolvedAuditDbPath,
    logDir: path.resolve(projectRoot, envOr('LOG_DIR', baseConfig.logDir, './logs')),
    kruschGitUrl: envOr('KRUSCH_GIT_URL', baseConfig.kruschGitUrl, 'http://127.0.0.1:4890'),
    ollamaUrl: envOr('OLLAMA_URL', baseConfig.ollamaUrl, 'http://127.0.0.1:11434'),
    ollamaFastModel: envOr('OLLAMA_FAST_MODEL', baseConfig.ollamaFastModel, 'qwen2.5-coder:7b'),
    frontierBenchmarkModel: envOr(
        'FRONTIER_BENCHMARK_MODEL',
        baseConfig.frontierBenchmarkModel,
        'anthropic/claude-sonnet-5.5'
    ),
    preferCloudFastTier: envBool(
        'PREFER_CLOUD_FAST_TIER',
        baseConfig.preferCloudFastTier,
        false
    ),
    sofaApiBaseUrl: envOr('SOFA_API_BASE_URL', baseConfig.sofaApiBaseUrl, 'https://api.factory.8090.dev'),
    sofaMcpUrl: envOr('SOFA_MCP_URL', baseConfig.sofaMcpUrl, 'https://api.factory.8090.dev/v2/mcp'),
    sofaProjectId: envOr('SOFA_PROJECT_ID', baseConfig.sofaProjectId, ''),
    sofaApiKey: envOr('SOFA_API_KEY', baseConfig.sofaApiKey, ''),
    sofaAdminApiKey: envOr('SOFA_ADMIN_API_KEY', baseConfig.sofaAdminApiKey, ''),
    sofaReportingApiKey: envOr('SOFA_REPORTING_API_KEY', baseConfig.sofaReportingApiKey, ''),
    hydradbApiKey: envOr('HYDRADB_API_KEY', baseConfig.hydradbApiKey, ''),
    hydradbBaseUrl: envOr('HYDRADB_BASE_URL', baseConfig.hydradbBaseUrl, 'https://api.hydradb.com'),
    hydradbDatabase: envOr('HYDRADB_DATABASE', baseConfig.hydradbDatabase, 'default-tenant'),
    hydradbCollection: envOr('HYDRADB_COLLECTION', baseConfig.hydradbCollection, 'work_orders'),
    hydradbGraphUrl: envOr('HYDRADB_GRAPH_URL', baseConfig.hydradbGraphUrl, ''),
    hydradbGraphToken: envOr('HYDRADB_GRAPH_TOKEN', baseConfig.hydradbGraphToken, ''),
    hydradbGraphId: envOr('HYDRADB_GRAPH_ID', baseConfig.hydradbGraphId, 'deadbolt-factory'),
    hydradbCellId: envOr('HYDRADB_CELL_ID', baseConfig.hydradbCellId, 'cell-0'),
    hydradbNamespace: envOr('HYDRADB_NAMESPACE', baseConfig.hydradbNamespace, 'default'),
    hydradbAllowLan: envBool('HYDRADB_ALLOW_LAN', baseConfig.hydradbAllowLan, false),
    composioApiKey: envOr('COMPOSIO_API_KEY', baseConfig.composioApiKey, ''),
    composioBaseUrl: envOr('COMPOSIO_BASE_URL', baseConfig.composioBaseUrl, 'https://backend.composio.dev/api/v3'),
    composioMcpUrl: envOr('COMPOSIO_MCP_URL', baseConfig.composioMcpUrl, 'https://connect.composio.dev/mcp'),
    elevenlabsApiKey: envOr('ELEVENLABS_API_KEY', baseConfig.elevenlabsApiKey, ''),
    elevenlabsVoiceId: envOr('ELEVENLABS_VOICE_ID', baseConfig.elevenlabsVoiceId, 'JBFqnCBsd6RMkjVDRZzb'),
    elevenlabsModelId: envOr('ELEVENLABS_MODEL_ID', baseConfig.elevenlabsModelId, 'eleven_turbo_v2_5'),
    geminiApiKey: resolvedGeminiApiKey,
    openRouterApiKey: resolvedOpenRouterApiKey,
    enableLiveReviewers: envBool(
        'ENABLE_LIVE_REVIEWERS',
        baseConfig.enableLiveReviewers,
        defaultEnableLiveReviewers
    ),
    auditHmacSecret: runtimeHmacSecret
});
