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
hydrateExternalEnvFile(path.join(os.homedir(), '.evolve.env'));

const baseConfig = await loadProjectConfig(projectRoot, {
    port: 4090,
    serviceName: 'deadbolt',
    dbPath: path.join(projectRoot, 'data', 'deadbolt.db'),
    stackDbPath: path.join(projectRoot, 'data', 'krusch-stack.db'),
    auditDbPath: path.join(projectRoot, 'data', 'deadbolt-audit.db'),
    logDir: path.join(projectRoot, 'logs')
});

const configuredHmac = envOr('AUDIT_HMAC_SECRET', baseConfig.auditHmacSecret, '');
const runtimeHmacSecret = configuredHmac || crypto.randomBytes(32).toString('hex');

export const config = Object.freeze({
    projectRoot,
    port: envInt('PORT', baseConfig.port, 4090),
    serviceName: envOr('SERVICE_NAME', baseConfig.serviceName, 'deadbolt'),
    dbPath: path.resolve(projectRoot, envOr('DB_PATH', baseConfig.dbPath, './data/deadbolt.db')),
    stackDbPath: path.resolve(projectRoot, envOr('STACK_DB_PATH', baseConfig.stackDbPath, './data/krusch-stack.db')),
    auditDbPath: path.resolve(projectRoot, envOr('AUDIT_DB_PATH', baseConfig.auditDbPath, './data/deadbolt-audit.db')),
    logDir: path.resolve(projectRoot, envOr('LOG_DIR', baseConfig.logDir, './logs')),
    kruschGitUrl: envOr('KRUSCH_GIT_URL', baseConfig.kruschGitUrl, 'http://127.0.0.1:4890'),
    ollamaUrl: envOr('OLLAMA_URL', baseConfig.ollamaUrl, 'http://127.0.0.1:11434'),
    sofaApiBaseUrl: envOr('SOFA_API_BASE_URL', baseConfig.sofaApiBaseUrl, 'https://api.factory.8090.dev'),
    sofaMcpUrl: envOr('SOFA_MCP_URL', baseConfig.sofaMcpUrl, 'https://api.factory.8090.dev/v2/mcp'),
    sofaProjectId: envOr('SOFA_PROJECT_ID', baseConfig.sofaProjectId, ''),
    sofaApiKey: envOr('SOFA_API_KEY', baseConfig.sofaApiKey, ''),
    sofaAdminApiKey: envOr('SOFA_ADMIN_API_KEY', baseConfig.sofaAdminApiKey, ''),
    vercelAiGatewayApiKey: envOr('AI_GATEWAY_API_KEY', baseConfig.vercelAiGatewayApiKey, ''),
    hydradbApiKey: envOr('HYDRADB_API_KEY', baseConfig.hydradbApiKey, ''),
    hydradbBaseUrl: envOr('HYDRADB_BASE_URL', baseConfig.hydradbBaseUrl, 'https://api.hydradb.com'),
    hydradbDatabase: envOr('HYDRADB_DATABASE', baseConfig.hydradbDatabase, 'deadbolt_factory'),
    hydradbCollection: envOr('HYDRADB_COLLECTION', baseConfig.hydradbCollection, 'work_orders'),
    hydradbGraphUrl: envOr('HYDRADB_GRAPH_URL', baseConfig.hydradbGraphUrl, ''),
    hydradbGraphToken: envOr('HYDRADB_GRAPH_TOKEN', baseConfig.hydradbGraphToken, ''),
    hydradbGraphId: envOr('HYDRADB_GRAPH_ID', baseConfig.hydradbGraphId, 'deadbolt-factory'),
    hydradbCellId: envOr('HYDRADB_CELL_ID', baseConfig.hydradbCellId, 'cell-0'),
    hydradbNamespace: envOr('HYDRADB_NAMESPACE', baseConfig.hydradbNamespace, 'default'),
    hydradbAllowLan: envBool('HYDRADB_ALLOW_LAN', baseConfig.hydradbAllowLan, false),
    composioApiKey: envOr('COMPOSIO_API_KEY', baseConfig.composioApiKey, ''),
    composioBaseUrl: envOr('COMPOSIO_BASE_URL', baseConfig.composioBaseUrl, 'https://backend.composio.dev/api/v3'),
    elevenlabsApiKey: envOr('ELEVENLABS_API_KEY', baseConfig.elevenlabsApiKey, ''),
    elevenlabsVoiceId: envOr('ELEVENLABS_VOICE_ID', baseConfig.elevenlabsVoiceId, 'JBFqnCBsd6RMkjVDRZzb'),
    elevenlabsModelId: envOr('ELEVENLABS_MODEL_ID', baseConfig.elevenlabsModelId, 'eleven_turbo_v2_5'),
    geminiApiKey: envOr('GEMINI_API_KEY', baseConfig.geminiApiKey, ''),
    openRouterApiKey: envOr('OPENROUTER_API_KEY', baseConfig.openRouterApiKey, ''),
    enableLiveReviewers: envBool('ENABLE_LIVE_REVIEWERS', baseConfig.enableLiveReviewers, false),
    auditHmacSecret: runtimeHmacSecret
});
