/**
 * @module connectors/hydradb-graph
 * @description Native OpenCypher HTTP client for hydra-db/hydradb (v0.4.0, ELv2):
 * - Query endpoint (:8443): GET /healthz and POST /v1/graphs/{graph_id}/query
 * - Headers: Authorization: Bearer <token>, X-Graph-Namespace: default
 * - Decodes typed OpenCypher cells (e.g. {"type":"vertex_id","value":1001} and omitted-value null cells)
 * - Seeds :WorkOrder, :CodeFile DEPENDED_ON_BY, and :Invariant SUPERSEDES via idempotent MERGE
 * - Queries 2-hop blast radius via MATCH [:DEPENDED_ON_BY*1..2] WHERE dst.id <> $start
 */

import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';
import { safeFetch } from '@krusch/toolkit/security';

const SAFE_GRAPH_ID_RE = /^[A-Za-z0-9_.-]{1,128}$/;
const SAFE_NAMESPACE_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const SAFE_CELL_ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;

const TAILSCALE_CGNAT_IPV4_RE =
    /\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b/g;
const RFC1918_10_IPV4_RE = /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
const RFC1918_192_IPV4_RE = /\b192\.168\.\d{1,3}\.\d{1,3}\b/g;
const RFC1918_172_IPV4_RE = /\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/g;
const LINK_LOCAL_IPV4_RE = /\b169\.254\.\d{1,3}\.\d{1,3}\b/g;
const TAILSCALE_IPV6_RE = /(?<![0-9a-fA-F:])\bfd7a:115c:a1e0:(?:[0-9a-fA-F:]*[0-9a-fA-F]\b|:*)/gi;
const BRACKETED_PRIVATE_IPV6_RE = /\[(?:f[cd][0-9a-f]{2}|fe80):[0-9a-f:]+\]/gi;
const RFC4193_ULA_IPV6_RE =
    /(?<![0-9a-fA-F:])\bf[cd][0-9a-f]{2}:[0-9a-f:]{2,}(?=\b|[^0-9a-f:]|$)/gi;
const LINK_LOCAL_IPV6_RE =
    /(?<![0-9a-fA-F:])\bfe80:[0-9a-f:]{2,}(?=\b|[^0-9a-f:]|$)/gi;
const LOOPBACK_INTERNAL_URL_RE =
    /\bhttps?:\/\/(?:[^\s/@]+@)?(?:localhost(?:\.localdomain)?|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|\[::1\])(?::\d{1,5})?(?:\/[^\s"'`):,\]]*)?/gi;
const LOOPBACK_HOST_PORT_RE =
    /(?:(?<=\s|^|["'(])\[::1\]|\b(?:localhost(?:\.localdomain)?|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)):\d{1,5}\b/gi;
const LOOPBACK_IPV4_RE = /\b(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0)\b/g;
const LOOPBACK_HOST_LITERAL_RE =
    /(?:\[::1\]|(?<![0-9a-fA-F:])::1(?![0-9a-fA-F:])|\blocalhost(?:\.localdomain)?\b)/gi;
const LOCAL_FS_PATH_RE =
    /(?<![A-Za-z0-9._-])\/(?:(?:home|Users)\/[A-Za-z0-9._-]+(?:\/[^\s"'`):,\]]+)*|(?:private\/tmp|var\/folders|tmp|mnt)\/[A-Za-z0-9._/-]+|root\/[A-Za-z0-9._/-]*)/g;
const BEARER_TOKEN_RE = /\bBearer\s+[A-Za-z0-9._~+/=-]{12,}/g;
const SECRET_TOKEN_RE =
    /\b(?:sofa-(?:admin|ext)-[A-Za-z0-9_-]+|sf-rpt-[A-Za-z0-9_-]+|ak_[A-Za-z0-9_-]{8,}|ck_[A-Za-z0-9_-]{8,}|hdb_[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|sk_[A-Za-z0-9_-]{16,}|sk-(?:or-v1-)?[A-Za-z0-9_-]{12,}|xi-[A-Za-z0-9_-]{12,}|AIza[0-9A-Za-z_-]{20,})\b/g;
const EMAIL_ADDRESS_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

const REDACTED_PRIVATE_HOST = '[redacted-private-host]';
const REDACTED_PATH = '[REDACTED_PATH]';
const REDACTED_TOKEN = 'Bearer [REDACTED_TOKEN]';
const REDACTED_SECRET = '[REDACTED_SECRET]';
const REDACTED_EMAIL = '[REDACTED_EMAIL]';
const REDACTED_DEPTH = '[REDACTED_DEPTH]';
const REDACTED_CYCLE = '[REDACTED_CYCLE]';
const MAX_SCRUB_DEPTH = 24;

function scrubString(str) {
    return str
        .replace(BEARER_TOKEN_RE, REDACTED_TOKEN)
        .replace(SECRET_TOKEN_RE, REDACTED_SECRET)
        .replace(LOOPBACK_INTERNAL_URL_RE, REDACTED_PRIVATE_HOST)
        .replace(EMAIL_ADDRESS_RE, REDACTED_EMAIL)
        .replace(LOCAL_FS_PATH_RE, REDACTED_PATH)
        .replace(LOOPBACK_HOST_PORT_RE, REDACTED_PRIVATE_HOST)
        .replace(LOOPBACK_IPV4_RE, REDACTED_PRIVATE_HOST)
        .replace(LOOPBACK_HOST_LITERAL_RE, REDACTED_PRIVATE_HOST)
        .replace(LINK_LOCAL_IPV4_RE, REDACTED_PRIVATE_HOST)
        .replace(TAILSCALE_CGNAT_IPV4_RE, REDACTED_PRIVATE_HOST)
        .replace(RFC1918_10_IPV4_RE, REDACTED_PRIVATE_HOST)
        .replace(RFC1918_192_IPV4_RE, REDACTED_PRIVATE_HOST)
        .replace(RFC1918_172_IPV4_RE, REDACTED_PRIVATE_HOST)
        .replace(BRACKETED_PRIVATE_IPV6_RE, REDACTED_PRIVATE_HOST)
        .replace(TAILSCALE_IPV6_RE, REDACTED_PRIVATE_HOST)
        .replace(RFC4193_ULA_IPV6_RE, REDACTED_PRIVATE_HOST)
        .replace(LINK_LOCAL_IPV6_RE, REDACTED_PRIVATE_HOST);
}

function scrubValue(value, depth, ancestors) {
    if (typeof value === 'string') {
        return scrubString(value);
    }
    if (value === null || value === undefined || typeof value !== 'object') {
        return value;
    }
    if (value instanceof Error) {
        return {
            name: scrubString(String(value.name || 'Error')),
            message: scrubString(String(value.message || ''))
        };
    }
    if (value instanceof URL) {
        return scrubString(value.toString());
    }
    if (ancestors.has(value)) {
        return REDACTED_CYCLE;
    }
    if (depth > MAX_SCRUB_DEPTH) {
        return REDACTED_DEPTH;
    }
    if (Array.isArray(value)) {
        ancestors.add(value);
        try {
            return value.map((item) => scrubValue(item, depth + 1, ancestors));
        } finally {
            ancestors.delete(value);
        }
    }
    const proto = Object.getPrototypeOf(value);
    if (proto === null || proto === Object.prototype) {
        ancestors.add(value);
        try {
            const out = {};
            for (const [k, v] of Object.entries(value)) {
                out[k] = scrubValue(v, depth + 1, ancestors);
            }
            return out;
        } finally {
            ancestors.delete(value);
        }
    }
    return value;
}

/**
 * Recursively redact private/loopback/link-local hosts, local paths, secret/Bearer tokens, Error stacks,
 * and email addresses across strings, arrays, and plain objects (up to depth 24) per INV-DB-08.
 *
 * @param {unknown} value
 * @param {number} [depth=0]
 * @returns {unknown}
 */
export function scrubPrivateNetworkStrings(value, depth = 0) {
    const startDepth = Number.isInteger(depth) && depth >= 0 ? depth : 0;
    return scrubValue(value, startDepth, new WeakSet());
}

function resolveResponseTarget(res) {
    if (!res || typeof res !== 'object') {
        return null;
    }
    if (typeof res.text === 'function' || typeof res.json === 'function') {
        return res;
    }
    const nested = res.data?.response ?? res.response ?? null;
    if (nested && (typeof nested.text === 'function' || typeof nested.json === 'function')) {
        return nested;
    }
    return null;
}

/**
 * Read a Response body as UTF-8 text under a strict post-header timeout so stalled TCP streams cannot hang.
 *
 * @param {Response|{data?: {response?: Response}}} res
 * @param {number} [timeoutMs=2500]
 * @returns {Promise<string>}
 */
export async function readTextWithTimeout(res, timeoutMs = 2500) {
    const response = resolveResponseTarget(res);
    if (!response || typeof response.text !== 'function') {
        throw new Error('Invalid response object passed to readTextWithTimeout.');
    }
    const boundedMs =
        Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
            ? Math.trunc(Number(timeoutMs))
            : 2500;
    let timer = null;
    try {
        const timeoutPromise = new Promise((_, reject) => {
            timer = setTimeout(() => {
                const err = new Error(`Response text stream timed out after ${boundedMs}ms.`);
                err.code = 'BODY_READ_TIMEOUT';
                reject(err);
            }, boundedMs);
        });
        return await Promise.race([response.text(), timeoutPromise]);
    } catch (err) {
        response.body?.cancel?.().catch?.(() => {});
        throw err;
    } finally {
        if (timer !== null) {
            clearTimeout(timer);
            timer.unref?.();
        }
    }
}

/**
 * Parse a Response JSON body under a strict post-header timeout so stalled TCP streams cannot hang.
 *
 * @param {Response|{data?: {response?: Response}}} res
 * @param {number} [timeoutMs=2500]
 * @returns {Promise<any>}
 */
export async function readJsonWithTimeout(res, timeoutMs = 2500) {
    const response = resolveResponseTarget(res);
    if (!response) {
        throw new Error('Invalid response object passed to readJsonWithTimeout.');
    }
    if (typeof response.json !== 'function' && typeof response.text === 'function') {
        const rawText = await readTextWithTimeout(response, timeoutMs);
        return rawText ? JSON.parse(rawText) : null;
    }
    if (typeof response.json !== 'function') {
        throw new Error('Invalid response object passed to readJsonWithTimeout.');
    }
    const boundedMs =
        Number.isFinite(Number(timeoutMs)) && Number(timeoutMs) > 0
            ? Math.trunc(Number(timeoutMs))
            : 2500;
    let timer = null;
    try {
        const timeoutPromise = new Promise((_, reject) => {
            timer = setTimeout(() => {
                const err = new Error(`Response JSON stream timed out after ${boundedMs}ms.`);
                err.code = 'BODY_READ_TIMEOUT';
                reject(err);
            }, boundedMs);
        });
        return await Promise.race([response.json(), timeoutPromise]);
    } catch (err) {
        response.body?.cancel?.().catch?.(() => {});
        throw err;
    } finally {
        if (timer !== null) {
            clearTimeout(timer);
            timer.unref?.();
        }
    }
}

/**
 * Decode a single HydraDB v0.4.0 OpenCypher result cell.
 * Handles typed wrappers ({"type":"vertex_id","value":1001}) and null cells that omit `value`.
 *
 * @param {unknown} cell
 * @returns {unknown}
 */
export function decodeHydraCell(cell) {
    if (cell === null || cell === undefined) {
        return null;
    }
    if (Array.isArray(cell)) {
        return cell.map((item) => decodeHydraCell(item));
    }
    if (typeof cell === 'object') {
        if (Object.hasOwn(cell, 'type')) {
            if (cell.type === 'null' || !Object.hasOwn(cell, 'value')) {
                return null;
            }
            const rawVal = cell.value;
            if (Array.isArray(rawVal)) {
                return rawVal.map((item) => decodeHydraCell(item));
            }
            return rawVal ?? null;
        }
        const out = {};
        for (const [k, v] of Object.entries(cell)) {
            out[k] = decodeHydraCell(v);
        }
        return out;
    }
    return cell;
}

/**
 * Normalize a HydraDB OpenCypher response body into positional `rows` and named `records`.
 *
 * @param {unknown} payload
 * @returns {{ columns: string[], rows: unknown[][], records: Record<string, unknown>[], stats: object|null }}
 */
export function decodeHydraQueryResult(payload) {
    if (!payload || typeof payload !== 'object') {
        return { columns: [], rows: [], records: [], stats: null };
    }

    const rawColumns = Array.isArray(payload.columns)
        ? payload.columns.map((col) => String(col))
        : [];
    const rawRows = Array.isArray(payload.rows) ? payload.rows : [];

    const rows = [];
    const records = [];

    for (const rawRow of rawRows) {
        if (Array.isArray(rawRow)) {
            const decodedRow = rawRow.map((cell) => decodeHydraCell(cell));
            rows.push(decodedRow);
            const record = {};
            for (let idx = 0; idx < decodedRow.length; idx += 1) {
                const colName = rawColumns[idx] || `col_${idx}`;
                record[colName] = decodedRow[idx];
            }
            records.push(record);
        } else if (rawRow && typeof rawRow === 'object') {
            const record = {};
            const decodedRow = [];
            const keys = rawColumns.length > 0 ? rawColumns : Object.keys(rawRow);
            for (const key of keys) {
                const val = decodeHydraCell(rawRow[key]);
                record[key] = val;
                decodedRow.push(val);
            }
            rows.push(decodedRow);
            records.push(record);
        }
    }

    const stats =
        payload.stats && typeof payload.stats === 'object' ? payload.stats : null;

    return {
        columns: rawColumns,
        rows,
        records,
        stats
    };
}

/**
 * Derive a deterministic positive integer vertex_id for a file path when beyond the 3 canonical hops.
 *
 * @param {string} filePath
 * @param {number} index
 * @returns {number}
 */
function resolveCodeFileVertexId(filePath, index = 0) {
    const clean = String(filePath || '').trim();
    if (clean === 'src/fee-engine.js') return 1001;
    if (clean === 'src/settlement-service.js') return 1002;
    if (clean === 'src/sox-reconciler.js') return 1003;
    let hash = 2166136261;
    for (let i = 0; i < clean.length; i += 1) {
        hash ^= clean.charCodeAt(i);
        hash = Math.imul(hash, 16777619);
    }
    return 2000 + ((hash >>> 0) % 100000) + index;
}

/**
 * Create a native OpenCypher HTTP client for hydra-db/hydradb v0.4.0 (:8443).
 *
 * @param {object} [options={}]
 * @param {string} [options.baseUrl=''] - HydraDB query endpoint (e.g. https://hydradb.example.com:8443)
 * @param {string} [options.token=''] - Bearer authentication token
 * @param {string} [options.graphId='deadbolt-factory'] - Target graph identifier
 * @param {string} [options.cellId='cell-0'] - Target HydraDB storage cell_id
 * @param {string} [options.namespace='default'] - X-Graph-Namespace header value
 * @param {boolean} [options.allowPrivateLan=false] - Allow RFC1918 LAN endpoints when explicitly opted in
 * @param {boolean} [options.allowTailscale=false] - Allow Tailscale endpoints when explicitly opted in
 * @param {number} [options.timeoutMs=2000] - Per-request timeout in milliseconds
 * @param {Function|null} [options.lookupFn=null] - Optional DNS lookup override for testing
 * @param {typeof fetch} [options.fetchImpl] - Optional fetch implementation override for testing
 */
export function createHydraGraphClient(options = {}) {
    const opts = options && typeof options === 'object' ? options : {};
    const cleanBaseUrl = String(opts.baseUrl || '').trim().replace(/\/+$/, '');
    const cleanToken = String(opts.token || '').trim();
    const rawGraphId = String(opts.graphId || 'deadbolt-factory').trim();
    const cleanGraphId = SAFE_GRAPH_ID_RE.test(rawGraphId) ? rawGraphId : 'deadbolt-factory';
    const rawCellId = String(opts.cellId || 'cell-0').trim();
    const cleanCellId = SAFE_CELL_ID_RE.test(rawCellId) ? rawCellId : 'cell-0';
    const rawNamespace = String(opts.namespace || 'default').trim();
    const cleanNamespace = SAFE_NAMESPACE_RE.test(rawNamespace) ? rawNamespace : 'default';
    const allowPrivateLan = opts.allowPrivateLan === true;
    const allowTailscale = opts.allowTailscale === true;
    const timeoutMs =
        Number.isFinite(Number(opts.timeoutMs)) && Number(opts.timeoutMs) > 0
            ? Math.trunc(Number(opts.timeoutMs))
            : 2000;
    const lookupFn = typeof opts.lookupFn === 'function' ? opts.lookupFn : null;
    const fetchImpl = typeof opts.fetchImpl === 'function' ? opts.fetchImpl : undefined;

    function isConfigured() {
        return cleanBaseUrl.length > 0;
    }

    function buildSafeFetchOptions(toolName) {
        let allowedHosts = null;
        if (cleanBaseUrl) {
            try {
                allowedHosts = [new URL(cleanBaseUrl).hostname];
            } catch {
                allowedHosts = null;
            }
        }
        return {
            allowedProtocols: ['https:', 'http:'],
            ...(allowedHosts ? { allowedHosts } : {}),
            allowPrivateLan,
            allowTailscale,
            maxRedirects: 0,
            timeoutMs,
            ...(lookupFn ? { lookupFn } : {}),
            ...(fetchImpl ? { fetchImpl } : {}),
            tool: toolName
        };
    }

    function buildHeaders({ includeJsonContentType = true } = {}) {
        const headers = {
            Accept: 'application/json',
            'X-Graph-Namespace': cleanNamespace
        };
        if (includeJsonContentType) {
            headers['Content-Type'] = 'application/json';
        }
        if (cleanToken) {
            headers.Authorization = `Bearer ${cleanToken}`;
        }
        return headers;
    }

    /**
     * Probe HydraDB v0.4.0 query server health (`GET /healthz` -> `{"status":"ok"}`).
     */
    async function healthz() {
        if (!isConfigured()) {
            return okEnvelope(
                'deadbolt.hydradb.healthz',
                'HydraDB OpenCypher endpoint not configured; running in local SQLite AST fallback.',
                {
                    configured: false,
                    healthy: false,
                    mode: 'sqlite_ast_fallback'
                }
            );
        }

        const res = await safeFetch(
            `${cleanBaseUrl}/healthz`,
            {
                method: 'GET',
                headers: buildHeaders({ includeJsonContentType: false })
            },
            buildSafeFetchOptions('deadbolt.hydradb.healthz')
        );

        if (!res.ok) {
            return errorEnvelope(
                res.error?.code || 'HYDRADB_HEALTHZ_FAILED',
                scrubPrivateNetworkStrings(
                    res.error?.message || 'HydraDB /healthz request failed.'
                ),
                {
                    graphId: cleanGraphId,
                    reasonCode: res.error?.code || 'HYDRADB_UNREACHABLE'
                },
                'deadbolt.hydradb.healthz'
            );
        }

        let parsed = null;
        try {
            parsed = await readJsonWithTimeout(res.data.response, timeoutMs);
        } catch (bodyErr) {
            if (bodyErr?.code === 'BODY_READ_TIMEOUT') {
                return errorEnvelope(
                    'HYDRADB_BODY_TIMEOUT',
                    scrubPrivateNetworkStrings(bodyErr.message),
                    {
                        graphId: cleanGraphId,
                        reasonCode: 'HYDRADB_BODY_TIMEOUT',
                        status: res.data.status
                    },
                    'deadbolt.hydradb.healthz'
                );
            }
            parsed = null;
        }

        const statusOk = res.data.status >= 200 && res.data.status < 300 && parsed?.status === 'ok';
        if (!statusOk) {
            return errorEnvelope(
                'HYDRADB_UNHEALTHY',
                scrubPrivateNetworkStrings(`HydraDB /healthz returned HTTP ${res.data.status}.`),
                {
                    graphId: cleanGraphId,
                    reasonCode: 'HYDRADB_UNHEALTHY',
                    status: res.data.status,
                    body: scrubPrivateNetworkStrings(parsed)
                },
                'deadbolt.hydradb.healthz'
            );
        }

        return okEnvelope('deadbolt.hydradb.healthz', 'HydraDB v0.4.0 OpenCypher engine healthy.', {
            configured: true,
            healthy: true,
            mode: 'hydradb_opencypher_live',
            graphId: cleanGraphId,
            cellId: cleanCellId,
            namespace: cleanNamespace,
            status: parsed.status
        });
    }

    /**
     * Execute a parameterized OpenCypher query on `POST /v1/graphs/{graph_id}/query`.
     *
     * @param {string} query - OpenCypher statement
     * @param {Record<string, unknown>} [parameters={}] - Bound OpenCypher parameters
     * @param {object} [queryOpts={}]
     * @param {string} [queryOpts.cellId] - Optional cell_id override
     */
    async function queryOpenCypher(query, parameters = {}, queryOpts = {}) {
        const cleanQuery = String(query || '').trim();
        if (!cleanQuery) {
            return errorEnvelope(
                'HYDRADB_EMPTY_QUERY',
                'OpenCypher query string is required.',
                null,
                'deadbolt.hydradb.query'
            );
        }

        if (!isConfigured()) {
            return errorEnvelope(
                'HYDRADB_NOT_CONFIGURED',
                'HYDRADB_GRAPH_URL is not configured.',
                { graphId: cleanGraphId },
                'deadbolt.hydradb.query'
            );
        }

        const effectiveCellId =
            queryOpts?.cellId && SAFE_CELL_ID_RE.test(String(queryOpts.cellId))
                ? String(queryOpts.cellId)
                : cleanCellId;

        const endpoint = `${cleanBaseUrl}/v1/graphs/${encodeURIComponent(cleanGraphId)}/query`;
        const res = await safeFetch(
            endpoint,
            {
                method: 'POST',
                headers: buildHeaders({ includeJsonContentType: true }),
                body: JSON.stringify({
                    cell_id: effectiveCellId,
                    query: cleanQuery,
                    parameters: parameters && typeof parameters === 'object' ? parameters : {}
                })
            },
            buildSafeFetchOptions('deadbolt.hydradb.query')
        );

        if (!res.ok) {
            return errorEnvelope(
                res.error?.code || 'HYDRADB_QUERY_FAILED',
                scrubPrivateNetworkStrings(
                    res.error?.message || 'HydraDB OpenCypher query request failed.'
                ),
                {
                    graphId: cleanGraphId,
                    reasonCode: res.error?.code || 'HYDRADB_UNREACHABLE'
                },
                'deadbolt.hydradb.query'
            );
        }

        let rawJson = null;
        try {
            rawJson = await readJsonWithTimeout(res.data.response, timeoutMs);
        } catch (bodyErr) {
            if (bodyErr?.code === 'BODY_READ_TIMEOUT') {
                return errorEnvelope(
                    'HYDRADB_BODY_TIMEOUT',
                    scrubPrivateNetworkStrings(bodyErr.message),
                    {
                        graphId: cleanGraphId,
                        reasonCode: 'HYDRADB_BODY_TIMEOUT',
                        status: res.data.status
                    },
                    'deadbolt.hydradb.query'
                );
            }
            rawJson = null;
        }

        if (res.data.status < 200 || res.data.status >= 300) {
            const errMsg =
                typeof rawJson?.error === 'string'
                    ? rawJson.error
                    : rawJson?.error?.message ||
                      rawJson?.message ||
                      `HydraDB query returned HTTP ${res.data.status}.`;
            return errorEnvelope(
                'HYDRADB_QUERY_HTTP_ERROR',
                scrubPrivateNetworkStrings(String(errMsg)),
                {
                    graphId: cleanGraphId,
                    reasonCode: rawJson?.error?.code || 'HYDRADB_QUERY_HTTP_ERROR',
                    status: res.data.status,
                    hydraCode: scrubPrivateNetworkStrings(rawJson?.error?.code || null)
                },
                'deadbolt.hydradb.query'
            );
        }

        const decoded = decodeHydraQueryResult(rawJson);
        return okEnvelope(
            'deadbolt.hydradb.query',
            `Executed OpenCypher query on ${cleanGraphId}/${effectiveCellId} (${decoded.records.length} row(s)).`,
            {
                graphId: cleanGraphId,
                cellId: effectiveCellId,
                namespace: cleanNamespace,
                columns: decoded.columns,
                rows: decoded.rows,
                records: decoded.records,
                stats: decoded.stats
            }
        );
    }

    /**
     * Idempotently seed :WorkOrder, :Invariant (SUPERSEDES), and :CodeFile (DEPENDED_ON_BY) vertices/edges.
     */
    async function seedWorkOrderLineageGraph({
        workOrderId = 'WO-101',
        hopFiles = ['src/fee-engine.js', 'src/settlement-service.js', 'src/sox-reconciler.js'],
        supersededCode = 'INV-FIN-02',
        activeCode = 'INV-FIN-03'
    } = {}) {
        const cleanWoId = String(workOrderId || 'WO-101').trim();
        const rawDigits = String(cleanWoId).replace(/\D+/g, '').slice(0, 9);
        const numericWoSuffix = Number(rawDigits) || 101;
        const woVertexId =
            cleanWoId.toUpperCase() === 'WO-101' ? 9001 : 9000 + numericWoSuffix;
        const orderedFiles =
            Array.isArray(hopFiles) && hopFiles.length >= 2
                ? hopFiles.map((f) => String(f).trim()).filter(Boolean)
                : ['src/fee-engine.js', 'src/settlement-service.js', 'src/sox-reconciler.js'];

        const fileVertices = orderedFiles.map((filePath, idx) => ({
            vertexId: resolveCodeFileVertexId(filePath, idx),
            filePath,
            isProtected: filePath.endsWith('sox-reconciler.js') ? true : null
        }));

        if (!isConfigured()) {
            return okEnvelope(
                'deadbolt.hydradb.seed_graph',
                `HydraDB OpenCypher running in deterministic local fallback for ${cleanWoId}.`,
                {
                    mode: 'sqlite_ast_fallback',
                    liveSynced: false,
                    graphId: cleanGraphId,
                    cellId: cleanCellId,
                    workOrderId: cleanWoId,
                    woVertexId,
                    verticesPrepared: fileVertices.length + 3
                }
            );
        }

        const toDegradedLineageFallback = (failedRes) =>
            okEnvelope(
                'deadbolt.hydradb.seed_graph',
                `HydraDB OpenCypher unreachable; degraded cleanly to local lineage fallback for ${cleanWoId}.`,
                {
                    mode: 'sqlite_lineage_fallback',
                    liveSynced: false,
                    fallbackReason: scrubPrivateNetworkStrings(
                        String(failedRes?.error?.code || 'HYDRADB_UNREACHABLE')
                    ),
                    graphId: cleanGraphId,
                    cellId: cleanCellId,
                    workOrderId: cleanWoId,
                    woVertexId,
                    verticesPrepared: fileVertices.length + 3
                }
            );

        // HydraDB v0.4.0 OpenCypher dialect rules (verified live against ghcr.io/hydra-db/hydradb:0.4.0):
        // 1. Single-statement MERGE accepts one-hop directed edge patterns without trailing SET/RETURN clauses.
        // 2. Mutations return { columns: [], rows: [], read_epoch: null }; follow up with MATCH ... RETURN.
        // 3. Trip on the first failed OpenCypher probe so venue Wi-Fi stalls degrade in <= 2s rather than 6x timeouts.
        const supersedesRes = await queryOpenCypher(
            'MERGE (curr:Invariant {id: $currInvId, code: $currCode, status: $currStatus})-[:SUPERSEDES]->(prev:Invariant {id: $prevInvId, code: $prevCode, status: $prevStatus})',
            {
                currInvId: 8003,
                currCode: activeCode,
                currStatus: 'ACTIVE',
                prevInvId: 8002,
                prevCode: supersededCode,
                prevStatus: 'SUPERSEDED'
            }
        );
        if (!supersedesRes.ok) {
            return toDegradedLineageFallback(supersedesRes);
        }

        const governedRes = await queryOpenCypher(
            'MERGE (wo:WorkOrder {id: $woId, code: $woCode})-[:GOVERNED_BY]->(curr:Invariant {id: $currInvId})',
            {
                woId: woVertexId,
                woCode: cleanWoId,
                currInvId: 8003
            }
        );
        if (!governedRes.ok) {
            return toDegradedLineageFallback(governedRes);
        }

        for (let i = 0; i < fileVertices.length - 1; i += 1) {
            const src = fileVertices[i];
            const dst = fileVertices[i + 1];
            const edgeRes = await queryOpenCypher(
                'MERGE (src:CodeFile {id: $srcId, path: $srcPath, protected: $srcProtected})-[:DEPENDED_ON_BY]->(dst:CodeFile {id: $dstId, path: $dstPath, protected: $dstProtected})',
                {
                    srcId: src.vertexId,
                    srcPath: src.filePath,
                    srcProtected: src.isProtected === true,
                    dstId: dst.vertexId,
                    dstPath: dst.filePath,
                    dstProtected: dst.isProtected === true
                }
            );
            if (!edgeRes.ok) {
                return toDegradedLineageFallback(edgeRes);
            }
        }

        const targetEdgeRes = await queryOpenCypher(
            'MERGE (wo:WorkOrder {id: $woId})-[:TARGETS]->(entry:CodeFile {id: $entryId})',
            {
                woId: woVertexId,
                entryId: fileVertices[0].vertexId
            }
        );
        if (!targetEdgeRes.ok) {
            return toDegradedLineageFallback(targetEdgeRes);
        }

        const lineageRes = await queryOpenCypher(
            [
                'MATCH (wo:WorkOrder {id: $woId})-[:GOVERNED_BY]->(curr:Invariant)-[:SUPERSEDES]->(prev:Invariant)',
                'RETURN wo.id AS woVertexId, curr.id AS activeInvVertexId, prev.id AS supersededInvVertexId'
            ].join('\n'),
            { woId: woVertexId }
        );
        if (!lineageRes.ok) {
            return toDegradedLineageFallback(lineageRes);
        }

        return okEnvelope(
            'deadbolt.hydradb.seed_graph',
            `Seeded ${cleanWoId} lineage and ${fileVertices.length - 1} DEPENDED_ON_BY edge(s) into HydraDB OpenCypher (${cleanGraphId}).`,
            {
                mode: 'hydradb_opencypher_live',
                liveSynced: true,
                graphId: cleanGraphId,
                cellId: cleanCellId,
                workOrderId: cleanWoId,
                woVertexId,
                fileVertices,
                lineageRecord: lineageRes.data.records[0] || null
            }
        );
    }

    /**
     * Traverse 1..2 hop downstream dependents in HydraDB OpenCypher using `WHERE dst.id <> $start`.
     */
    async function queryTwoHopBlastRadius({
        entryFile = 'src/fee-engine.js',
        entryVertexId = undefined
    } = {}) {
        const startId =
            Number.isInteger(entryVertexId) && entryVertexId > 0
                ? entryVertexId
                : resolveCodeFileVertexId(entryFile, 0);

        if (!isConfigured()) {
            return okEnvelope(
                'deadbolt.hydradb.blast_radius',
                `HydraDB OpenCypher unconfigured; deferring 2-hop traversal for ${entryFile} to local AST graph.`,
                {
                    mode: 'sqlite_ast_fallback',
                    liveQueried: false,
                    startVertexId: startId,
                    entryFile,
                    dependents: []
                }
            );
        }

        const blastCypher = [
            'MATCH (src:CodeFile {id: $start})-[:DEPENDED_ON_BY*1..2]->(dst:CodeFile)',
            'WHERE dst.id <> $start',
            'RETURN dst.id AS vertexId, dst.path AS filePath, dst.protected AS isProtected'
        ].join('\n');

        const queryRes = await queryOpenCypher(blastCypher, { start: startId });
        if (!queryRes.ok) {
            return queryRes;
        }

        const dependents = queryRes.data.records.map((rec) => ({
            vertexId: rec.vertexId,
            filePath: rec.filePath,
            isProtected: rec.isProtected === true
        }));

        return okEnvelope(
            'deadbolt.hydradb.blast_radius',
            `Queried 2-hop OpenCypher blast radius from ${entryFile} (${dependents.length} dependent node(s)).`,
            {
                mode: 'hydradb_opencypher_live',
                liveQueried: true,
                graphId: cleanGraphId,
                cellId: cleanCellId,
                startVertexId: startId,
                entryFile,
                dependents
            }
        );
    }

    return Object.freeze({
        graphId: cleanGraphId,
        cellId: cleanCellId,
        namespace: cleanNamespace,
        isConfigured,
        healthz,
        queryOpenCypher,
        seedWorkOrderLineageGraph,
        queryTwoHopBlastRadius
    });
}
