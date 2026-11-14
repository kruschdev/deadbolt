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
 * @param {number} [options.timeoutMs=5000] - Per-request timeout in milliseconds
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
            : 5000;
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
                res.error?.message || 'HydraDB /healthz request failed.',
                res.error?.details ?? null,
                'deadbolt.hydradb.healthz'
            );
        }

        let parsed = null;
        try {
            parsed = await res.data.response.json();
        } catch {
            parsed = null;
        }

        const statusOk = res.data.status >= 200 && res.data.status < 300 && parsed?.status === 'ok';
        if (!statusOk) {
            return errorEnvelope(
                'HYDRADB_UNHEALTHY',
                `HydraDB /healthz returned HTTP ${res.data.status}.`,
                { status: res.data.status, body: parsed },
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
                res.error?.message || 'HydraDB OpenCypher query request failed.',
                res.error?.details ?? null,
                'deadbolt.hydradb.query'
            );
        }

        let rawJson = null;
        try {
            rawJson = await res.data.response.json();
        } catch {
            rawJson = null;
        }

        if (res.data.status < 200 || res.data.status >= 300) {
            return errorEnvelope(
                'HYDRADB_QUERY_HTTP_ERROR',
                rawJson?.error || rawJson?.message || `HydraDB query returned HTTP ${res.data.status}.`,
                { status: res.data.status },
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
                    verticesPrepared: fileVertices.length + 3
                }
            );
        }

        const seedLineageCypher = [
            'MERGE (wo:WorkOrder {id: $woId})',
            'SET wo.code = $woCode',
            'MERGE (prev:Invariant {id: $prevInvId})',
            'SET prev.code = $prevCode, prev.status = $prevStatus',
            'MERGE (curr:Invariant {id: $currInvId})',
            'SET curr.code = $currCode, curr.status = $currStatus',
            'MERGE (curr)-[:SUPERSEDES]->(prev)',
            'MERGE (wo)-[:GOVERNED_BY]->(curr)',
            'RETURN wo.id AS woVertexId, curr.id AS activeInvVertexId, prev.id AS supersededInvVertexId'
        ].join('\n');

        const lineageRes = await queryOpenCypher(seedLineageCypher, {
            woId: 9001,
            woCode: cleanWoId,
            prevInvId: 8002,
            prevCode: supersededCode,
            prevStatus: 'SUPERSEDED',
            currInvId: 8003,
            currCode: activeCode,
            currStatus: 'ACTIVE'
        });

        if (!lineageRes.ok) {
            return lineageRes;
        }

        for (let i = 0; i < fileVertices.length; i += 1) {
            const node = fileVertices[i];
            const nodeRes = await queryOpenCypher(
                [
                    'MERGE (f:CodeFile {id: $vertexId})',
                    'SET f.path = $filePath, f.protected = $isProtected',
                    'RETURN f.id AS vertexId, f.path AS filePath, f.protected AS isProtected'
                ].join('\n'),
                {
                    vertexId: node.vertexId,
                    filePath: node.filePath,
                    isProtected: node.isProtected
                }
            );
            if (!nodeRes.ok) {
                return nodeRes;
            }
        }

        for (let i = 0; i < fileVertices.length - 1; i += 1) {
            const src = fileVertices[i];
            const dst = fileVertices[i + 1];
            const edgeRes = await queryOpenCypher(
                [
                    'MATCH (src:CodeFile {id: $srcId}), (dst:CodeFile {id: $dstId})',
                    'MERGE (src)-[:DEPENDED_ON_BY]->(dst)',
                    'RETURN src.id AS srcVertexId, dst.id AS dstVertexId'
                ].join('\n'),
                {
                    srcId: src.vertexId,
                    dstId: dst.vertexId
                }
            );
            if (!edgeRes.ok) {
                return edgeRes;
            }
        }

        await queryOpenCypher(
            [
                'MATCH (wo:WorkOrder {id: $woId}), (entry:CodeFile {id: $entryId})',
                'MERGE (wo)-[:TARGETS]->(entry)',
                'RETURN wo.id AS woVertexId, entry.id AS entryVertexId'
            ].join('\n'),
            {
                woId: 9001,
                entryId: fileVertices[0].vertexId
            }
        );

        return okEnvelope(
            'deadbolt.hydradb.seed_graph',
            `Seeded ${cleanWoId} lineage and ${fileVertices.length - 1} DEPENDED_ON_BY edge(s) into HydraDB OpenCypher (${cleanGraphId}).`,
            {
                mode: 'hydradb_opencypher_live',
                liveSynced: true,
                graphId: cleanGraphId,
                cellId: cleanCellId,
                workOrderId: cleanWoId,
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
