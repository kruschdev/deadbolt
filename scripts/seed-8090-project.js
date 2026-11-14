#!/usr/bin/env node
/**
 * @module seed-8090-project
 * @description Idempotently seeds an 8090 Software Factory project over `/v2/external-api`
 * and `/v2/reporting-api/feedback` (via DNS-pinned `safeFetch`) with DEADBOLT's:
 * 1. Feature Requirements Document (`REQ-FIN-001..003` + binary `AC-FIN-*` criteria)
 * 2. Component Blueprint (`DEADBOLT 4-Stage Factory Governance Engine` + Mermaid diagram + ADR-001)
 * 3. Project Skill (`DEADBOLT Stage 4 Governance & SOX-Style Reconciliation`)
 * 4. Three parallel-disjoint Work Orders (`[WO-101]`, `[WO-102]`, `[WO-103]`) linked to Requirements & Blueprints
 * 5. Initial Stage 4 Validator Feedback signal (`FB-*`) linked to `[WO-101]`
 */

import { okEnvelope, errorEnvelope } from '@krusch/toolkit/http';
import { safeFetch } from '@krusch/toolkit/security';
import { config } from '../src/config.js';
import {
    readJsonWithTimeout,
    readTextWithTimeout,
    scrubPrivateNetworkStrings
} from '../src/connectors/hydradb-graph.js';

const FEATURE_REQUIREMENTS_TITLE = 'Billing Settlement Governance & SOX-Style Reconciliation';
const COMPONENT_BLUEPRINT_TITLE = 'DEADBOLT 4-Stage Factory Governance Engine';
const PROJECT_SKILL_TITLE = 'DEADBOLT Stage 4 Governance & SOX-Style Reconciliation';

const FEATURE_REQUIREMENTS_MARKDOWN = `## Overview

Autonomous coding agents frequently pass single-invoice unit tests while introducing sub-cent rounding drift across multi-line settlement batches or weakening downstream reconciliation assertions to force green checks. Billing Settlement Governance enforces zero-cent batch reconciliation, protects verification files from supervised agent tampering, and requires cryptographic audit receipts before any pull request is promoted.

Finance and platform engineering teams use this capability to turn untrusted agent patches into deterministic, auditable Work Order promotions without manual line-by-line forensic review.

## Terminology

- **Batch Settlement Ledger**: The end-of-day aggregation module that verifies the sum of allocated integer line fees plus net merchant payouts equals gross invoice cents with zero residual variance.
- **Largest-Remainder Fee Engine**: The integer basis-point fee allocator in \`src/fee-engine.js\` that distributes sub-cent fractional remainders deterministically across batch line items.
- **Policy Floor**: An import-frozen governance gate that rejects any candidate patch touching protected verification or audit modules before tests execute.
- **Stage 4 Audit Receipt**: A tamper-evident SHA-256 hash-chained ledger entry recording deterministic gate verdicts and measured cost per verified task.

## Requirements

### REQ-FIN-001: Zero-Cent Batch Settlement Reconciliation

**User Story:** As a finance platform engineer, I want every fee allocation change verified against multi-line batch settlement totals, so that sub-cent rounding drift never reaches production ledgers.

**Acceptance Criteria:**
- AC-FIN-001.1: Given a 3-line batch of \`[3334, 3333, 3333]\` cents (\`10000\` cents gross) at \`250\` bps, the allocated line fees sum to \`250\` cents and net merchant settlement equals \`9750\` cents (\`0\` cent delta).
- AC-FIN-001.2: When a candidate patch produces a \`+1\` cent or \`-1\` cent batch settlement discrepancy, Stage 4 rejects the candidate with verdict \`GATE_REJECTED\` even if single-invoice unit tests pass.
- AC-FIN-001.3: When a candidate run fails verification, \`costPerVerifiedTaskUsd\` is reported as \`null\` rather than charging unverified compute as a completed task.

### REQ-FIN-002: Protected Reconciler Policy Floor

**User Story:** As a security lead, I want verification modules locked against autonomous agent edits, so that a supervised agent cannot silence failing batch assertions by loosening tolerances.

**Acceptance Criteria:**
- AC-FIN-002.1: When a candidate patch modifies \`src/sox-reconciler.js\` or weakens reconciliation flags, the Policy Floor blocks promotion immediately with verdict \`WORKAROUND_REJECTED\`.
- AC-FIN-002.2: Every \`WORKAROUND_REJECTED\` event records an immutable SHA-256 audit chain entry and emits a deterministic Foreman alert.

### REQ-FIN-003: Disjoint Parallel Work Order Execution & Confused-Deputy Guard

**User Story:** As an engineering lead, I want non-overlapping billing fixes leased in parallel and outbound pull requests gated by verification receipts, so that throughput scales safely without prompt-injection or SSRF exposure.

**Acceptance Criteria:**
- AC-FIN-003.1: Stage 2 Planner computes 2-hop AST dependency cones and issues parallel execution leases across \`WO-101\`, \`WO-102\`, and \`WO-103\` when their cones do not intersect.
- AC-FIN-003.2: Outbound pull request dispatch blocks any unverified candidate, neutralizes untrusted delimiter breakout directives, and blocks private or cloud-metadata SSRF targets.
`;

const COMPONENT_BLUEPRINT_MARKDOWN = `## Overview

DEADBOLT provides a 4-stage deterministic governance pipeline (Refinery, Planner, Foundry, Validator) in front of autonomous coding agents operating on 8090 Software Factory Work Orders.

## Architecture Diagram

\`\`\`mermaid
flowchart LR
    SOFA["8090 Software Factory (Requirements, Blueprints, WO-101..103)"] --> REF["Stage 1: Refinery (<4,000 tok + INV-12 SHA-256 Span Locks)"]
    REF --> PLN["Stage 2: Planner (2-Hop AST Graph + HydraDB v0.4.0 OpenCypher)"]
    PLN --> FND["Stage 3: Foundry (<1ms Slop Breaker + Isolated Journaled Staging)"]
    FND --> VAL["Stage 4: Validator (Policy Floor + SOX-Style Batch Reconciler)"]
    VAL -->|WORKAROUND_REJECTED| FB["8090 Feedback Inbox & Foreman Alert"]
    VAL -->|VERIFIED + SHA-256 Receipt| CMP["Composio Connect MCP PR Gate"]
\`\`\`

## System Contracts

### Key Contracts
- **Bounded Context Hydration (\`INV-DB-01\`)**: Stage 1 Refinery packs 6 organizational modalities under a strict \`4,000\`-token ceiling and verifies \`INV-12\` SHA-256 source span hashes before planning.
- **Zero Boilerplate Slop (\`INV-DB-02\`)**: Stage 3 Foundry rejects hand-rolled infrastructure plumbing in \`< 1 ms\` and stages edits inside isolated \`os.tmpdir()\` journals with crash-safe rollback.
- **Fixed Validator Order (\`INV-DB-04\`)**: Stage 4 executes deterministic Policy Floor and SOX-style batch reconciliation checks before cross-family model review and cryptographic SHA-256 ledger sealing.

### Integration Contracts
- **8090 Software Factory v2 APIs**: Reads Organization spend governance via \`/v2/organization-api/spend-status\`, syncs Work Orders via \`/v2/external-api/work_orders\`, and reports governance blocks via \`/v2/reporting-api/feedback\`.
- **HydraDB \`v0.4.0\` OpenCypher**: Persists Work Order lineage (\`SUPERSEDES\`) and 2-hop \`DEPENDED_ON_BY\` edges via \`POST /v1/graphs/{graph_id}/query\`.
- **Composio Connect MCP**: Authenticates over \`x-consumer-api-key\` only after Layer 1-3 Confused-Deputy verification succeeds.

## Architecture Decision Records

### ADR-001: Import-Frozen Policy Floor Over Same-Family Model Self-Review

**Context**: Single-model coding agents routinely approve their own off-by-one rounding bugs and attempt to silence batch reconciliation failures by editing test or reconciler tolerances.

**Decision**: Enforce an import-frozen deterministic Policy Floor (\`src/sox-reconciler.js\` immutable) and integer largest-remainder batch reconciliation prior to cross-family reviewer arbitration.

**Consequences**: Sneaky agent workarounds are caught deterministically in sub-millisecond time with zero LLM token burn, and only mathematically reconciled diffs advance to pull request dispatch.
`;

const PROJECT_SKILL_MARKDOWN = `---

description: Enforce DEADBOLT 4-stage deterministic governance, 2-hop AST blast-radius checks, and SOX-style batch reconciliation on Work Orders before pull request promotion.

---

# DEADBOLT Stage 4 Governance Skill

Use this skill whenever implementing or reviewing financial, security, or pagination Work Orders in this project.

## Mandatory 4-Stage Workflow

1. **Hydrate Bounded Context (\`deadbolt_hydrate_work_order\`, \`Allow\`)**: Retrieve the \`<= 4,000\`-token 6-modality context bundle and verify \`INV-12\` SHA-256 span locks are \`VALID\`.
2. **Map 2-Hop Blast Radius (\`deadbolt_map_blast_radius\`, \`Allow\`)**: Inspect the 2-hop AST dependency cone (\`src/fee-engine.js -> src/settlement-service.js -> src/sox-reconciler.js\`) and confirm parallel lease disjointness before editing files.
3. **Validate Candidate Patch (\`deadbolt_validate_reconciliation\`, \`Allow\`)**: Run the \`< 1 ms\` Slop Breaker, import-frozen Policy Floor check, and \`INV-FIN-03\` SOX-style batch reconciliation oracle (\`[3334, 3333, 3333] @ 250 bps => 9750\` net cents, \`0\` cent delta). Never modify protected reconciler files (\`src/sox-reconciler.js\`).
4. **Verify Audit Chain & Promote (\`deadbolt_verify_audit_chain\` \`Allow\`, then \`deadbolt_apply_verified_stage\` \`Confirm\`)**: Confirm the SHA-256 hash chain is intact and request human confirmation before promoting the staged diff and dispatching the \`[WO-*]\`-linked pull request receipt.
`;

const WORK_ORDER_SPECS = Object.freeze([
    {
        code: 'WO-101',
        title: '[WO-101] Fix integer basis-point residual allocation in src/fee-engine.js',
        priority: 'urgent',
        type: 'fix',
        status: 'in_review',
        markdown: `### **Summary**

Replace naive per-line floating-point rounding in \`src/fee-engine.js\` with largest-remainder integer basis-point allocation so multi-line settlement batches reconcile to zero residual cents. Enables verified promotion of \`WO-101\` without tripping \`INV-FIN-03\`.

### **In Scope**

- Integer basis-point fee calculation and largest-remainder residual distribution across batch items in \`src/fee-engine.js\`.
- Preserving downstream compatibility with \`src/settlement-service.js\` and read-only verification under \`src/sox-reconciler.js\`.

### **Out of Scope**

- Any modification to \`src/sox-reconciler.js\` or weakening of batch tolerance thresholds (blocked by Policy Floor).
- Webhook HMAC verification (\`WO-102\`) and invoice pagination cursors (\`WO-103\`).

## Requirements

### REQ-FIN-001: Zero-Cent Batch Settlement Reconciliation

**User Story:** As a finance platform engineer, I want every fee allocation change verified against multi-line batch settlement totals, so that sub-cent rounding drift never reaches production ledgers.

**Acceptance Criteria:**
- AC-FIN-001.1: Given a 3-line batch of \`[3334, 3333, 3333]\` cents (\`10000\` cents gross) at \`250\` bps, the allocated line fees sum to \`250\` cents and net merchant settlement equals \`9750\` cents (\`0\` cent delta).
- AC-FIN-001.2: When a candidate patch produces a \`+1\` cent or \`-1\` cent batch settlement discrepancy, Stage 4 rejects the candidate with verdict \`GATE_REJECTED\` even if single-invoice unit tests pass.

### REQ-FIN-002: Protected Reconciler Policy Floor

**User Story:** As a security lead, I want verification modules locked against autonomous agent edits, so that a supervised agent cannot silence failing batch assertions by loosening tolerances.

**Acceptance Criteria:**
- AC-FIN-002.1: When a candidate patch modifies \`src/sox-reconciler.js\` or weakens reconciliation flags, the Policy Floor blocks promotion immediately with verdict \`WORKAROUND_REJECTED\`.

## Blueprints

- DEADBOLT 4-Stage Factory Governance Engine - 2-hop AST blast-radius cone, Policy Floor enforcement, and Stage 4 SOX-style batch reconciliation.`
    },
    {
        code: 'WO-102',
        title: '[WO-102] Replace timing-vulnerable webhook HMAC comparison in src/webhook-handler.js',
        priority: 'high',
        type: 'fix',
        status: 'ready',
        markdown: `### **Summary**

Replace direct string equality on webhook HMAC digests in \`src/webhook-handler.js\` with constant-time signature verification and replay-window validation. Eliminates timing side-channel exposure in an AST cone disjoint from \`WO-101\` and \`WO-103\`.

### **In Scope**

- Constant-time HMAC-SHA256 signature verification and timestamp replay bounds in \`src/webhook-handler.js\`.
- Zero-boilerplate Sealed Brick compliance verified by Stage 3 Foundry Slop Breaker.

### **Out of Scope**

- Fee allocation math in \`src/fee-engine.js\` (\`WO-101\`).
- Invoice list cursor encoding in \`src/invoice-list.js\` (\`WO-103\`).

## Requirements

### REQ-FIN-003: Disjoint Parallel Work Order Execution & Confused-Deputy Guard

**User Story:** As an engineering lead, I want non-overlapping billing fixes leased in parallel and outbound pull requests gated by verification receipts, so that throughput scales safely without prompt-injection or SSRF exposure.

**Acceptance Criteria:**
- AC-FIN-003.1: Stage 2 Planner computes 2-hop AST dependency cones and issues parallel execution leases across \`WO-101\`, \`WO-102\`, and \`WO-103\` when their cones do not intersect.

## Blueprints

- DEADBOLT 4-Stage Factory Governance Engine - Disjoint AST lease verification and Stage 3 Sealed Brick Slop Breaker.`
    },
    {
        code: 'WO-103',
        title: '[WO-103] Enforce HMAC-signed keyset pagination cursors in src/invoice-list.js',
        priority: 'medium',
        type: 'build',
        status: 'ready',
        markdown: `### **Summary**

Replace unsigned base64 offset pagination in \`src/invoice-list.js\` with clamped, HMAC-signed keyset cursors. Prevents cursor tampering and unbounded query scans while executing safely in parallel with \`WO-101\` and \`WO-102\`.

### **In Scope**

- Clamped page limits and HMAC-signed keyset cursor encoding/decoding in \`src/invoice-list.js\`.
- Stage 3 Slop Breaker verification confirming zero unsigned cursor anti-patterns.

### **Out of Scope**

- Batch fee settlement logic (\`WO-101\`) and webhook signature handlers (\`WO-102\`).

## Requirements

### REQ-FIN-003: Disjoint Parallel Work Order Execution & Confused-Deputy Guard

**User Story:** As an engineering lead, I want non-overlapping billing fixes leased in parallel and outbound pull requests gated by verification receipts, so that throughput scales safely without prompt-injection or SSRF exposure.

**Acceptance Criteria:**
- AC-FIN-003.1: Stage 2 Planner computes 2-hop AST dependency cones and issues parallel execution leases across \`WO-101\`, \`WO-102\`, and \`WO-103\` when their cones do not intersect.

## Blueprints

- DEADBOLT 4-Stage Factory Governance Engine - Parallel Work Order lease cone and Stage 3 Foundry verification.`
    }
]);

async function callSofaJson(
    baseUrl,
    apiHost,
    pathname,
    { method = 'GET', headers = {}, body = undefined, allowStatuses = [] } = {}
) {
    const reqHeaders = {
        Accept: 'application/json',
        ...headers,
        ...(body !== undefined ? { 'Content-Type': 'application/json' } : {})
    };
    const res = await safeFetch(
        `${baseUrl}${pathname}`,
        {
            method,
            headers: reqHeaders,
            ...(body !== undefined ? { body: JSON.stringify(body) } : {})
        },
        {
            allowedProtocols: ['https:'],
            allowedHosts: [apiHost],
            allowPrivateLan: false,
            allowTailscale: false,
            maxRedirects: 0,
            timeoutMs: 10000,
            tool: 'deadbolt.scripts.seed_8090'
        }
    );
    if (!res.ok) {
        throw new Error(
            scrubPrivateNetworkStrings(
                `${method} ${pathname} blocked: ${res.error?.message || res.error?.code}`
            )
        );
    }

    const httpRes = res.data.response;
    const status = res.data.status;
    const contentType = String(httpRes.headers?.get?.('content-type') || '').toLowerCase();
    let json = null;
    let rawText = '';

    if (contentType.includes('application/json')) {
        try {
            json = await readJsonWithTimeout(httpRes, 5000);
        } catch (err) {
            if (err?.code === 'BODY_READ_TIMEOUT') {
                throw new Error(
                    scrubPrivateNetworkStrings(
                        `${method} ${pathname} timed out reading JSON body.`
                    )
                );
            }
            json = null;
        }
    } else {
        rawText = await readTextWithTimeout(httpRes, 5000);
        try {
            json = rawText ? JSON.parse(rawText) : null;
        } catch {
            json = rawText ? { raw: rawText } : null;
        }
    }

    const httpOk = Boolean(httpRes.ok && status >= 200 && status < 300);
    if (!httpOk && !allowStatuses.includes(status)) {
        const errDetail =
            typeof json?.detail === 'string'
                ? json.detail
                : typeof json?.error === 'string'
                  ? json.error
                  : json?.error?.message ||
                    json?.message ||
                    (rawText ? rawText.slice(0, 240) : `HTTP ${status}`);
        throw new Error(
            scrubPrivateNetworkStrings(
                `${method} ${pathname} failed with HTTP ${status}: ${errDetail}`
            )
        );
    }

    return { status, json };
}

export async function seedLive8090Project({
    apiBaseUrl = config.sofaApiBaseUrl || 'https://api.factory.8090.dev',
    externalApiKey = config.sofaApiKey || '',
    reportingApiKey = config.sofaReportingApiKey || ''
} = {}) {
    const cleanExtKey = String(externalApiKey || '').trim();
    if (!cleanExtKey.startsWith('sofa-ext-')) {
        return errorEnvelope(
            'SOFA_EXT_KEY_MISSING',
            'SOFA_API_KEY (sofa-ext-*) is required to seed an 8090 Software Factory project.',
            null,
            'deadbolt.scripts.seed_8090'
        );
    }

    const baseUrl = String(apiBaseUrl).trim().replace(/\/+$/, '');
    const apiHost = new URL(baseUrl).hostname;
    const extHeaders = { Authorization: `Bearer ${cleanExtKey}` };

    // 1. Idempotently ensure Feature Requirements Document
    const reqList = await callSofaJson(baseUrl, apiHost, '/v2/external-api/requirements?page=1&page_size=50', {
        headers: extHeaders
    });
    const existingReq = (reqList.json?.items || []).find(
        (item) => item.title === FEATURE_REQUIREMENTS_TITLE
    );
    let requirementId = existingReq?.id || existingReq?.document_id || null;
    let requirementCreated = false;

    if (!requirementId) {
        const createdReq = await callSofaJson(baseUrl, apiHost, '/v2/external-api/requirements', {
            method: 'POST',
            headers: extHeaders,
            body: {
                title: FEATURE_REQUIREMENTS_TITLE,
                document_type: 'FEATURE',
                markdown_content: FEATURE_REQUIREMENTS_MARKDOWN
            }
        });
        requirementId =
            createdReq.json?.data?.id ||
            createdReq.json?.data?.document_id ||
            createdReq.json?.id ||
            null;
        requirementCreated = createdReq.status >= 200 && createdReq.status < 300;
    }

    // 2. Idempotently ensure Component Blueprint
    const bpList = await callSofaJson(baseUrl, apiHost, '/v2/external-api/blueprints?page=1&page_size=50', {
        headers: extHeaders
    });
    const existingBp = (bpList.json?.items || []).find(
        (item) => item.title === COMPONENT_BLUEPRINT_TITLE
    );
    let blueprintId = existingBp?.id || existingBp?.document_id || null;
    let blueprintCreated = false;

    if (!blueprintId) {
        const createdBp = await callSofaJson(baseUrl, apiHost, '/v2/external-api/blueprints', {
            method: 'POST',
            headers: extHeaders,
            body: {
                title: COMPONENT_BLUEPRINT_TITLE,
                category_name: 'Components',
                markdown_content: COMPONENT_BLUEPRINT_MARKDOWN
            }
        });
        blueprintId =
            createdBp.json?.data?.id ||
            createdBp.json?.data?.document_id ||
            createdBp.json?.id ||
            null;
        blueprintCreated = createdBp.status >= 200 && createdBp.status < 300;
    }

    // 3. Idempotently ensure DEADBOLT Governance Skill
    const skillList = await callSofaJson(
        baseUrl,
        apiHost,
        '/v2/external-api/skills?category=work_orders&page=1&page_size=50',
        { headers: extHeaders }
    );
    const existingSkill = (skillList.json?.items || []).find(
        (item) => item.title === PROJECT_SKILL_TITLE
    );
    let skillIdentifier = existingSkill?.identifier || null;
    let skillCreated = false;

    if (!skillIdentifier) {
        const createdSkill = await callSofaJson(baseUrl, apiHost, '/v2/external-api/skills', {
            method: 'POST',
            headers: extHeaders,
            body: {
                title: PROJECT_SKILL_TITLE,
                category: 'work_orders',
                markdown_content: PROJECT_SKILL_MARKDOWN
            }
        });
        skillIdentifier =
            createdSkill.json?.data?.identifier || createdSkill.json?.identifier || null;
        skillCreated = createdSkill.status >= 200 && createdSkill.status < 300;
    }

    // 4. Idempotently ensure [WO-101], [WO-102], [WO-103] Work Orders
    const woList = await callSofaJson(baseUrl, apiHost, '/v2/external-api/work_orders?page=1&page_size=50', {
        headers: extHeaders
    });
    const existingWos = woList.json?.items || [];
    const missingSpecs = WORK_ORDER_SPECS.filter(
        (spec) => !existingWos.some((wo) => String(wo.title || '').startsWith(`[${spec.code}]`))
    );

    let batchCreateStatus = null;
    if (missingSpecs.length > 0) {
        const createBatchRes = await callSofaJson(
            baseUrl,
            apiHost,
            '/v2/external-api/work_orders/batch_create',
            {
                method: 'POST',
                headers: extHeaders,
                body: {
                    request_id: `deadbolt-seed-${Date.now()}`,
                    operations: missingSpecs.map((spec) => ({
                        operation_id: `create-${spec.code.toLowerCase()}`,
                        operation_type: 'CreateWorkOrder',
                        patch: {
                            title: spec.title,
                            priority: spec.priority,
                            type: spec.type,
                            status: spec.status,
                            markdown_content: spec.markdown
                        }
                    }))
                }
            }
        );
        batchCreateStatus = {
            httpStatus: createBatchRes.status,
            batchStatus: createBatchRes.json?.status || null,
            detail: createBatchRes.status >= 400 ? createBatchRes.json : null
        };
    }

    // Refresh Work Orders list and attach descriptions + Requirement/Blueprint links + Stage 4 audit comment on WO-101
    const refreshedWoList = await callSofaJson(
        baseUrl,
        apiHost,
        '/v2/external-api/work_orders?page=1&page_size=50',
        { headers: extHeaders }
    );
    const liveWos = refreshedWoList.json?.items || [];
    const seededWorkOrders = [];

    for (const spec of WORK_ORDER_SPECS) {
        const match = liveWos.find((wo) => String(wo.title || '').startsWith(`[${spec.code}]`));
        if (!match) continue;

        if (!match.description_snippet) {
            await callSofaJson(
                baseUrl,
                apiHost,
                `/v2/external-api/work_orders/${match.id}/description`,
                {
                    method: 'PATCH',
                    headers: extHeaders,
                    body: { markdown_content: spec.markdown }
                }
            );
        }

        const linkOps = [];
        if (requirementId) {
            linkOps.push({
                operation_id: `link-req-${spec.code.toLowerCase()}`,
                operation_type: 'LinkRequirements',
                target: { work_order_id: match.id },
                patch: { requirements_document_ids: [requirementId] }
            });
        }
        if (blueprintId) {
            linkOps.push({
                operation_id: `link-bp-${spec.code.toLowerCase()}`,
                operation_type: 'LinkBlueprints',
                target: { work_order_id: match.id },
                patch: { blueprint_ids: [blueprintId] }
            });
        }
        if (linkOps.length > 0) {
            await callSofaJson(baseUrl, apiHost, '/v2/external-api/work_orders/batch_update', {
                method: 'POST',
                headers: extHeaders,
                body: {
                    request_id: `deadbolt-link-${spec.code.toLowerCase()}-${Date.now()}`,
                    operations: linkOps
                }
            });
        }

        if (spec.code === 'WO-101') {
            const commentsRes = await callSofaJson(
                baseUrl,
                apiHost,
                `/v2/external-api/work_orders/${match.id}/comments`,
                { headers: extHeaders }
            );
            const existingComments = commentsRes.json?.items || commentsRes.json?.data || [];
            const alreadyCommented =
                Array.isArray(existingComments) &&
                existingComments.some((c) =>
                    String(c.markdown_content || '').includes('DEADBOLT Stage 4 Governance Receipt')
                );
            if (!alreadyCommented) {
                await callSofaJson(
                    baseUrl,
                    apiHost,
                    `/v2/external-api/work_orders/${match.id}/comments`,
                    {
                        method: 'POST',
                        headers: extHeaders,
                        body: {
                            markdown_content:
                                '### DEADBOLT Stage 4 Governance Receipt\n\n' +
                                '- **Attempt 1 (`naive` rounding)**: `GATE_REJECTED` (`+1c` SOX-style batch settlement discrepancy on `[3334, 3333, 3333] @ 250 bps`).\n' +
                                '- **Attempt 2 (`sneaky` reconciler edit)**: `WORKAROUND_REJECTED` (Policy Floor blocked agent modification to protected `src/sox-reconciler.js`).\n' +
                                '- **Attempt 3 (`largest-remainder` integer fix)**: `VERIFIED` (`9750` expected vs `9750` actual net cents, `0c` delta, `100%` Sealed Brick coverage, SHA-256 audit chain valid).'
                        }
                    }
                );
            }
        }

        seededWorkOrders.push({
            id: match.id,
            code: spec.code,
            workOrderNumber: match.work_order_number,
            title: match.title,
            status: match.status,
            priority: match.priority
        });
    }

    // 5. Idempotently seed 1 Validator Feedback item via sf-rpt-* Reporting API if Inbox is empty, and link to WO-101
    let feedbackSignal = { seeded: false, linkedToWo101: false, totalItems: null };
    const cleanRptKey = String(reportingApiKey || '').trim();
    let fbList = await callSofaJson(
        baseUrl,
        apiHost,
        '/v2/external-api/feedback/items?page=1&page_size=10',
        { headers: extHeaders }
    );
    const existingFbCount = Number(fbList.json?.total ?? (fbList.json?.items || []).length);
    feedbackSignal.totalItems = existingFbCount;

    if (existingFbCount === 0 && cleanRptKey.startsWith('sf-rpt-')) {
        const rptRes = await callSofaJson(baseUrl, apiHost, '/v2/reporting-api/feedback', {
            method: 'POST',
            headers: { 'X-API-Key': cleanRptKey },
            body: {
                end_user_email: 'validator-gate@deadbolt.dev',
                content:
                    'DEADBOLT Stage 4 Policy Floor Alert on [WO-101]: Blocked supervised coding agent Attempt 2 (`WORKAROUND_REJECTED`) when candidate patch attempted to modify protected `src/sox-reconciler.js` to mask a `+1c` SOX-style batch settlement discrepancy (`9751` vs `9750` net cents). Attempt 3 remediated `src/fee-engine.js` via integer largest-remainder basis-point allocation (`0c` delta, `VERIFIED`).'
            }
        });
        feedbackSignal.seeded = rptRes.status >= 200 && rptRes.status < 300;
        feedbackSignal.httpStatus = rptRes.status;
        feedbackSignal.response = rptRes.json;

        fbList = await callSofaJson(
            baseUrl,
            apiHost,
            '/v2/external-api/feedback/items?page=1&page_size=10',
            { headers: extHeaders }
        );
        feedbackSignal.totalItems = Number(fbList.json?.total ?? (fbList.json?.items || []).length);
    }

    const firstFb = (fbList.json?.items || [])[0];
    const wo101Record = seededWorkOrders.find((w) => w.code === 'WO-101');
    if (firstFb?.id && wo101Record?.id) {
        const linkFbRes = await callSofaJson(
            baseUrl,
            apiHost,
            `/v2/external-api/feedback/items/${firstFb.id}/work_orders`,
            {
                method: 'POST',
                headers: extHeaders,
                body: { work_order_id: wo101Record.id },
                allowStatuses: [409]
            }
        );
        feedbackSignal.linkedToWo101 =
            (linkFbRes.status >= 200 && linkFbRes.status < 300) || linkFbRes.status === 409;
        feedbackSignal.displayId = firstFb.display_id || 'FB-1';
    }

    const publicWorkOrders = seededWorkOrders.map(({ id: _omitId, ...rest }) => rest);

    return okEnvelope(
        'deadbolt.scripts.seed_8090',
        `Seeded live 8090 Software Factory project (${publicWorkOrders.length} Work Orders, Requirement, Blueprint, Skill, and Validator Feedback).`,
        scrubPrivateNetworkStrings({
            requirement: { title: FEATURE_REQUIREMENTS_TITLE, created: requirementCreated, present: Boolean(requirementId) },
            blueprint: { title: COMPONENT_BLUEPRINT_TITLE, created: blueprintCreated, present: Boolean(blueprintId) },
            skill: { title: PROJECT_SKILL_TITLE, identifier: skillIdentifier, created: skillCreated },
            batchCreateStatus,
            workOrders: publicWorkOrders,
            feedbackSignal
        })
    );
}

if (import.meta.url === `file://${process.argv[1]}`) {
    try {
        const result = await seedLive8090Project();
        console.log(JSON.stringify(scrubPrivateNetworkStrings(result), null, 2));
        if (!result.ok) {
            process.exitCode = 1;
        }
    } catch (err) {
        console.error(scrubPrivateNetworkStrings(err?.message || String(err)));
        process.exitCode = 1;
    }
}
