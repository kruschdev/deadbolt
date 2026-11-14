# DEADBOLT Specification (`spec.md`)

**STATUS**: `FROZEN`  
**Version**: `0.1.0`  
**Author**: Kevin Saylor Ruschman (`kruschdev <kruschdev@users.noreply.github.com>`)  
**License**: MIT  

## 1. Purpose & Positioning

DEADBOLT is the deterministic governance control plane, 2-hop blast-radius planner, self-rejecting validator, and live Breaker Panel built for **8090's Software Factory** (`1. Refinery -> 2. Planner -> 3. Foundry -> 4. Validator`).

8090 builds the software; DEADBOLT makes it harder to break. DEADBOLT reduces the risk of unsafe AI-generated changes through deterministic controls, independent cross-family review, and recoverable staged execution.

## 2. Numbered Operational & Architectural Invariants

- **`INV-DB-01` (Deterministic Envelope Contract)**: Every HTTP API handler, engine method, and MCP tool returns `{ ok: boolean, tool: string, summary: string, data?: object, error?: { code, message, details } }` via `okEnvelope` / `errorEnvelope` (`@krusch/toolkit/http`) or `okMcpResult` / `errorMcpResult` (`@krusch/toolkit/mcp`).
- **`INV-DB-02` (Zero Boilerplate Slop / 100% Sealed Golden Bricks)**: Deadbolt source files (`src/**/*.js`, `client/src/**/*.{js,jsx}`) must pass `krusch-lego audit` (`auditBoilerplateText` / `scoreLegoBrickCoverage`) with **0 findings**. Legacy anti-pattern samples used to test the `<1ms` Slop Breaker live exclusively in `src/fixtures/billing-repo-snapshot.json` (JSON data, never raw `.js` source inside `src/`).
- **`INV-DB-03` (Three Distinct Concepts Never Conflated)**:
  1. **Content-integrity fingerprints** (`INV-12` SHA-256 line-span hashes in `krusch-context-mcp` proving code text has not drifted underneath stored memories).
  2. **Architectural & domain invariants** (rules such as `INV-FIN-03` governing settlement batch parity).
  3. **Dependency & call-graph relationships** (`krusch-git` AST symbol + 2-hop file/caller graph + `HydraDB v2` `IMPORTS` edges).
- **`INV-FIN-03` (SOX-Style Batch Reconciliation Demonstration)**: Sum of settled line-item net payouts plus batch processor fee in integer cents must equal gross invoice total in integer cents (`deltaCents === 0`). Per-item `Math.round` without residual carry creates a `+1` cent discrepancy on multi-line split invoices (`expectedNetCents = 10000`, `actualSumCents = 10001`, `deltaCents = +1`).
- **`INV-DB-04` (Fixed Validator Order & Non-Overridable Policy Floor)**: Validation executes in strict order:
  1. Deterministic checks (`<1ms` `scoreLegoBrickCoverage` Slop Breaker + import-frozen `createFrozenPolicyFloor` workaround guard + isolated SOX-style ledger execution).
  2. Separate-family model reviews (`@krusch/toolkit/llm` when configured, deterministic structured audit fallback offline).
  3. Disagreement detection (`consensus` vs `ESCALATE_TO_HUMAN`).
  No model vote can override a failed deterministic gate or authorize mutating a protected verification file (`sox-reconciler.js`).
- **`INV-DB-05` (Self-Rejection of Agent Workarounds)**: When an agent attempts to pass `INV-FIN-03` by weakening `sox-reconciler.js`, widening tolerance (`toleranceCents > 0`), or toggling `strictSox = false`, DEADBOLT deterministically blocks the workaround (`WORKAROUND_REJECTED`), records the violation in the SHA-256 hash-chained audit log (`@krusch/toolkit/audit-log`), and requires a legitimate fix in `fee-engine.js` (largest-remainder / integer cent allocation) that passes revalidation.
- **`INV-DB-06` (Isolated Staging & Crash-Recoverable Apply Journal)**: Proposed edits are staged in an isolated workspace via `krusch-stack` `harness` (`harness_tasks` + `harness_apply_journal`) before touching target files, with deterministic crash simulation and recovery (`recoverInFlight`).
- **`INV-DB-07` (Confused-Deputy & Outbound Action Gate)**: External ticket/chat/PR text is wrapped with `delimitUntrustedContent` (`@krusch/toolkit/harness-engineering`) and scanned with `sanitizeAgentMessage` (`@krusch/toolkit/trajectory-guard`). Composio outbound PR actions are blocked until Stage 4 (`Validator`) returns `VERIFIED` and all outbound URLs pass `safeFetch` / `validateOutboundUrl` (`@krusch/toolkit/security`).
- **`INV-DB-08` (Measured Cost-Per-Verified-Task & Zero Leaks)**: Only live measured token counts, latency, retries, and USD cost are reported (`costPerVerifiedTaskUsd` is `null` for unverified/failed runs). Zero API keys, private IPs, or local workstation paths may appear in tracked files.
- **`INV-SOLO-VOICE-01` (First-Person Voice & No Em Dashes)**: All user-facing copy, README prose, and UI labels use clear technical prose without em dashes (`U+2014`).

## 3. Disjoint Module Ownership & Frozen Export Contracts

### Module A (Agent 1): Fixture Data & Stage 1 Refinery
Files owned exclusively by Agent 1:
- `src/fixtures/billing-repo-snapshot.json`
- `src/fixtures/billing-scenario.js`
- `src/engines/refinery-context.js`

Exports of `src/fixtures/billing-scenario.js`:
- `BILLING_WORK_ORDERS`: Frozen array of 3 8090 Software Factory Work Orders (`WO-101`, `WO-102`, `WO-103`) matching 8090's schema (`id`, `title`, `type`, `priority`, `status`, `phase`, `assignee`, `labels`, `targetFiles`, `dependencies`, `blueprintRef`, `requirementRef`, `description`).
  - `WO-101`: Fix `BILL-101` sub-cent fee rounding drift in `src/fee-engine.js` without breaking `src/settlement-service.js` or `src/sox-reconciler.js`.
  - `WO-102`: Replace legacy webhook signature check in `src/webhook-handler.js` with constant-time HMAC brick (disjoint from `WO-101`).
  - `WO-103`: Add signed keyset pagination to `src/invoice-list.js` (disjoint from `WO-101` and `WO-102`).
- `ORG_CONTEXT_MODALITIES`: Frozen object containing all 6 EVOLVE organizational context sources:
  1. `tickets` (8090 Work Orders + Requirements + Blueprints)
  2. `codebaseSpans` (`src/fee-engine.js`, `src/settlement-service.js`, `src/sox-reconciler.js` exact line spans)
  3. `pastSessions` (prior failed session trace synthesizing `INV-FIN-03` with `supersedes_id` lineage)
  4. `emails` (Controller audit email specifying zero-cent batch variance rule)
  5. `chats` (`#billing-eng` Slack thread warning about `sox-reconciler.js` 2 hops downstream + an untrusted prompt-injected external ticket comment for the Confused-Deputy drill)
  6. `transcripts` (Architecture review meeting transcript locking largest-remainder cent allocation)
- `CANDIDATE_PATCHES`: Frozen object with 3 exact `src/fee-engine.js` / `src/sox-reconciler.js` patch sets:
  - `naiveAgentPatch`: Modifies `src/fee-engine.js` using naive per-line `Math.round(amountCents * feeBps / 10000)` that passes local single-item unit test (`$100.00` single line) but produces `+1` cent batch discrepancy on a 3-way `$100.00` (`3334 + 3333 + 3333 = 10000` gross, `2.5%` fee = `250` cents expected vs `83 + 83 + 83 = 249` fee / `9751` vs `9750` net -> `+1` cent delta!).
  - `sneakyWorkaroundPatch`: Agent attempts to silence the failure by editing `src/sox-reconciler.js` (`const MAX_TOLERANCE_CENTS = 2; strictSox = false;`).
  - `verifiedRemediationPatch`: Legitimate fix in `src/fee-engine.js` using integer basis-point largest-remainder distribution so line-item fees sum identically to batch fee (`deltaCents === 0`), while keeping `src/sox-reconciler.js` untouched.
- `materializeBillingRepo(targetDir)`: Writes the clean `acme-legacy-billing` target files (`src/fee-engine.js`, `src/settlement-service.js`, `src/sox-reconciler.js`, `src/webhook-handler.js`, `src/invoice-list.js`, `src/server.js`, `.sw-factory/WO-101.json`) from `billing-repo-snapshot.json` into `targetDir` and returns `{ repoDir, filesWritten }`.
- `getLegacySlopSamples()`: Returns the array of `{ filePath, content }` brownfield anti-pattern samples from `billing-repo-snapshot.json` for Stage 3 Slop-Breaker demonstration.

Exports of `src/engines/refinery-context.js`:
- `createRefineryEngine({ stack, hydraClient = null, workspaceRoot })`:
  - `seedOrganizationalContext({ repoDir })`: Seeds `stack.context` (`krusch-context-mcp` SQLite `FTS5/BM25` + `INV-12` span provenance + `revise` superseding lineage from `INV-FIN-02` to `INV-FIN-03`), indexes `emails`, `chats`, and `transcripts` into `@krusch/toolkit/raw-rag` (`createRawRagIndex({ offline: true })` + `chunkConversationWindows` + `rerankCandidateWindows`), and optionally syncs lineage to `hydraClient.ingestMemories` when `hydraClient?.isConfigured()` is true. Returns `okEnvelope('deadbolt.refinery.seed', ...)`.
  - `hydrateWorkOrderContext({ workOrderId = 'WO-101', query = 'INV-FIN-03 fee rounding batch settlement reconciliation', tokenBudget = 4000 })`: Retrieves bounded context (`< 4000` tokens) from `stack.context.retrieve`, `rawRag.retrieve`, `stack.context.health` (`INV-12` span lock verification: `VALID` vs `STALE_DRIFT`), sanitizes untrusted external inputs via `delimitUntrustedContent` + `sanitizeAgentMessage`, and optionally enriches from `hydraClient.queryContext`. Returns `okEnvelope('deadbolt.refinery.hydrate', summary, { workOrder, contextBriefing, tokensUsed, tokenBudget, spanIntegrity, lineageChain, modalitiesHydrated, untrustedGuard, hydraSync })`.

### Module B (Agent 2): Stage 2 Planner & Stage 3 Foundry
Files owned exclusively by Agent 2:
- `src/engines/planner-graph.js`
- `src/engines/foundry-staging.js`

Exports of `src/engines/planner-graph.js`:
- `createPlannerEngine({ stack, kruschGitClient = null })`:
  - `analyzeBlastRadius({ repoDir, repoName = 'acme-legacy-billing', entryFile = 'src/fee-engine.js', workOrders = [] })`:
    1. Indexes `repoDir` in `stack.git.indexRepo({ path: repoDir, name: repoName })` and queries `stack.git.dependencyGraph` + `stack.git.fileSymbols` to compute exact 1-hop (`src/settlement-service.js`) and 2-hop (`src/sox-reconciler.js`, `src/server.js`) callers/dependents.
    2. Probes remote `kruschGitClient` (`health()` / `listRepos()`) when configured to report live Tier 2A fleet graph connectivity alongside local SQLite AST graph.
    3. Routes bounded plumbing vs. multi-hop financial domain tasks using `<25µs` `selectCascadeTier` + `createTierCircuitBreaker` (`@krusch/toolkit/cascade`), measuring actual routing elapsed microseconds (`process.hrtime.bigint()`).
    4. Computes **Parallel Work Order Disjoint AST Leases** across `workOrders` (`WO-101`, `WO-102`, `WO-103`), proving which Work Orders have disjoint 2-hop cones (`canRunInParallel: true`) vs colliding choke points (`src/server.js` reserved for orchestrator).
    Returns `okEnvelope('deadbolt.planner.blast_radius', summary, { entryFile, hop1Files, hop2Files, hopPath, symbolGraph, cascadeRoutes, routingLatencyUs, parallelLeases, remoteKruschGit })`.
  - `scanExternalRepository({ repoUrlOrPath, maxFiles = 60 })`:
    Supports live *"Paste Any GitHub Repo URL or Local Path"* intake! Validates `https://github.com/<owner>/<repo>` URLs via `validateOutboundUrl` (`allowedHosts: ['github.com']`) before shallow-cloning (`git clone --depth 1 --single-branch` into `/tmp/deadbolt-scan-*` with `execFileSync` timeout `20000ms` and zero shell interpolation) OR reads an existing local directory path safely, indexes AST symbols with `stack.git.indexRepo`, and runs `<1ms` `scoreLegoBrickCoverage` (`@krusch/toolkit/catalog`) across JS/TS/JSX/PY files. Cleans up temp clone directory after scanning. Returns `okEnvelope('deadbolt.planner.repo_scan', summary, { target, scannedFiles, symbolCount, dependencyPreview, slopAudit, elapsedMs })`.

Exports of `src/engines/foundry-staging.js`:
- `createFoundryEngine({ stack })`:
  - `auditWithSlopBreaker({ files, label = 'candidate' })`: Runs `<1ms` `scoreLegoBrickCoverage` and `auditBoilerplateText` (`@krusch/toolkit/catalog`), measuring sub-millisecond execution (`process.hrtime.bigint()`), returning `okEnvelope('deadbolt.foundry.slop_breaker', summary, { label, elapsedMs, breakerTripped, slopFindingCount, sealedCoverageRatio, recommendedBrickIds, findings })`.
  - `stageWorkOrderEdits({ workOrderId, goal, repoDir, edits })`: Stages `edits` (`[{ file_path, content }]`) in an isolated staging workspace copy + records durable apply intent in `stack.harness.run` (`harness_tasks`), returning `{ taskId, status, unifiedDiff, stagingDir, invariantFindings }` inside `okEnvelope('deadbolt.foundry.stage', ...)`.
  - `applyVerifiedStage({ taskId })`: Calls `stack.harness.applyDiff({ task_id: taskId })` only after Validator approval. Returns `okEnvelope('deadbolt.foundry.apply', ...)`.
  - `runCrashRecoveryDrill({ repoDir })`: Demonstrates journaled crash recovery on a scratch copy of `repoDir`: stages a 2-file edit, simulates a mid-apply crash leaving `harness_apply_journal.state = 'RECOVERY_PENDING'` with partial disk state, invokes `stack.harness.recoverInFlight()`, and verifies deterministic convergence (`halfWrittenFiles === 0`) with before/after SHA-256 file hashes. Returns `okEnvelope('deadbolt.foundry.crash_drill', ...)`.

### Module C (Agent 3): Stage 4 Validator & Sponsor Connectors
Files owned exclusively by Agent 3:
- `src/engines/validator-gate.js`
- `src/connectors/sponsors.js`

Exports of `src/engines/validator-gate.js`:
- `createValidatorEngine({ auditDbPath, hmacSecret, llmConfig = {} })`:
  - Uses `createAuditLog({ sqlitePath: auditDbPath, hmacSecret })` (`@krusch/toolkit/audit-log`) and `createFrozenPolicyFloor` (`@krusch/toolkit/harness-engineering`) with protected paths `['src/sox-reconciler.js', 'sox-reconciler.js', '.sw-factory/policy.lock']` and extra rule `FLOOR-SOX-TOLERANCE-BYPASS` blocking `strictSox\s*=\s*false` or `MAX_TOLERANCE_CENTS\s*=\s*[1-9]`.
  - `runSoxReconciliationCheck({ repoDir, candidateEdits = [] })`: Materializes `repoDir` + `candidateEdits` in an isolated temp sandbox and executes both:
    1. Single-invoice unit check (`$100.00` single item @ `250 bps` -> passes on both naive and fixed code, showing why naive unit tests miss the bug!).
    2. Multi-line split batch settlement ledger (`INV-2026-9001`: 3 split line items `[3334, 3333, 3333]` cents = `10000` gross cents @ `250 bps` batch fee = `250` fee cents, `expectedNetCents = 9750`). Computes `actualLineFeeSumCents`, `actualNetCents`, `deltaCents`, and `invariantId: 'INV-FIN-03'`.
    Returns `okEnvelope('deadbolt.validator.reconcile', summary, { passed, invariantId, unitTestPassed, batchCheck: { invoiceId, grossCents, expectedFeeCents, actualFeeCents, expectedNetCents, actualNetCents, deltaCents }, lineBreakdown })`.
  - `validateCandidate({ workOrderId, attemptLabel, repoDir, edits, targetTools = ['edit_file'], runCrossModel = true })`:
    Executes fixed review order (`INV-DB-04`):
    1. **Policy Floor & Self-Rejection Workaround Check**: Checks every edited file path and diff content against `policyFloor.evaluate` and workaround detectors (editing `sox-reconciler.js`, changing tolerance, disabling `strictSox`). If tripped -> `verdict: 'WORKAROUND_REJECTED'` (appends `DENIED` entry to `auditLog`).
    2. **Deterministic Slop Breaker** (`scoreLegoBrickCoverage`) + **SOX-Style Batch Reconciliation Gate** (`runSoxReconciliationCheck`). If `deltaCents !== 0` or slop found -> `verdict: 'GATE_REJECTED'` (appends `FAILURE` entry to `auditLog`).
    3. **Separate-Family Cross-Model Review**: When `runCrossModel` is enabled, runs 2 separate model families (`@krusch/toolkit/llm` if live keys/endpoints respond within `4500ms`, otherwise deterministic structural family profiles clearly labeled `mode: 'offline_deterministic'` vs `mode: 'live_api'`), recording exact measured `inputTokens`, `outputTokens`, `latencyMs`, and `costUsd`.
    4. **Disagreement Check**: If reviewers disagree -> `verdict: 'ESCALATE_TO_HUMAN'`. Only if all deterministic gates pass AND reviewers converge -> `verdict: 'VERIFIED'` (appends `SUCCESS` entry to `auditLog`).
    Returns `okEnvelope('deadbolt.validator.validate', summary, { verdict, reviewOrder, policyCheck, slopCheck, reconciliation, crossModelReview, auditReceipt, telemetry })`.
  - `getAuditTrail({ limit = 50 })`: Queries `auditLog.query({ limit, order: 'desc' })` and runs `auditLog.verify()`, returning `{ valid, verifiedCount, headHash, tailHash, entries }` in `okEnvelope('deadbolt.validator.audit_trail', ...)`.
  - `close()`: Closes `auditLog`.

Exports of `src/connectors/sponsors.js`:
- `createSponsorHub({ config, hydraClient = null })`:
  - **8090 Software Factory Connector (`sofa`)**: Reads/writes `.sw-factory/WO-*.json` + connects to `SOFA_MCP_URL` (`https://api.factory.8090.dev/v2/mcp`) with `X-Sofa-Mcp-Project-Id` and `Bearer sofa-ext-*` via `safeFetch` when `SOFA_API_KEY` & `SOFA_PROJECT_ID` are set; formats PR title `[WO-101] Fix integer basis-point residual allocation in fee-engine` for 8090 automatic PR-to-Work-Order linking + generates Blueprint Drift Bot summary.
  - **HydraDB v2 Connector (`hydradb`)**: Uses `createHydraDbClient` (`@krusch/toolkit/hydradb`) to report live `API-Version: 2` status and sync `supersedes_id` memory lineage + 2-hop `IMPORTS` graph edges when `HYDRADB_API_KEY` is configured, with clean road-mode SQLite fallback.
  - **Composio Connector (`composio`)**: Enforces `INV-DB-07` 3-layer Confused-Deputy defense: (1) refuses execution if `validatorVerdict !== 'VERIFIED'` or `auditChainValid !== true`, (2) blocks prompt-injected payloads (`sanitizeAgentMessage` / `delimitUntrustedContent`), (3) dispatches verified GitHub PR creation via `safeFetch` to `COMPOSIO_BASE_URL` when `COMPOSIO_API_KEY` is present or emits a deterministic signed dry-run PR receipt offline.
  - **ElevenLabs Factory Foreman Voice Connector (`elevenlabs`)**: Calls ElevenLabs streaming TTS (`https://api.elevenlabs.io/v1/text-to-speech/${voiceId}` via `safeFetch` when `ELEVENLABS_API_KEY` is set) and falls back cleanly to `@krusch/toolkit/audio` `encodeWavPcm16` synthesized cockpit breaker alert chime + crisp transcript (`audioBase64`, `mimeType`, `mode: 'elevenlabs_live' | 'pcm16_breaker_synth'`) so audio works 100% reliably on stage with or without venue Wi-Fi!
  - Methods: `getConnectorStatuses()`, `syncSoftwareFactoryWorkOrder(payload)`, `dispatchVerifiedPullRequest(payload)`, `runConfusedDeputyDrill(payload)`, `synthesizeForemanAlert(payload)`.

### Module D (Agent 4): Deadbolt MCP Server & Live Breaker Panel UI
Files owned exclusively by Agent 4:
- `src/mcp/deadbolt-mcp.js`
- `client/src/components/BreakerCockpit.jsx`
- `client/src/styles.css`
- `client/index.html`

Exports of `src/mcp/deadbolt-mcp.js`:
- `DEADBOLT_MCP_TOOLS`: Array of 5 `defineMcpTool` definitions aligned with **8090 Software Factory's MCP Permission Model** (`Settings -> Connections -> MCP Servers`):
  - **4 Read-Only Tools (`readOnlyHint: true`, `destructiveHint: false` -> 8090 `Allow` for unattended Automations & Drift Bot)**:
    1. `deadbolt_hydrate_work_order`: Hydrate bounded `<4,000`-token org context + `INV-12` span lock status for a `WO-*` Work Order.
    2. `deadbolt_map_blast_radius`: Compute 2-hop AST call graph, `<25µs` Cascade tier route, and parallel `WO-*` disjoint leases.
    3. `deadbolt_validate_reconciliation`: Run deterministic Slop Breaker, policy-floor workaround check, and SOX-style penny reconciliation on proposed edits.
    4. `deadbolt_verify_audit_chain`: Verify SHA-256 cryptographic audit ledger integrity and measured cost-per-verified-task receipts.
  - **1 Action Tool (`readOnlyHint: false`, `destructiveHint: false`, `openWorldHint: true` -> 8090 `Confirm` human approval gate)**:
    5. `deadbolt_apply_verified_stage`: Atomically apply a `VERIFIED` staged task to disk and emit a `WO-<id>`-linked PR receipt.
- `createDeadboltMcp({ orchestrator, connect = false })`: Builds the MCP server via `createMcpServer('deadbolt-mcp', '0.1.0', DEADBOLT_MCP_TOOLS, handler, { connect })` (`@krusch/toolkit/mcp`). Also runnable directly via `node src/mcp/deadbolt-mcp.js` when invoked as CLI entrypoint.

Exports of `client/src/components/BreakerCockpit.jsx`:
- `BreakerCockpit`: High-contrast dark-obsidian **Software Factory Breaker Panel** designed for 15-foot stage projection (`#07090E` obsidian background, cyber-grid overlay, canonical 13-point `deadbolt-svg` lightning emblem, crisp emerald `#10B981`, amber `#F59E0B`, crimson `#EF4444`, and cyan `#06B6D4` telemetry indicators).
- **CRITICAL LEGO RULE**: Must use ONLY `@krusch/toolkit/react` (`fetchApiJson`, `useApiQuery`, `useSSEStream`, `StatusPill`, `cn`) for all network/SSE calls. NEVER write raw `fetch(` inside `useEffect` or `new EventSource(`. Zero em dashes (`U+2014`) anywhere in JSX strings!
- Interactive stage controls & panels:
  1. **Top Telemetry Bar**: Live connection pills (`krusch-context-mcp`, `krusch-git` 2-hop AST, `8090 Software Factory`, `HydraDB v2`, `Composio`, `ElevenLabs Foreman`) + audio mute/play button for the Foreman voice alert.
  2. **Primary Action: "Run Head-to-Head Ticket-to-PR (`WO-101`)"** (streams live SSE events via `useSSEStream('/api/run/stream')`):
     - **Left Column (`Standard Single-Model Agent`)**: Modifies `fee-engine.js`, passes naive `$100` single-line unit test, misses `sox-reconciler.js` 2 hops away, same-family reviewer rubber-stamps -> **`INV-FIN-03` VIOLATED (`+$0.01` / `+1¢` batch discrepancy, UNSAFE MERGE)**.
     - **Right Column (`DEADBOLT 4-Stage Factory Governance`)**:
       - `1. REFINERY`: Hydrates all 6 org context modalities (`<4,000` tokens), verifies `INV-12` SHA-256 span locks (`VALID`), shows `INV-FIN-02 -> INV-FIN-03` superseding lineage.
       - `2. PLANNER`: `<25µs` Cascade Router + 2-hop subway map (`fee-engine.js -> settlement-service.js -> sox-reconciler.js`) + Parallel `WO-101 / WO-102 / WO-103` disjoint AST lease matrix.
       - `3. FOUNDRY`: `<1ms` Slop Breaker + isolated staging unified diff.
       - `4. VALIDATOR (Self-Rejection Beat)`:
         - Attempt 1 (Naive rounding): Gate trips on `+1¢` delta (`expected: 9750¢`, `actual: 9751¢`, `delta: +1¢`).
         - Attempt 2 (Agent tries sneaky workaround editing `sox-reconciler.js` tolerance): **BREAKER TRIPPED (`WORKAROUND_REJECTED`: policy floor cannot be overridden by supervised AI)** + plays ElevenLabs Foreman alert!
         - Attempt 3 (Legitimate integer largest-remainder fix in `fee-engine.js`): `delta: 0¢` + separate-family review passes -> `VERIFIED` PR (`[WO-101]`) + verified SHA-256 audit receipt + **Measured Cost-Per-Verified-Task** ledger.
  3. **Live Brownfield Scanner Tab / Drawer ("Paste Any GitHub Repo URL or Local Path")**: Pre-filled quick-select buttons (`acme-legacy-billing`, `https://github.com/OWASP/NodeGoat`) + custom URL input calling `POST /api/repo/scan` via `fetchApiJson`.
  4. **Resilience Drills Bar**: One-click **"Run Crash-Recovery Drill (`INV-DB-06`)"** (`POST /api/drills/crash-recovery`) and **"Run Confused-Deputy Prompt-Injection Drill (`INV-DB-07`)"** (`POST /api/drills/confused-deputy`) + **8090 MCP Tools Matrix** (`Allow` vs `Confirm`).

### Choke-Point Orchestrator (Wired Only by Main Orchestrator)
Files wired exclusively by the orchestrator after subagents finish:
- `src/config.js`
- `src/orchestrator.js`
- `src/server.js`
- `client/src/App.jsx`
- `tests/deadbolt.test.js`

HTTP API Routes exposed by `src/server.js` (`createApiServer` on `:4090`):
- `GET /health` & `GET /doctor` (automatic via `@krusch/toolkit/http`)
- `GET /api/status`: Full dashboard state, connector statuses, work orders, audit trail head/tail hash, and MCP tool permission table.
- `POST /api/run`: Synchronous full head-to-head execution (`Standard Agent` vs `DEADBOLT` 3-attempt self-rejection & remediation loop) returning complete JSON receipt.
- `POST /api/run/stream`: Live `sseResponse` streaming each stage beat (`refinery`, `planner`, `foundry`, `validator.attempt1`, `validator.workaround_blocked`, `validator.verified`, `pr.dispatched`) + final `done` envelope.
- `POST /api/repo/scan`: Scans any GitHub URL or local path (`scanExternalRepository`).
- `POST /api/drills/crash-recovery`: Runs `runCrashRecoveryDrill`.
- `POST /api/drills/confused-deputy`: Runs `runConfusedDeputyDrill`.
- `POST /api/foreman/speak`: Synthesizes Foreman audio alert (`synthesizeForemanAlert`).
- `GET /api/audit`: Returns cryptographically verified SHA-256 audit chain (`getAuditTrail`).
- Static UI routes (`GET /`, `GET /index.html`, `GET /assets/app.js`, `GET /assets/app.css`, `GET /favicon.svg`).
