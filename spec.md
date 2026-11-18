# DEADBOLT Specification (`spec.md`)

**STATUS**: `FROZEN`  
**Version**: `0.1.0`  
**Author**: Kevin Saylor Ruschman (`kruschdev <kruschdev@users.noreply.github.com>`)  
**License**: MIT  

## 1. Purpose & Positioning

DEADBOLT is the deterministic governance control plane, 2-hop blast-radius planner, self-rejecting validator, and live Breaker Panel built for **8090's Software Factory** (`1. Refinery -> 2. Planner -> 3. Foundry -> 4. Validator`).

8090 builds the software; DEADBOLT makes it harder to break. DEADBOLT reduces the risk of unsafe AI-generated changes through deterministic controls, independent cross-family review, and recoverable staged execution.

### Role in the Common Ground · HydraScope · DEADBOLT Ontology Triad
DEADBOLT serves as **Pillar 3** of the [Common Ground · HydraScope · DEADBOLT Ontology Triad](https://krusch.dev/articles/ontological-brick-exchange-deadbolt-common-ground-hydrascope):
- **Pillar 1 ([`0xANUSHKA/common-ground-8090`](https://github.com/0xANUSHKA/common-ground-8090), MIT)**: Captures and structures multi-channel organizational context into Software Factory Work Orders and specifications.
- **Pillar 2 ([`kruschdev/HydraScope`](https://github.com/kruschdev/HydraScope) + [`@krusch/toolkit`](https://github.com/kruschdev/toolkit) `brick-exchange`, MIT)**: Compiles sealed Golden Bricks across the 4-axis ontology (`SoftwareStack`, `DataPort`, `Channel`, `MoEProfile`) into HydraDB `v0.4.0` using deterministic 48-bit SHA-256 `surrogateVertexId` keys, `:SUPERSEDES` lineage, and `:GOVERNS` AST links.
- **Pillar 3 (`DEADBOLT`, MIT)**: Enforces 2-hop Tree-sitter CST blast-radius leases, `< 1ms` Golden Brick Slop-Breaker checks, import-frozen policy floors, integer-cent reconciliation (`INV-FIN-03`), and cross-family consensus prior to Stage-4 promotion.

## 2. Numbered Operational & Architectural Invariants

- **`INV-DB-01` (Deterministic Envelope Contract)**: Every HTTP API handler, engine method, and MCP tool returns `{ ok: boolean, tool: string, summary: string, data?: object, error?: { code, message, details } }` via `okEnvelope` / `errorEnvelope` (`@krusch/toolkit/http`) or `okMcpResult` / `errorMcpResult` (`@krusch/toolkit/mcp`).
- **`INV-DB-02` (Zero Boilerplate Slop / 100% Sealed Golden Bricks)**: Deadbolt source files (`src/**/*.js`, `client/src/**/*.{js,jsx}`) must pass `krusch-lego audit` (`auditBoilerplateText` / `scoreLegoBrickCoverage`) with **0 findings**. Legacy anti-pattern samples used to test the `<1ms` Slop Breaker live exclusively in `src/fixtures/billing-repo-snapshot.json` (JSON data, never raw `.js` source inside `src/`).
- **`INV-DB-03` (Three Distinct Concepts Never Conflated)**:
  1. **Content-integrity fingerprints** (`INV-12` SHA-256 line-span hashes in `krusch-context-mcp` proving code text has not drifted underneath stored memories).
  2. **Architectural & domain invariants** (rules such as `INV-FIN-03` governing settlement batch parity).
  3. **Dependency & call-graph relationships** (`krusch-git` AST symbol + 2-hop file/caller graph + `HydraDB v2` `IMPORTS` edges).
- **`INV-FIN-03` (SOX-Style Batch Reconciliation Demonstration)**: Sum of settled line-item net payouts plus batch processor fee in integer cents must equal gross invoice total in integer cents (`deltaCents === 0`). Per-item `Math.round` without residual carry creates a `+1` cent discrepancy on multi-line split invoices (`expectedNetCents = 10000`, `actualSumCents = 10001`, `deltaCents = +1`).
- **`INV-DB-04` (Fixed Validator Order & Non-Overridable Policy Floor)**: Validation executes in strict order:
  1. Deterministic checks (`<1ms` `scoreLegoBrickCoverage` Slop Breaker + import-frozen `createFrozenPolicyFloor` workaround & lease guard + out-of-process Node 22 `--permission` SOX-style ledger execution with holdout multi-line splits).
  2. Separate-family model reviews (`@krusch/toolkit/llm` with fail-closed `Promise.allSettled` consensus when live reviewers are enabled, deterministic structured audit fallback offline).
  3. Disagreement detection (`consensus` vs `ESCALATE_TO_HUMAN`).
  No model vote can override a failed deterministic gate or authorize mutating protected verification or intermediary files (`sox-reconciler.js`, `settlement-service.js`, `node_modules/`).
- **`INV-DB-05` (Self-Rejection of Agent Workarounds)**: When an agent attempts to pass `INV-FIN-03` by weakening `sox-reconciler.js`, mutating `settlement-service.js`, widening tolerance (`toleranceCents > 0`), or toggling `strictSox = false`, DEADBOLT deterministically blocks the workaround (`WORKAROUND_REJECTED`), records the violation in the SHA-256 hash-chained audit log (`@krusch/toolkit/audit-log`), and requires a legitimate fix in `fee-engine.js` (largest-remainder / integer cent allocation) that passes revalidation.
- **`INV-DB-06` (Isolated Staging & Multi-Process Crash-Recoverable Apply Journal)**: Proposed edits are staged in an isolated workspace via `krusch-stack` `harness` (`harness_tasks` + `harness_apply_journal`) before touching target files, promoted into `repoDir` via a symlink-guarded persisted SQLite apply journal (`.krusch-stack/repo-apply.db`), and verified with a real two-process OS `SIGKILL` crash drill (`runCrashRecoveryDrill` kills an active apply worker after the first rename and recovers preimages in a cold fresh process via `recoverInFlight`).
- **`INV-DB-TS-01` (Portable WASM Tree-sitter Polyglot CST Engine)**: Stage 2 (`planner-graph.js`) and Stage 4 (`validator-gate.js`) parse all 10 supported languages and 14 source extensions via portable WebAssembly Tree-sitter grammars (`web-tree-sitter` + `tree-sitter-wasms` in `src/engines/treesitter-ast.js`, zero native C++ addons), releasing WASM trees deterministically (`tree.delete()`) and preventing fake imports, declarations, or policy-floor workarounds hidden inside comments, strings, or obfuscated AST assignments.
- **`INV-DB-07` (Confused-Deputy & Outbound Action Gate)**: External ticket/chat/PR text is sanitized with `sanitizeAgentMessage` (`@krusch/toolkit/trajectory-guard`) and wrapped with `delimitUntrustedContent` (`@krusch/toolkit/harness-engineering`). Shallow `git clone` operations run with host credential helpers, symlinks, and LFS disabled. Composio outbound PR actions are blocked until Stage 4 (`Validator`) returns `VERIFIED` and all outbound URLs pass `safeFetch` / `validateOutboundUrl` (`@krusch/toolkit/security`).
- **`INV-DB-08` (Measured Cost-Per-Verified-Task & Zero Leaks)**: Only live non-estimated token counts, latency, retries, and USD cost are reported (`costPerVerifiedTaskUsd` is `null` for unverified, degraded-fallback, or estimated runs). Zero API keys, private IPs, or local workstation paths may appear in tracked files or API/MCP responses.
- **`INV-DB-09` (8090 Governance Receipt Stage-4 Gate)**: `POST /api/sofa/sync-receipt` (`syncSofaGovernanceReceipt`) is strictly gated on a real Stage 4 `validator.verified` (`actor === 'deadbolt-validator-gate'`, `outcome === 'SUCCESS'`) audit entry matching `workOrderId` via `findLatestVerifiedEntry` with a 64-hex `entryHash` (`409 UNVERIFIED_STAGE_BLOCKED` before Stage 4 runs or on `modernizer.verified` collisions, `404 WORK_ORDER_NOT_FOUND` when `workOrderId` does not match any live 8090 Work Order; never fabricates `'sha256:verified'` or synthetic USD costs).
- **`INV-DB-HYDRA-ISOLATION-01` (Ephemeral Sponsor Isolation)**: Keep `HYDRADB_API_KEY` (Cloud `v2`) strictly isolated from `HYDRADB_GRAPH_TOKEN` (self-hosted `v0.4.0` OpenCypher), and enforce offline sponsor defaults whenever `ephemeral === true` unless explicit keys are passed in `options.config`, including an offline-short-circuit `hydraClient` when `hydradbApiKey === ''` so `npm test` never leaks to or mutates live sponsor APIs.
- **`INV-SOLO-VOICE-01` (First-Person Voice & No Em Dashes)**: All user-facing copy, README prose, and UI labels use singular first-person technical prose without em dashes (`U+2014`) or unhedged `"guarantees"` claims.

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

### Module B (Agent 2): Stage 2 Planner, Portable WASM Tree-sitter & Stage 3 Foundry
Files owned exclusively by Agent 2:
- `src/engines/treesitter-ast.js`
- `src/engines/planner-graph.js`
- `src/engines/foundry-staging.js`

Exports of `src/engines/treesitter-ast.js`:
- `TREE_SITTER_GRAMMAR_BY_EXTENSION`: Frozen map of all 14 enterprise extensions to their 11 WebAssembly Tree-sitter grammars.
- `initTreeSitterRuntime()` & `isTreeSitterReady()`: Idempotent WASM parser and grammar preloader (`web-tree-sitter` + `tree-sitter-wasms`).
- `analyzeFileWithTreeSitter(sourceText, filePath)`: Deterministic CST symbol, import, call, syntax-error, and SOX policy-floor AST analyzer returning `okEnvelope('deadbolt.treesitter.analyze', ...)`.

Exports of `src/engines/planner-graph.js`:
- `normalizeGitHubRepoInput(rawInput)`: Normalizes browser-copied GitHub URLs (`/tree/<ref>/...`, `/blob/<ref>/<file>`, `github.com/owner/repo`, `owner/repo`, `git@github.com:owner/repo.git`) while rejecting path-traversal segments and preserving SSRF checks.
- `createPlannerEngine({ stack, kruschGitClient = null })`:
  - `analyzeBlastRadius({ repoDir, repoName = 'acme-legacy-billing', entryFile = 'src/fee-engine.js', workOrders = [] })`:
    1. Enforces `isSensitiveLocalPath` + `realpathSync` checks on `repoDir`, indexes `repoDir` in `stack.git.indexRepo`, and queries symbol/edge graphs in $O(N)$ to compute 1-hop (`src/settlement-service.js`) and 2-hop (`src/sox-reconciler.js`, `src/server.js`) callers/dependents.
    2. Probes remote `kruschGitClient` (`health()` / `listRepos()`) with private-IP scrubbing when configured.
    3. Routes bounded plumbing vs. multi-hop financial domain tasks using `<25µs` `selectCascadeTier` (`@krusch/toolkit/cascade`).
    4. Computes **Parallel Work Order Disjoint AST Leases** across `workOrders` (`WO-101`, `WO-102`, `WO-103`).
    Returns `okEnvelope('deadbolt.planner.blast_radius', summary, { entryFile, hop1Files, hop2Files, hopPath, symbolGraph, cascadeRoutes, routingLatencyUs, parallelLeases, remoteKruschGit })`.
  - `scanExternalRepository({ repoUrlOrPath, maxFiles = 60 })`:
    Validates GitHub URLs via `validateOutboundUrl` (`allowedHosts: ['github.com', 'www.github.com']`, upgrading `http://github.com/...` to `https://` and stripping trailing slashes) before non-blocking shallow `git clone --depth 1 --single-branch --filter=blob:limit=256k` (`execFile` timeout `12000ms`), or safely walks local non-sensitive directories (`<= 256 KB` non-binary files, prioritizing `src/`, `app/`, `lib/`, `pkg/`, `cmd/`, `internal/`, `public/`, and `hintedFile` ahead of `tests/`/`examples/`/`benchmarks/`) across 10 languages and 14 enterprise source extensions (`.js`, `.mjs`, `.cjs`, `.jsx`, `.ts`, `.tsx`, `.py`, `.php`, `.java`, `.cs`, `.go`, `.rb`, `.rs`, `.kt`), extracting polyglot dependency edges (`.py`, `.go`, `.rs`, `.java`, `.kt`, `.cs`, `.rb`, `@/`/`~/` TS aliases, and `.php`) and evaluating 28 deterministic Golden Brick + PHP + Polyglot hazard rules. Cleans up temp directories and ephemeral SQLite scan rows in `finally`.

Exports of `src/engines/foundry-staging.js`:
- `createFoundryEngine({ stack })`:
  - `auditWithSlopBreaker({ files, label = 'candidate' })`: Runs `<1ms` `scoreLegoBrickCoverage` and `auditBoilerplateText` (`@krusch/toolkit/catalog`).
  - `stageWorkOrderEdits({ workOrderId, goal, repoDir, edits })`: Stages `edits` in an isolated staging workspace copy with an isolated per-stage journal (`stage.db`) and bounded `MAX_STAGED_TASKS = 64` LRU eviction aligned with `MAX_VERIFIED_TASKS = 64`.
  - `applyVerifiedStage({ taskId, applyToRepoDir = false })`: Applies verified staged diffs only after Validator approval, using a symlink-guarded persisted SQLite apply journal (`.krusch-stack/repo-apply.db`) when `applyToRepoDir === true`.
  - `releaseStage(taskId)`: Deterministically removes staged scratch directories from `os.tmpdir()` and evicts `stagedTasks` state.
  - `runCrashRecoveryDrill({ repoDir })`: Spawns a child apply worker on an isolated `drill-stack.db`, terminates the worker with `SIGKILL` immediately after the first file rename (`APPLYING`), and spawns a fresh recovery process (`recoverInFlight`) proving deterministic rollback (`halfWrittenFiles === 0`).

### Module C (Agent 3): Stage 4 Validator, Modernizer Benchmark & Sponsor Connectors
Files owned by Agent 3 / Modernizer & Connector layer:
- `src/engines/validator-gate.js`
- `src/engines/modernizer-benchmark.js`
- `src/connectors/hydradb-graph.js`
- `src/connectors/sponsors.js`

Exports of `src/engines/validator-gate.js`:
- `parseReviewerVerdictPayload(rawText)`: Fail-closed JSON/structured verdict parser that strips `<think>...</think>` blocks, iterates across embedded JSON objects until a `.verdict` field is found, and returns `APPROVE` strictly when parsed `verdict === 'APPROVE'` (or unambiguous final `VERDICT: APPROVE` / `APPROVE` text without active rejection verdicts), otherwise returning `REJECT`.
- `estimateReviewerUsageCostUsd(modelId, usage)`: Exact per-1M token cost calculator.
- `createValidatorEngine({ auditDbPath, hmacSecret, llmConfig = {} })`: Enforces fixed review order (`1A Policy Floor with string-aware masking -> 1B Slop + INV-FIN-03 SOX Reconciliation -> 2 Cross-Family Review within 4500ms -> 3 Disagreement Escalation`) and tamper-evident SHA-256 `auditLog`.

Exports of `src/engines/modernizer-benchmark.js`:
- `toTargetModernizedPath(relPath)` & `selectModernizationWave({ fileEntries, findings, edges, requestedFile })`.
- `createModernizerBenchmarkEngine(...)`: Runs Head-to-Head Legacy Modernization (`POST /api/repo/modernize`) comparing Arm A (1 Single Frontier Model with full-repo stuffing) vs. Arm B (HydraDB Dual-Live `v2` + `v0.4.0` OpenCypher 2-hop graph slice + `<25µs` Cascade Router + `<1ms` Golden Brick + `vm.Script` + `okEnvelope` Slop/Syntax Breaker + real 2-family `parseReviewerVerdictPayload` consensus with `invariantChecks` pre-deliberation + `:SUPERSEDES` writeback gated on `VERIFIED`). Fast-probes `ollamaUrl` (`1500ms`) before `runArmB` to avoid venue Tailscale stalls, keeps 1-file leaf micro-repos on `L1_FAST` unless multi-hop financial math applies, deduplicates target output paths, and labels token/cost telemetry honestly (`INV-DB-08`).

Exports of `src/connectors/hydradb-graph.js` & `src/connectors/sponsors.js`:
- `scrubPrivateNetworkStrings(value)` & `createHydraGraphClient(...)`: Depth-12 leaf-preserving network/path/secret/email scrubber (never wiping deep nested objects to `{}`) + native HydraDB `v0.4.0` OpenCypher HTTP client over `safeFetch` (`2000ms` header + body timeout and fast-break on unreachable host).
- `createSponsorHub({ config, hydraClient, hydraGraphClient })`: Manages 8090 Software Factory Tri-API (`sofa-admin-*`, `sofa-ext-*`, `sf-rpt-*`, live `getSoftwareFactoryGovernanceSnapshot` and Stage-4-gated `syncGovernanceReceiptTo8090`), HydraDB Dual-Live (`v2.0.1` + `v0.4.0` OpenCypher with `INV-DB-HYDRA-ISOLATION-01` token separation), Composio Connect MCP (`ck_*`) + v3 Confused-Deputy 3-layer gate (`INV-DB-07` pinned hosts + delimited `diffSummary`), and ElevenLabs TTS (`language_code: 'en'`, `3500ms` bounded header + body timeout with offline PCM16 WAV fallback).

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
  3. **Tab 2: Head-to-Head GitHub Modernizer & Polyglot Hazard Scanner**: Pre-filled quick-select pills (`https://github.com/taniarascia/pdo`, `acme-legacy-billing`, `pdo-nextjs-governed`) + custom GitHub URL / local directory input calling `POST /api/repo/modernize` (Arm A 1-Frontier vs. Arm B HydraDB Dual-Live + `<25µs` Cascade + Golden Bricks) and `POST /api/repo/scan` (`<1ms` 28-rule scanner across 10 languages and 14 extensions).
  4. **Tab 3 (`3. 8090 Factory & Safety`)**: Live **8090 Software Factory Tri-API Governance Control Plane** (`GET /api/sofa/governance` + Stage-4-gated `POST /api/sofa/sync-receipt` showing Work Orders, Blueprints, Requirements, Skills, locked `tests`/`blueprints` `AgentPermissionOverride` automations, org token spend, and Stage 4 receipt sync), one-click **"Run Crash-Recovery Drill (`INV-DB-06`)"** (`POST /api/drills/crash-recovery`), **"Run Confused-Deputy Prompt-Injection Drill (`INV-DB-07`)"** (`POST /api/drills/confused-deputy`), and **8090 MCP Tools Matrix** (`4 Allow` vs `1 Confirm`).

### Choke-Point Orchestrator (Wired Only by Main Orchestrator)
Files wired exclusively by the orchestrator after subagents finish:
- `src/config.js`
- `src/orchestrator.js`: Central choke-point orchestrator exposing `modernizeRepository()` (with live 4-axis `SoftwareStack` inference across `python-fastapi`, `react-vite`, `typescript-node`, and `node-esm`, returning `brickOntology: { targetStack, ontologyReady, supportedStacks, supportedPorts }`) alongside `inspectBrickOntology()`, `composeBrickOntology()`, and `synthesizeBrickOntologyBinding()` backed by `stack.brickExchange` (`@krusch/toolkit/brick-exchange`).
- `src/server.js`
- `src/mcp/deadbolt-mcp.js`
- `client/src/App.jsx`
- `package.json`, `client/package.json`, `package-lock.json`, `client/package-lock.json`, `.env.example`, `config.json`, `Dockerfile`, `.dockerignore`, `.gitignore`, `docker-compose.yml`, `.github/workflows/ci.yml`, `README.md`, `AGENTS.md`
- `tests/deadbolt.test.js`, `tests/smoke.test.js`, `scripts/seed-8090-project.js`

HTTP API Routes exposed by `src/server.js` (`createApiServer` on `127.0.0.1:4090` by default, `HOST=0.0.0.0` in Docker, localhost-scoped CORS):
- `GET /health` & `GET /doctor` (automatic via `@krusch/toolkit/http`)
- `GET /api/status`: Full dashboard state, connector statuses, work orders, audit trail head/tail hash, and MCP tool permission table.
- `POST /api/run`: Synchronous full head-to-head execution (`Standard Agent` vs `DEADBOLT` 3-attempt self-rejection & remediation loop) returning complete JSON receipt.
- `POST /api/run/stream`: Live `sseResponse` streaming each stage beat (`refinery`, `planner`, `foundry`, `validator.attempt1`, `validator.workaround_blocked`, `validator.verified`, `pr.dispatched`) + final `done` envelope, honoring client `AbortSignal`.
- `POST /api/repo/scan`: Scans any GitHub URL or local path (`scanExternalRepository`).
- `POST /api/repo/modernize`: Runs Head-to-Head Legacy Modernization (`runModernizationComparison`).
- `POST /api/drills/crash-recovery`: Runs `runCrashRecoveryDrill`.
- `POST /api/drills/confused-deputy`: Runs `runConfusedDeputyDrill`.
- `POST /api/foreman/speak`: Synthesizes Foreman audio alert (`synthesizeForemanAlert`).
- `GET /api/sofa/governance`: Returns live or deterministic 8090 Software Factory Tri-API governance snapshot (`getSofaGovernance`).
- `POST /api/sofa/sync-receipt`: Stage-4-gated governance receipt sync to 8090 Work Order + Feedback Inbox (`syncSofaGovernanceReceipt`, `409 UNVERIFIED_STAGE_BLOCKED` before Stage 4 `VERIFIED`, `404 WORK_ORDER_NOT_FOUND` on unknown Work Order).
- `GET /api/audit`: Returns cryptographically verified SHA-256 audit chain (`getAuditTrail`).
- `GET /api/metrics` & `POST /api/stream`: Telemetry event counter & baseline SSE stream.
- Static UI routes (`GET /`, `GET /index.html`, `GET /assets/app.js`, `GET /assets/app.css`, `GET /favicon.svg`).
