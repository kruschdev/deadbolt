# DEADBOLT

**Deterministic Governance Layer, 2-Hop Blast-Radius Planner, Self-Rejecting Validator, and Live Breaker Panel for the 8090 Software Factory**

AI software factories generate code fast, but generating code is not knowing it is safe to merge. I built **DEADBOLT** at **EVOLVE (8090 AI Hackathon)** to plug directly into 8090's 4-stage Software Factory pipeline (`1. Refinery -> 2. Planner -> 3. Foundry -> 4. Validator`) and reduce the risk of unsafe AI-generated changes through deterministic controls, separate-family model review, and crash-recoverable staged execution.

## Architecture: How DEADBOLT Plugs Into 8090

```mermaid
flowchart LR
    T["8090 Work Order (WO-101)"] --> R["1. REFINERY: External Memory + 6 Org Context Modalities"]
    R --> P["2. PLANNER: <25us Cascade Router + 2-Hop AST Blast Radius"]
    P --> F["3. FOUNDRY: <1ms Slop Breaker + Isolated Staged Diffs"]
    F --> V["4. VALIDATOR: Deterministic Gates FIRST, Policy Floor, Cross-Family Review"]
    V -->|"Workaround or penny delta"| F
    V -->|"Reviewers disagree"| H["Human Escalation"]
    V -->|"All green"| D["Verified WO-Linked PR + SHA-256 Audit Chain"]
```

### Core Capabilities

1. **Stage 1: Refinery (`src/engines/refinery-context.js`)**  
   Hydrates governing engineering invariants (`< 4,000` tokens/turn) outside the LLM context window from all 6 organizational context modalities (8090 Work Orders/Requirements/Blueprints, codebase spans, past failure traces with `supersedes_id` lineage, emails, Slack threads, and meeting transcripts) using SQLite `FTS5/BM25` + `INV-12` SHA-256 code-span drift locks, `Raw-RAG` lossless windows, and optional **HydraDB v2** graph sync.
2. **Stage 2: Planner (`src/engines/planner-graph.js`)**  
   Maps the 2-hop AST call-graph blast radius (`fee-engine.js -> settlement-service.js -> sox-reconciler.js`) via `krusch-git`, routes bounded plumbing vs. domain math in `< 25µs` via the in-process Cascade Router, computes disjoint AST leases so non-overlapping 8090 Work Orders (`WO-101`, `WO-102`, `WO-103`) can execute in parallel, and scans any pasted GitHub repository URL or local path on demand.
3. **Stage 3: Foundry (`src/engines/foundry-staging.js`)**  
   Enforces pre-audited Golden Bricks with a `< 1ms` zero-token Slop Breaker (`scoreLegoBrickCoverage`), stages unified diffs in isolation, and records write-ahead apply intent in SQLite with deterministic mid-apply crash recovery (`recoverInFlight`).
4. **Stage 4: Validator & Self-Rejection (`src/engines/validator-gate.js`)**  
   Runs checks in fixed non-overridable order:
   - **Import-Frozen Policy Floor (`INV-DB-05`)**: Catches and rejects DEADBOLT's own supervised agent if it attempts a shortcut workaround (such as editing `sox-reconciler.js` or widening cent tolerance) instead of fixing the root rounding bug.
   - **SOX-Style Batch Reconciliation Demonstration (`INV-FIN-03`)**: Computes exact integer-cent batch settlement totals (`expectedNetCents`, `actualNetCents`, and `+1¢` delta).
   - **Separate-Family Review & Disagreement Escalation**: Runs only after deterministic checks pass, logs every verdict to a SHA-256 hash-chained audit ledger, and measures real cost per verified task.
5. **Live Breaker Panel & 8090-Aligned MCP Server (`client/`, `src/mcp/deadbolt-mcp.js`)**  
   High-contrast dark-obsidian cockpit with split-screen **Standard Agent vs. DEADBOLT** SSE streaming, **ElevenLabs** Factory Foreman breaker alerts (with offline PCM16 WAV synthesis fallback), **Composio** Confused-Deputy gated PR dispatch, and a 5-tool MCP server matching 8090's `Allow` (read-only Automations) vs. `Confirm` (mutating Actions) permission split.

## Quick Start

```bash
cp .env.example .env
npm install
npm --prefix client install
npm run build
npm test
npm start
```

Open `http://127.0.0.1:4090` to launch the **DEADBOLT Breaker Panel**, or attach the stdio MCP server (`npm run mcp`) to 8090 Software Factory / Cursor / Claude Code / Antigravity. To idempotently seed an 8090 Software Factory project with DEADBOLT's Feature Requirements, Component Blueprint, Governance Skill, `[WO-101..103]` Work Orders, and Stage 4 Feedback signal via `SOFA_API_KEY` (`sofa-ext-*`), run `npm run seed:8090`.

---

## Open Source License & EVOLVE Section 10(c) / Section 11 Disclosures

**License**: Released under the **MIT License** (`Copyright (c) 2026 Kevin Saylor Ruschman`). See [`LICENSE`](./LICENSE).

### 1. What Was Built During the EVOLVE Event Period (Nov 13, 2026 7:10 PM PT to Nov 14, 2026 3:30 PM PT)
- **DEADBOLT Governance Pipeline (`deadbolt`)**: End-to-end 4-stage Software Factory governance orchestrator (`Refinery -> Planner -> Foundry -> Validator`), 6-modality organizational context refinery, parallel `WO-*` disjoint AST lease planner, live GitHub repository intake scanner, SOX-style financial batch reconciliation gate (`INV-FIN-03`), self-rejection workaround interceptor, Confused-Deputy & crash-recovery drills, 8090-aligned 5-tool MCP server, live Breaker Panel UI, ElevenLabs Factory Foreman voice telemetry, and measured cost-per-verified-task instrumentation.

### 2. Pre-Existing Public Open-Source Libraries by Author (Disclosed per Agreement Section 10(c))
| Package / Repository | License | Pre-Existing Role Used as Library Dependency |
|---|---|---|
| [`@krusch/toolkit`](https://github.com/kruschdev/toolkit) (`v1.8.1`) | MIT | Pre-audited runtime Golden Bricks (`http`, `streaming`, `mcp`, `security`, `audit-log`, `cascade`, `hydradb`, `audio`, `raw-rag`, `harness-engineering`, `trajectory-guard`, `react`) & `<1ms` `auditBoilerplateText` / `scoreLegoBrickCoverage` Slop-Breaker rules. |
| [`krusch-stack`](https://github.com/kruschdev/krusch-stack) (`v1.1.0`) | MIT | Unified Node 22 SQLite packaging of Tier 1 working memory (`krusch-context-mcp`), Tier 2A AST symbol & dependency graph (`krusch-git`), and Tier 3 staged diff journal (`krusch-coding-harness`). |
| [`krusch-context-mcp`](https://github.com/kruschdev/krusch-context-mcp) (`v2.0.0`) | MIT | Tier 1 SQLite `FTS5/BM25` + `1024d` vector working-memory MCP server with `INV-12` SHA-256 span drift locks. |
| [`krusch-git`](https://github.com/kruschdev/krusch-git) (`v1.2.2`) | MIT | Tier 2A AST symbol & 2-hop call-graph dependency engine. |
| [`krusch-coding-harness`](https://github.com/kruschdev/krusch-coding-harness) & [`krusch-grounded-harness`](https://github.com/kruschdev/krusch-grounded-harness) | MIT | Tier 3 isolated workspace staging, durable apply-intent journal, and Turn-0 workspace grounding primitives. |

### 3. Sponsor Event Tools, Commercial APIs & Open-Source Dependencies (Agreement Sections 10(c) & 11)
- **8090 Software Factory** (Event Tool, subject to 8090 Event Tool Terms)
- **HydraDB** ([`hydra-db/hydradb`](https://github.com/hydra-db/hydradb) `v0.4.0` OpenCypher Graph Engine & `API-Version: 2`, Elastic License 2.0 `ELv2` / Sponsor Event Tool Terms)
- **Composio** (`@composio/core` / REST v3, MIT SDK / Sponsor Service Terms)
- **ElevenLabs** (ElevenLabs TTS Streaming API, Sponsor Service Terms)
- **Vercel** (Deployment & Preview Platform, Sponsor Service Terms)
- **Node.js 22 ESM, PostgreSQL + `pgvector`, SQLite (`node:sqlite`), React 19 + Vite 6** (MIT / PostgreSQL License)
