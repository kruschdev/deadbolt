# Install `deadbolt`

These are instructions for a coding agent (Claude Code, Codex, Cursor, Windsurf, or Antigravity) that a person asked to install and configure `deadbolt` (`kruschdev/deadbolt`) on their machine or connect to their IDE.

`deadbolt` is a Node 22+ ESM deterministic 4-stage Software Factory governance layer (`Refinery -> Planner -> Foundry -> Validator`) featuring a React 19 / Vite 6 3-tab Breaker Panel (`http://127.0.0.1:4090`) and a 5-tool 8090-aligned stdio MCP server (`src/mcp/deadbolt-mcp.js` / `npm run mcp`).

## 1. Check Prerequisites First (All at Once)

Run one read-only check before making any changes:

```bash
id -u
node -v 2>/dev/null || echo "MISSING: node"
npm -v 2>/dev/null || echo "MISSING: npm"
git --version 2>/dev/null || echo "MISSING: git"
ss -ltnp 2>/dev/null | grep -E ':4090\b' || lsof -iTCP:4090 -sTCP:LISTEN 2>/dev/null || echo "PORT_4090_FREE"
docker compose version 2>/dev/null || echo "OPTIONAL_MISSING: docker-compose"
ollama --version 2>/dev/null || echo "OPTIONAL_MISSING: ollama"
```

Evaluate the results:
1. **User check**: If `id -u` prints `0` (root), stop and ask the person to run you under a normal non-root developer account.
2. **Node.js `>= 22.0.0` (Required)**: `deadbolt` relies on Node 22 native `node:sqlite` (`WAL` + `FTS5`), portable WebAssembly Tree-sitter (`web-tree-sitter`), and Node 22 `--permission` subprocess sandboxes for SOX-style integer-cent batch reconciliation (`INV-FIN-03`). If `node -v` is missing or below `v22.0.0`, ask the person before installing or switching to Node 22 (`nvm install 22` or `fnm use 22`).
3. **Port `4090` check**: Confirm port `4090` is free before starting the server (`PORT` in `.env` can be changed if `4090` is in use).
4. **Docker, Ollama & External APIs (Strictly Optional)**: Mode A runs offline at `$0.00` with local SQLite WAL storage, deterministic Slop-Breaker and Policy-Floor checks, and offline PCM16 WAV Foreman audio synthesis.

## 2. Choose the Right Setup Mode

- **Mode A: Zero-Docker Local Breaker Panel & Deterministic Verification (Recommended Default)**: Installs locked root and client packages via `npm ci`, builds the React 19 / Vite 6 frontend and runs all 18 automated test suites via `npm test`, and launches the Breaker Panel on `http://127.0.0.1:4090`.
- **Mode B: Optional Local HydraDB `v0.4.0` Graph & 8090 Software Factory Tri-API Sync**: Starts local `ghcr.io/hydra-db/hydradb:0.4.0` via Docker Compose (`--profile hydradb`) and, **only** if the person explicitly provides `SOFA_API_KEY` and `SOFA_PROJECT_ID`, seeds an 8090 Software Factory project via `npm run seed:8090`.

## 3. Install & Verify

### Mode A: Zero-Docker Local Breaker Panel & Verification (Default)

Clone into the target directory if not already inside a `deadbolt` checkout (check `pwd` first):

```bash
git clone https://github.com/kruschdev/deadbolt.git
cd deadbolt
[ -f .env ] || cp .env.example .env
npm ci
npm test
```

*(Note: `npm test` automatically runs the `pretest` hook, which installs `client/node_modules` if missing, builds `client/dist/index.html` with Vite 6, and executes all 18 deterministic governance, polyglot scanner, crash-recovery, and reconciliation test suites.)*

Start the 3-tab Breaker Panel (`1. Work Order Gate`, `2. GitHub Modernizer`, `3. 8090 Factory & Safety`) on `http://127.0.0.1:4090` and check `/health`:

```bash
npm start
# In a separate terminal or background check:
curl -fsS http://127.0.0.1:4090/health
```

### Mode B: Optional Local HydraDB `v0.4.0` & 8090 Software Factory Tri-API Seeding

1. **Optional Self-Hosted HydraDB `v0.4.0` OpenCypher Graph** (only when Docker is active and ports `8443` and `9090` are free):
   ```bash
   docker compose --profile hydradb up -d
   ```
   If connecting the host server directly to the local HydraDB container, set `HYDRADB_GRAPH_URL=http://127.0.0.1:8443` and `HYDRADB_GRAPH_TOKEN=deadbolt-local-dev-token` in `.env`.

2. **Optional 8090 Software Factory Project Seeding** (run **only** when the person explicitly asks to connect 8090 Software Factory and provides `SOFA_API_KEY` and `SOFA_PROJECT_ID`, plus optional `SOFA_ADMIN_API_KEY` and `SOFA_REPORTING_API_KEY` in `.env`):
   ```bash
   npm run seed:8090
   ```

## 4. Connect the 5-Tool Stdio MCP Server to the Person's Coding Agent

`src/mcp/deadbolt-mcp.js` (`npm run mcp`) exposes 5 tools aligned with 8090's permission split: 4 read-only `Allow` tools (`deadbolt_hydrate_work_order`, `deadbolt_map_blast_radius`, `deadbolt_validate_reconciliation`, `deadbolt_verify_audit_chain`) and 1 human-gated `Confirm` action tool (`deadbolt_apply_verified_stage`). Replace `/absolute/path/to/deadbolt` with the real path returned by `pwd`:

- **Claude Code CLI**:
  ```bash
  claude mcp add deadbolt -- node /absolute/path/to/deadbolt/src/mcp/deadbolt-mcp.js
  ```
- **Cursor (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), or Antigravity (`~/.gemini/antigravity/mcp_config.json`)**:
  ```json
  {
    "mcpServers": {
      "deadbolt": {
        "command": "node",
        "args": ["/absolute/path/to/deadbolt/src/mcp/deadbolt-mcp.js"]
      }
    }
  }
  ```
- **Codex (`~/.codex/config.toml`)**:
  ```toml
  [mcp_servers.deadbolt]
  command = "node"
  args = ["/absolute/path/to/deadbolt/src/mcp/deadbolt-mcp.js"]
  ```

## Never

- **Never run `npm`, `node`, or `git` with `sudo` or as `root`**.
- **Never overwrite an existing `.env` or wipe existing entries in an IDE MCP config file**; always read, parse, and merge only the `deadbolt` entry non-destructively.
- **Never invent or populate external API keys** (`SOFA_API_KEY`, `SOFA_PROJECT_ID`, `SOFA_ADMIN_API_KEY`, `SOFA_REPORTING_API_KEY`, `HYDRADB_API_KEY`, `COMPOSIO_API_KEY`, `ELEVENLABS_API_KEY`, `GEMINI_API_KEY`, `OPENROUTER_API_KEY`) in `.env`.
- **Never run `npm run seed:8090`** unless the person explicitly asked to seed an 8090 Software Factory project and provided `SOFA_API_KEY` and `SOFA_PROJECT_ID`.
- **Never start Docker containers** unless the person requested self-hosted `hydradb:0.4.0` and ports `8443` and `9090` are free.

## Tell the Person After

Share a concise status summary:
1. **Breaker Panel URL & mode**: Confirm `http://127.0.0.1:4090` is ready in Mode A (Zero-Docker deterministic governance) or Mode B (with optional `hydradb:0.4.0` / 8090 Tri-API integration).
2. **Verification status**: Report the exact `npm test` pass count (and client build completion).
3. **Configured MCP clients**: List the exact MCP config files updated and remind the person to reload MCP servers so the 5 `deadbolt_*` tools appear.
4. **First-turn test prompt**: Suggest running `"Call deadbolt_hydrate_work_order and deadbolt_verify_audit_chain for WO-101 to verify deadbolt is connected."`
