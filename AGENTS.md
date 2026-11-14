# deadbolt (`AGENTS.md`)

Full-stack Node 22 ESM + Vite React application stamped from the `fullstack-react-vite` Lego archetype for the 8090 Software Factory.

## Stack & Toolkit Bricks
- Backend: `@krusch/toolkit/http`, `@krusch/toolkit/streaming` (`sseResponse`), `@krusch/toolkit/mcp`, `@krusch/toolkit/sqlite` (`openSqliteDb`), `@krusch/toolkit/security` (`safeFetch`, `validateOutboundUrl`), `@krusch/toolkit/audit-log`, `@krusch/toolkit/cascade`, `@krusch/toolkit/hydradb`, `@krusch/toolkit/krusch-git`, `@krusch/toolkit/audio`, `@krusch/toolkit/raw-rag`, `@krusch/toolkit/harness-engineering`, `@krusch/toolkit/trajectory-guard`, `@krusch/toolkit/catalog`, `@krusch/toolkit/llm`, `@krusch/toolkit/config`, `@krusch/toolkit/log`, and `krusch-stack`
- Frontend: `@krusch/toolkit/react` (`ErrorBoundary`, `fetchApiJson`, `useApiQuery`, `useSSEStream`, `StatusPill`, `cn`, `setReactRuntime`)
- **OS Drive Protection**: Point `DATA_DIR` to a dedicated non-OS storage volume in production.
- **GitHub Attribution**: Author all commits as `kruschdev <kruschdev@users.noreply.github.com>`.
