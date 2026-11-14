# deadbolt (`AGENTS.md`)

Full-stack Node 22 ESM + Vite React application stamped from the `fullstack-react-vite` Lego archetype.

## Stack & Toolkit Bricks
- Backend: `@krusch/toolkit/http`, `@krusch/toolkit/streaming` (`sseResponse`), `@krusch/toolkit/db`, `@krusch/toolkit/config`, `@krusch/toolkit/log`
- Frontend: `@krusch/toolkit/react` (`AppShell`, `StatusPill`, `MetricCard`, `useApiQuery`, `useSSEStream`)
- **OS Drive Protection**: Point `DATA_DIR` to a dedicated non-OS storage volume in production.
- **GitHub Attribution**: Author all commits as `kruschdev <kruschdev@users.noreply.github.com>`.
