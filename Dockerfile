FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
ENV PUPPETEER_SKIP_DOWNLOAD=true

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY client/package*.json ./client/
RUN npm --prefix client ci

COPY . .
RUN npm run build && mkdir -p /app/data /app/logs && chown -R node:node /app

ENV NODE_ENV=production
ENV HOST=0.0.0.0
USER node
EXPOSE 4090
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD node --input-type=module -e "const r = await fetch('http://127.0.0.1:4090/health'); if (!r.ok) process.exit(1);"
CMD ["node", "src/server.js"]
