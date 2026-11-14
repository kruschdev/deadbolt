FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
ENV PUPPETEER_SKIP_DOWNLOAD=true

WORKDIR /app
COPY package*.json ./
RUN npm install

COPY client/package*.json ./client/
RUN npm --prefix client install

COPY . .
RUN npm run build

ENV NODE_ENV=production
EXPOSE 4090
CMD ["node", "src/server.js"]
