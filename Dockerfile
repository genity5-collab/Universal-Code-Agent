# Universal Code Agent: small, non-root, production image.
FROM node:22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY test ./test
RUN npm run build && npm prune --omit=dev

FROM node:22-bookworm-slim
# git, python and make so the AI's run_command / git / tests work out of the box
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl python3 make && apt-get clean && find /var/lib/apt/lists -type f -delete
ENV NODE_ENV=production PORT=10000 UCA_DATA_DIR=/data
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY web ./web
COPY agent ./agent
RUN useradd -m -u 10001 uca && mkdir -p /data && chown -R uca:uca /data /app
USER uca
EXPOSE 10000
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS http://127.0.0.1:${PORT}/healthz || exit 1
CMD ["node", "dist/src/cli.js", "http"]
