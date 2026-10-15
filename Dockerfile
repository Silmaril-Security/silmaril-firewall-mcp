# syntax=docker/dockerfile:1.7
FROM node:22.22.2-bookworm-slim AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM node:22.22.2-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
ARG SILMARIL_MCP_COMMIT
RUN test -n "$SILMARIL_MCP_COMMIT" && echo "$SILMARIL_MCP_COMMIT" | grep -Eq '^[a-f0-9]{40}$'
ENV GIT_COMMIT_SHA=${SILMARIL_MCP_COMMIT}
LABEL com.silmaril.firewall-mcp.commit="${SILMARIL_MCP_COMMIT}" com.silmaril.firewall-mcp.mode="customer_hosted"
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
RUN mkdir -p /app/.next/cache && chown -R node:node /app/.next/cache
VOLUME ["/tmp", "/app/.next/cache"]
USER node
EXPOSE 3000
CMD ["node", "server.js"]
