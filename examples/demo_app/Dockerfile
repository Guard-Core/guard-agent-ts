# Build context is the repository root:
#   docker build -f examples/demo_app/Dockerfile .
FROM node:22-alpine AS build

WORKDIR /app

COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY tsconfig.json tsup.config.ts ./
COPY src/ src/
RUN pnpm build

FROM node:22-alpine

RUN addgroup -S guard && adduser -S -G guard guard

WORKDIR /app

COPY --from=build /app/node_modules /app/node_modules
COPY --from=build /app/dist /app/dist
COPY --from=build /app/package.json /app/package.json
COPY examples/demo_app/app.ts /app/examples/demo_app/app.ts

LABEL org.opencontainers.image.title="guard-agent-ts demo" \
    org.opencontainers.image.description="Containerized Guard Agent demo: a small Node service streaming security telemetry to a Guard Core ingestion endpoint" \
    org.opencontainers.image.source="https://github.com/Guard-Core/guard-agent-ts" \
    org.opencontainers.image.licenses="MIT"

ENV GUARD_AGENT_ENDPOINT=https://api.guard-core.com \
    GUARD_AGENT_PROJECT_ID=demo-project \
    PORT=8080

USER guard

EXPOSE 8080

# Type stripping executes app.ts directly; the agent import resolves to the
# built dist/ through the package self-reference.
CMD ["node", "--experimental-strip-types", "examples/demo_app/app.ts"]
