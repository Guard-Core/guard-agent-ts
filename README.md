# guardagent

Telemetry & Monitoring Agent for the [guard ecosystem](https://github.com/rennf93) (TypeScript / Node.js). Companion agent to [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) and its thin adapters.

Docs: <https://guard-core.github.io/guard-agent-ts/>

**Status:** Released (v3.0.2 on npm). TypeScript port of the [guard-agent](https://github.com/Guard-Core/guard-agent) semantics, reporting to the Guard Core App ingestion API.

## Install

```bash
pnpm add guardagent
pnpm add ioredis   # optional: crash-recovery persistence
```

## Usage

```ts
import { GuardAgent, AgentConfig } from "guardagent";

const agent = new GuardAgent(AgentConfig.create({
  endpoint: "https://api.guard-core.com",
  apiKey: process.env.GUARD_API_KEY!,
  projectId: "my-project",
}));
await agent.start();

agent.sendEvent({ kind: "security_event", payload: { /* ... */ } });

await agent.stop(); // final flush + confirm
```

At-least-once delivery, 413 split-or-drop, Retry-After backoff, permanent-rejection handling, degraded-state detection, TTL-cached dynamic rules polled from `GET /api/v1/rules` on `dynamicRuleInterval` (`agent.getDynamicRules()`), and optional Redis crash recovery. See [AGENTS.md](AGENTS.md) for the full reliability semantics.

## About

The guard ecosystem provides application-layer API security middleware across multiple languages and frameworks:

- **Python**: [fastapi-guard](https://github.com/Guard-Core/fastapi-guard), [flaskapi-guard](https://github.com/Guard-Core/flaskapi-guard), [djapi-guard](https://github.com/Guard-Core/djapi-guard), [tornadoapi-guard](https://github.com/Guard-Core/tornadoapi-guard), with [guard-agent](https://pypi.org/project/guard-agent/) for telemetry
- **TypeScript**: [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) with adapters for Express, Fastify, Hono, NestJS
- **Rust**: [guard-core-rs](https://github.com/Guard-Core/guard-core-rs) with adapters for [tower](https://github.com/Guard-Core/tower-guard-rs), [axum](https://github.com/Guard-Core/axum-guard-rs), [actix-web](https://github.com/Guard-Core/actix-guard-rs), [rocket](https://github.com/Guard-Core/rocket-guard-rs), plus [guard-agent-rs](https://github.com/Guard-Core/guard-agent-rs) for telemetry

## License

MIT
