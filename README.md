<p align="center">
    <a href="https://guard-core.github.io/guard-core/latest/">
        <img src="https://guard-core.github.io/guard-core/latest/assets/guard_core_legend.svg" alt="Guard Core">
    </a>
</p>

___

<p align="center">
    <strong>Telemetry & Monitoring Agent for the [guard ecosystem](https://github.com/rennf93) (TypeScript / Node.js). Companion agent to [guard-core-ts](https://github.com/Guard-Core/guard-core-ts) and its thin adapters.</strong>
</p>

<p align="center">
    <a href="https://www.npmjs.com/package/guardagent">
        <img src="https://img.shields.io/npm/v/guardagent?color=0080ff" alt="npm version">
    </a>
    <a href="https://guard-core.github.io/guard-agent-ts/latest/">
        <img src="https://img.shields.io/badge/docs-latest-0080ff.svg" alt="Docs">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/release.yml">
        <img src="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/release.yml/badge.svg" alt="Release">
    </a>
    <a href="https://opensource.org/licenses/MIT">
        <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/ci.yml">
        <img src="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/ci.yml/badge.svg" alt="CI">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/codeql.yml">
        <img src="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/codeql.yml/badge.svg" alt="CodeQL">
    </a>
</p>

<p align="center">
    <a href="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/pages/pages-build-deployment">
        <img src="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/pages/pages-build-deployment/badge.svg?branch=gh-pages" alt="PagesBuildDeployment">
    </a>
    <a href="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/docs.yml">
        <img src="https://github.com/Guard-Core/guard-agent-ts/actions/workflows/docs.yml/badge.svg" alt="DocsUpdate">
    </a>
    <img src="https://img.shields.io/github/last-commit/Guard-Core/guard-agent-ts?style=flat&amp;logo=git&amp;logoColor=white&amp;color=0080ff" alt="last-commit">
</p>

<p align="center">
    <img src="https://img.shields.io/badge/TypeScript-3178C6.svg?style=flat&logo=typescript&logoColor=white" alt="TypeScript">
    <a href="https://www.npmjs.com/package/guardagent">
        <img src="https://img.shields.io/npm/dt/guardagent" alt="Downloads">
    </a>
</p>

<p align="center">
    <a href="https://guard-core.com">Website</a> &middot;
    <a href="https://guard-core.github.io/guard-agent-ts/latest/">Docs</a> &middot;
    <a href="https://playground.guard-core.com">Playground</a> &middot;
    <a href="https://app.guard-core.com">Dashboard</a> &middot;
    <a href="https://discord.gg/ZW7ZJbjMkK">Discord</a>
</p>

---

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
