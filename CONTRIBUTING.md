# Contributing to Guard Agent TS

Thanks for considering a contribution to Guard Agent TS, part of the Guard ecosystem (guard-agent-ts follows the conventions of the Python baseline: guard-core and fastapi-guard).

## Development Setup

Requirements:

- Node.js 20 or newer
- pnpm 10.25.0 (`corepack enable`)

```bash
pnpm install --frozen-lockfile
pnpm lint        # tsc --noEmit
pnpm build       # tsup
pnpm test        # vitest
pnpm test:coverage
```

Integration-flavored tests need Redis on `redis://localhost:6379` (`docker run -p 6379:6379 redis:7-alpine`).

## Quality Gates

Run before pushing (CI enforces the same checks):

```bash
pnpm lint
pnpm build
pnpm test
pnpm audit --audit-level=low
```

## Pull Requests

- Every PR closes an open issue ("Delivers issue: #N") or carries the `no-issue` label (chores and dependency bumps).
- Keep the CI green; one clean push per PR is preferred.
- Commit messages: lowercase, imperative, conventional style (`fix(scope): ...`, `feat(scope): ...`, `ci(scope): ...`). No attribution trailers.

## Security

Never open public issues for security vulnerabilities. Follow SECURITY.md and report via GitHub security advisories.

## Questions

Open a GitHub Discussion in this repository or ask in the Guard Discord (#help).
