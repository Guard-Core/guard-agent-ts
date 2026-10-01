Release Notes
=============

___

v3.2.0 (2026-10-01)
-------------------

The hardening release: full coverage, scaffold baseline, and audit-clean dev deps (v3.2.0)
------------------------------------------------------------------------------------------

### About this release

- **A maintenance release for the 4.3.0 train.** There are no runtime behavior changes in this version: every `src/` delta since 3.1.0 is either a coverage hint or a comment. The release exists so consumers on the Guard 4.3.0 train pick up the audit-clean toolchain, the repo governance baseline, and the 100%-coverage test suite in a tagged, npm-published artifact.

### Changed (3.1.0 -> 3.2.0)

- **Dev dependency bumps and audit fixes.** `vitest` and `@vitest/coverage-v8` move to 5.x, `@types/node` to 26.x, and the dev-only `ioredis` to 6.x (the optional `ioredis` peer dependency stays at `^5.0.0`, so consumer-facing requirements are unchanged); an `esbuild` override (`^0.28.2`) clears its audit advisory. `typescript` is deliberately held on the 5.x line because tsup's dts bundler crashes on the TypeScript 7 API.
- **Repo scaffold baseline.** Adopted the guard-core process baseline: issue templates, pull request template, `dependabot.yml`, `CODE_OF_CONDUCT.md`, `CONTRIBUTING.md`, `SECURITY.md`, and CI/release/scheduled-lint workflow updates.

### Testing

- **Branch and statement coverage closed to 100% and gated.** New suites (`agent-paths`, `buffer-paths`, `encryption-edges`, `models-and-utils-edges`, `redis-adapter`, `transport-encryption`, `transport-paths`, `utils`) pin the previously uncovered paths; `vitest` thresholds and CI now fail below 100%. Unreachable-by-contract defensive arms in `src/` are annotated with `v8 ignore` hints and explanatory comments rather than distorting the code.

### Compatibility

- **No dependency on `@guardcore/core`.** The agent talks to the guard-core-app ingestion API over HTTP and intentionally declares no dependency on the core engine (neither registry nor peer), so no `@guardcore/core` floor applies to this package; it stays installable alongside any core version, including 4.3.0.

___

v3.1.0 (2026-09-27)
-------------------

The parity release: the dynamic-rules and encrypted-ingest surface ports (v3.1.0)
----------------------------------------------------------------------------------

### About this release

- **This is the parity release for the Guard agent family.** The 3.1.0 wave (Python, TypeScript, Go, PHP, Rust) ships the same feature surface in every port. Note: the earlier 4.1.0 family tags were a version-accuracy error and were yanked/unpublished; 3.1.0 is the correct version for this train. The conformance corpus (219 cases, spec 4.1.0) validates the shared surface across the ports.

### Added (3.0.2 -> 3.1.0 feature list)

- **AES-256-GCM encrypted ingest.** Event batches can be encrypted end to end with an AES-256-GCM key (`src/encryption.ts`); the server decrypts after transport-level TLS, so batch contents are opaque to intermediaries even on the wire.
- **Sensitive-header redaction.** Authorization, Cookie, Set-Cookie, and other configured sensitive headers are redacted at ingest and again at egress (`sanitizeHeaders`), so secrets never leave the process in plaintext form.
- **Dynamic rules.** The agent polls the guard-core server for dynamic rate-limit and ban rules on a configurable interval (`dynamicRuleInterval`, default 300 seconds) and enforces them locally, emitting `dynamic_rule_applied`, `dynamic_rule_updated`, and `dynamic_rule_violation` events.
- **`on_error` / `max_payload` knobs.** A typed `onError` hook fires per failed pipeline stage (`flush_events`, `flush_metrics`, ...) with the exception and stage context, and `maxPayloadSize` bounds each POST body with automatic payload split.
- **Helpers.** Shared helpers are exported for adapter authors building custom ingest paths: header sanitization, backoff calculation, `Retry-After` parsing, batch-id generation, IP hashing, payload truncation, and safe JSON serialization.

### Fixed

- **The wire version stamp now reports the release version instead of the initial implementation stub.** `AGENT_VERSION` in `src/version.ts` was still hardcoded to `0.1.0` from before the 3.0.2 release train, so the `guardagent/0.1.0` User-Agent header and the `agent_version` batch envelope field lagged the package version. The constant is now derived from `package.json` (inlined by tsup/vitest), so `make bump-version` cannot leave the stamp behind; a derivation test pins the equality.

___

v3.0.2 (2026-09-24)
-------------------

First tagged release: parity with guard-agent 3.0.2 (v3.0.2)
------------------------------------------------------------

### Added

- **Payload-signature contract parity with the reference guard-agent 3.0.2 (Python).** The signature is an HMAC over the uncompressed body; the server verifies after decompression, so the signature always covers the uncompressed bytes on both the encrypted and unencrypted POST paths.

### Fixed

- **The flush loop's partial-failure warning no longer claims Redis retention without Redis.** When a batch was partially rejected and Redis persistence was disabled, the warning said items were "retained in Redis for retry" even though the true disposition is the in-memory buffer only. The warning now names the backend that actually holds the requeued items, and regression tests cover both the Redis-disabled and Redis-enabled warnings.

___
