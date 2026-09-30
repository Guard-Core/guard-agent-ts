/**
 * Edge coverage for the pure modules: model normalization failures and
 * defaults, the sanitize/redaction recursion tails, config validation
 * branches, the logger fallbacks, install-id filesystem failures, and the
 * sleep/safe-json helpers.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";

import { validateAgentConfig, resolveAgentConfig } from "../src/config.js";
import { SerializationError } from "../src/errors.js";
import { debugEnabled, DefaultAgentLogger, errorMessage, resolveLogger } from "../src/logger.js";
import {
  DynamicRules,
  normalizeDynamicRules,
  normalizeSecurityEvent,
  normalizeSecurityMetric,
  SecurityEvent,
  SecurityMetric,
  timestampOrDefault,
} from "../src/models.js";
import { resolveInstallId } from "../src/install-id.js";
import {
  calculateBackoffDelay,
  REDACTED,
  safeJsonParse,
  safeJsonStringify,
  sanitizeHeaders,
  sleep,
  truncatePayload,
  summarizeResponseBody,
} from "../src/utils.js";

afterAll(() => {
  vi.restoreAllMocks();
});

describe("model normalization edge cases", () => {
  it("timestampOrDefault falls back to now and parses valid values", () => {
    expect(timestampOrDefault(undefined).getTime()).toBeGreaterThan(0);
    expect(timestampOrDefault(null).getTime()).toBeGreaterThan(0);
    expect(timestampOrDefault("2024-01-01T00:00:00.000Z").toISOString()).toBe(
      "2024-01-01T00:00:00.000Z",
    );
  });

  it("rejects invalid timestamps in every accepted shape", () => {
    const base = { eventType: "rate_limited" };
    expect(() =>
      normalizeSecurityEvent({ ...base, timestamp: new Date("bogus") }),
    ).toThrow("timestamp is not a valid Date");
    expect(() => normalizeSecurityEvent({ ...base, timestamp: Number.NaN })).toThrow(
      "timestamp is not a valid epoch timestamp",
    );
    expect(() =>
      normalizeSecurityEvent({ ...base, timestamp: "not-a-date" }),
    ).toThrow("timestamp is not a valid ISO-8601 timestamp");
    expect(() => normalizeSecurityEvent({ ...base, timestamp: {} })).toThrow(
      "timestamp is required",
    );
  });

  it("accepts epoch-millisecond timestamps", () => {
    const event = normalizeSecurityEvent({
      eventType: "rate_limited",
      timestamp: 1700000000000,
    });
    expect(event.timestamp.toISOString()).toBe("2023-11-14T22:13:20.000Z");
  });

  it("rejects wrong-typed optional fields", () => {
    const base = { eventType: "rate_limited", timestamp: new Date() };
    expect(() => normalizeSecurityEvent({ ...base, country: 5 })).toThrow(
      "country must be a string or null",
    );
    expect(() => normalizeSecurityEvent({ ...base, statusCode: 1.5 })).toThrow(
      "status_code must be an integer or null",
    );
    expect(() => normalizeSecurityEvent({ ...base, metadata: 42 })).toThrow(
      "metadata must be an object",
    );
  });

  it("maps null optional fields onto the defaults", () => {
    const event = normalizeSecurityEvent({
      eventType: "rate_limited",
      timestamp: new Date(),
      country: null,
      action_taken: null,
      reason: null,
      status_code: null,
    });
    expect(event.country).toBeNull();
    expect(event.actionTaken).toBe("");
    expect(event.reason).toBe("");
    expect(event.statusCode).toBeNull();
  });

  it("coerces numeric tag values to strings", () => {
    const metric = normalizeSecurityMetric({
      metricType: "request_count",
      value: 1,
      timestamp: new Date(),
      tags: { n: 5 },
    });
    expect(metric.tags).toEqual({ n: "5" });
  });

  it("rejects wrong-typed metric inputs", () => {
    expect(() => normalizeSecurityMetric(42)).toThrow("Metric must be an object");
    expect(() => normalizeSecurityMetric({ metricType: "nope", value: 1 })).toThrow(
      "metric_type must be one of",
    );
    expect(() =>
      normalizeSecurityMetric({ metricType: "request_count", value: null }),
    ).toThrow("value is required and must be a number");
    expect(() =>
      normalizeSecurityMetric({
        metricType: "request_count",
        value: "   ",
        timestamp: new Date(),
      }),
    ).toThrow("value must be a finite number or null");
    expect(() =>
      normalizeSecurityMetric({
        metricType: "request_count",
        value: "not-a-number",
        timestamp: new Date(),
      }),
    ).toThrow("value must be a finite number or null");
    expect(() =>
      normalizeSecurityMetric({
        metricType: "request_count",
        value: 1,
        timestamp: new Date(),
        tags: "nope",
      }),
    ).toThrow("tags must be an object");
  });

  it("applies constructor defaults for events and metrics", () => {
    const timestamp = new Date();
    const event = new SecurityEvent({
      idempotencyKey: "123e4567-e89b-12d3-a456-426614174000",
      timestamp,
      eventType: "rate_limited",
    });
    expect(event.ipAddress).toBe("");
    expect(event.country).toBeNull();
    expect(event.userAgent).toBeNull();
    expect(event.actionTaken).toBe("");
    expect(event.reason).toBe("");
    expect(event.metadata).toEqual({});

    const metric = new SecurityMetric({ timestamp, metricType: "error_rate", value: 2 });
    expect(metric.endpoint).toBeNull();
    expect(metric.tags).toEqual({});
  });
});

describe("dynamic rules normalization edge cases", () => {
  it("passes DynamicRules instances through untouched", () => {
    const rules = new DynamicRules({ ruleId: "cached" });
    expect(normalizeDynamicRules(rules)).toBe(rules);
  });

  it("rejects wrong-typed known fields", () => {
    expect(() => normalizeDynamicRules({ rule_id: 5 })).toThrow("rule_id must be a string");
    expect(() => normalizeDynamicRules({ ip_blacklist: [5] })).toThrow(
      "ip_blacklist must contain only strings",
    );
    expect(() => normalizeDynamicRules({ ip_blacklist: "nope" })).toThrow(
      "ip_blacklist must be an array of strings",
    );
    expect(() => normalizeDynamicRules({ enable_ip_banning: "yes" })).toThrow(
      "enable_ip_banning must be a boolean or null",
    );
    expect(() => normalizeDynamicRules({ auto_ban_threshold: 0 })).toThrow(
      "auto_ban_threshold must be at least 1",
    );
    expect(() => normalizeDynamicRules({ endpoint_rate_limits: 5 })).toThrow(
      "endpoint_rate_limits must be an object",
    );
    expect(() =>
      normalizeDynamicRules({ endpoint_rate_limits: { "/a": [null, 60] } }),
    ).toThrow("endpoint_rate_limits[\"/a\"] must contain two integers");
  });

  it("treats null rule ids as absent and applies defaults", () => {
    const rules = normalizeDynamicRules({ rule_id: null, blocked_countries: null });
    expect(rules.ruleId).toBe("default-rule");
    expect(rules.blockedCountries).toEqual([]);
    expect(rules.ttl).toBe(300);
  });

  it("applies every constructor default", () => {
    const rules = new DynamicRules({ timestamp: new Date() });
    expect(rules.ruleId).toBe("default-rule");
    expect(rules.version).toBe(1);
    expect(rules.ttl).toBe(300);
    expect(rules.ipBanDuration).toBe(3600);
    expect(rules.blockedCloudProviders.size).toBe(0);
    expect(rules.emergencyMode).toBe(false);
    expect(rules.emergencyWhitelistOnly).toBe(false);
    expect(rules.globalRateLimit).toBeNull();
    expect(rules.autoBanThreshold).toBeNull();
    expect(rules.enablePenetrationDetection).toBeNull();
    expect(rules.expiresAt).toBeNull();
    expect(rules.timestamp.getTime()).toBeGreaterThan(0);
  });
});

describe("sanitizeHeaders recursion tails", () => {
  it("redacts class instances it cannot classify", () => {
    class UnknownShape {
      token = "secret";
    }
    const result = sanitizeHeaders(
      { mystery: new UnknownShape(), keep: "ok" },
      ["cookie"],
    ) as Record<string, unknown>;
    expect(typeof result["mystery"]).toBe("string");
    expect(result["keep"]).toBe("ok");
  });

  it("redacts values it cannot sanitize instead of raising", () => {
    const value = {
      get authorization(): string {
        throw new Error("getter exploded");
      },
    };
    expect(sanitizeHeaders(value, ["authorization"])).toBe(REDACTED);
  });

  it("sanitizes Maps key-by-key with case-insensitive matching", () => {
    const map = new Map<unknown, unknown>([
      ["Authorization", "secret"],
      ["profile", { cookie: "x" }],
      [42, "num-key"],
    ]);
    const result = sanitizeHeaders(map, ["authorization", "cookie"]) as Record<
      string,
      unknown
    >;
    expect(result["Authorization"]).toBe(REDACTED);
    expect(result["42"]).toBe("num-key");
    expect((result["profile"] as Record<string, unknown>)["cookie"]).toBe(REDACTED);
  });

  it("sanitizes Set members", () => {
    const result = sanitizeHeaders(new Set(['{"cookie":"tok"}', "plain"]), ["cookie"]);
    expect(result).toEqual(['{"cookie":"[REDACTED]"}', "plain"]);
  });

  it("flattens pydantic-style model_dump objects", () => {
    const value = { model_dump: () => ({ authorization: "leak", keep: 1 }) };
    expect(sanitizeHeaders(value, ["authorization"])).toEqual({
      authorization: REDACTED,
      keep: 1,
    });
  });

  it("redacts functions and symbols", () => {
    const result = sanitizeHeaders(
      { fn: () => {}, sym: Symbol("s"), keep: "ok" },
      [],
    ) as Record<string, unknown>;
    expect(result["fn"]).toBe(REDACTED);
    expect(typeof result["sym"]).toBe("string");
    expect(result["keep"]).toBe("ok");
  });

  it("handles null-prototype objects", () => {
    const value = Object.create(null) as Record<string, unknown>;
    value["keep"] = "ok";
    value["cookie"] = "session";
    expect(sanitizeHeaders(value, ["cookie"])).toEqual({ keep: "ok", cookie: REDACTED });
  });

  it("returns unparseable and empty JSON-looking strings untouched", () => {
    expect(sanitizeHeaders({ s: "{invalid" }, ["cookie"])).toEqual({ s: "{invalid" });
    expect(sanitizeHeaders({ s: "" }, ["cookie"])).toEqual({ s: "" });
  });

  it("redacts nested structures past the depth cap", () => {
    let deep: unknown = "leaf";
    for (let i = 0; i < 15; i++) deep = { nested: deep };
    const result = sanitizeHeaders(deep, ["cookie"]);
    expect(JSON.stringify(result)).toContain(REDACTED);
  });
});

describe("helper edges", () => {
  it("sleep resolves immediately on an already-aborted signal", async () => {
    const controller = new AbortController();
    controller.abort();
    const start = Date.now();
    await sleep(5_000, controller.signal);
    expect(Date.now() - start).toBeLessThan(1_000);
  });

  it("sleep resolves early when aborted mid-wait", async () => {
    const controller = new AbortController();
    const pending = sleep(5_000, controller.signal);
    setTimeout(() => controller.abort(), 10);
    const start = Date.now();
    await pending;
    expect(Date.now() - start).toBeLessThan(1_000);
  });

  it("safeJsonStringify raises SerializationError for unserializable values", () => {
    expect(() => safeJsonStringify(undefined)).toThrow(SerializationError);
    const circular: Record<string, unknown> = {};
    circular["self"] = circular;
    expect(() => safeJsonStringify(circular)).toThrow(SerializationError);
    expect(() => safeJsonStringify({ big: 1n })).toThrow(SerializationError);
  });

  it("safeJsonParse rejects non-object payloads", () => {
    expect(safeJsonParse("[1,2]")).toBeNull();
    expect(safeJsonParse("42")).toBeNull();
    expect(safeJsonParse("nope")).toBeNull();
    expect(safeJsonParse('{"a":1}')).toEqual({ a: 1 });
  });

  it("keeps backoff, truncation, and summary helpers within their bounds", () => {
    expect(calculateBackoffDelay(-1, 1, 60)).toBe(1);
    expect(calculateBackoffDelay(10, 1, 60)).toBe(60);
    expect(truncatePayload("abcdef", 3)).toBe("abc...[TRUNCATED]");
    expect(truncatePayload("abc", 10)).toBe("abc");
    expect(summarizeResponseBody("a\n\nb   c")).toBe("a b c");
    expect(summarizeResponseBody("x".repeat(400))).toContain("[truncated, 400 chars total]");
  });
});

describe("config validation branches", () => {
  const base = resolveAgentConfig({ apiKey: "test-api-key-1234" });

  it("reports every validation failure", () => {
    const problems = validateAgentConfig({
      ...base,
      apiKey: "short",
      endpoint: "ftp://example.com",
      bufferSize: 0,
      flushInterval: 0,
      timeout: 0,
      retryAttempts: -1,
      backoffFactor: 0,
      statusInterval: 10,
      dynamicRuleInterval: 10,
      highWatermarkRatio: 1.5,
      maxConcurrentFlushes: 0,
      compressionThreshold: -1,
      redis: { url: "ftp://localhost", commandTimeoutMs: 0 },
    });
    expect(problems).toEqual([
      "apiKey must be at least 10 characters long",
      "endpoint must be a valid HTTP/HTTPS URL",
      "bufferSize must be greater than 0",
      "flushInterval must be greater than 0",
      "timeout must be greater than 0",
      "retryAttempts cannot be negative",
      "backoffFactor must be greater than 0",
      "statusInterval must be at least 60 seconds",
      "dynamicRuleInterval must be at least 60 seconds",
      "highWatermarkRatio must be in the range (0, 1]",
      "maxConcurrentFlushes must be at least 1",
      "compressionThreshold cannot be negative",
      "redis.url must be a redis:// or rediss:// URL",
      "redis.commandTimeoutMs must be greater than 0",
    ]);
  });

  it("accepts a valid config with no complaints", () => {
    expect(validateAgentConfig(base)).toEqual([]);
  });

  it("honours caller-provided sensitive headers", () => {
    const config = resolveAgentConfig({
      apiKey: "test-api-key-1234",
      sensitiveHeaders: ["x-custom-secret"],
    });
    expect(config.sensitiveHeaders).toEqual(["x-custom-secret"]);
  });
});

describe("logger seams", () => {
  it("fills missing methods from the default logger", () => {
    const debugCalls: string[] = [];
    const logger = resolveLogger({ debug: (message) => debugCalls.push(message) });
    logger.debug("d");
    const infoSpy = vi.spyOn(console, "info").mockImplementation(() => {});
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    logger.info("i");
    logger.warn("w");
    logger.error("e");
    expect(debugCalls).toEqual(["d"]);
    expect(infoSpy).toHaveBeenCalledWith("[guardagent] i");
    expect(warnSpy).toHaveBeenCalledWith("[guardagent] w");
    expect(errorSpy).toHaveBeenCalledWith("[guardagent] e");
  });

  it("returns the console logger unchanged when nothing is injected", () => {
    expect(resolveLogger(null)).toBeInstanceOf(DefaultAgentLogger);
    expect(resolveLogger(undefined)).toBeInstanceOf(DefaultAgentLogger);
  });

  it("formats non-Error throwables", () => {
    expect(errorMessage(new TypeError("bad"))).toBe("TypeError: bad");
    expect(errorMessage("plain")).toBe("plain");
    expect(errorMessage(42)).toBe("42");
  });

  it("reads the debug flag from the environment", () => {
    const original = process.env["GUARD_AGENT_DEBUG"];
    try {
      process.env["GUARD_AGENT_DEBUG"] = "1";
      expect(debugEnabled()).toBe(true);
      process.env["GUARD_AGENT_DEBUG"] = "off";
      expect(debugEnabled()).toBe(false);
      process.env["GUARD_AGENT_DEBUG"] = "";
      expect(debugEnabled()).toBe(false);
      delete process.env["GUARD_AGENT_DEBUG"];
      expect(debugEnabled()).toBe(false);
    } finally {
      if (original === undefined) {
        delete process.env["GUARD_AGENT_DEBUG"];
      } else {
        process.env["GUARD_AGENT_DEBUG"] = original;
      }
    }
  });
});

describe("install id resolution", () => {
  const writeFile = (path: string, content: string): void => {
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content, "utf8");
  };

  it("reuses a persisted install id", () => {
    const dir = mkdtempSync(join(tmpdir(), "guard-install-"));
    try {
      const statePath = join(dir, "state", "install-id");
      writeFile(statePath, " 0f1a2b3c-1111-4222-8333-abcdefabcdef \n");
      const logger = collectingLogger();
      expect(resolveInstallId({ statePath, logger })).toBe(
        "0f1a2b3c-1111-4222-8333-abcdefabcdef",
      );
      expect(logger.warnings()).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("regenerates when the cached id is empty", () => {
    const dir = mkdtempSync(join(tmpdir(), "guard-install-"));
    try {
      const statePath = join(dir, "install-id");
      writeFile(statePath, "   \n");
      const logger = collectingLogger();
      const generated = resolveInstallId({ statePath, logger });
      expect(generated).toMatch(/^[0-9a-f-]{36}$/);
      expect(readFileSync(statePath, "utf8")).toBe(generated);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("falls back to a fresh uuid when the state path is unusable", () => {
    const dir = mkdtempSync(join(tmpdir(), "guard-install-"));
    try {
      const logger = collectingLogger();
      const first = resolveInstallId({ statePath: dir, logger });
      expect(first).toMatch(/^[0-9a-f-]{36}$/);
      const warnings = logger.warnings().join("\n");
      expect(warnings).toContain("install_id.read_failed");
      expect(warnings).toContain("install_id.write_failed");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function collectingLogger() {
  const messages: { level: string; message: string }[] = [];
  return {
    messages,
    debug: (message: string) => messages.push({ level: "debug", message }),
    info: (message: string) => messages.push({ level: "info", message }),
    warn: (message: string) => messages.push({ level: "warn", message }),
    error: (message: string) => messages.push({ level: "error", message }),
    warnings: () => messages.filter((m) => m.level === "warn").map((m) => m.message),
    errors: () => messages.filter((m) => m.level === "error").map((m) => m.message),
  };
}
