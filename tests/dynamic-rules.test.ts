/**
 * Dynamic-rules surface tests, mirroring the Python baseline behavior:
 * GET /api/v1/rules with retry (guard_agent/_transport_send.py:140-152,
 * 238-289), TTL caching with stale-on-failure (guard_agent/_client_loops.py:
 * 19-38), the rules loop (guard_agent/_client_loops.py:103-116), and the
 * DynamicRules wire model (guard_agent/models.py:250-324). Everything goes
 * through the public API (GuardAgent / HttpTransport) against the mock
 * ingestion server.
 */
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { GuardAgent } from "../src/agent.js";
import { InvalidRulesError } from "../src/errors.js";
import { DynamicRules, normalizeDynamicRules } from "../src/models.js";
import { HttpTransport } from "../src/transport.js";
import { MockIngestionServer } from "./helpers/mock-server.js";
import { collectingLogger, testAgentConfig } from "./helpers/test-utils.js";

const API_KEY = "test-api-key-1234";

let server: MockIngestionServer;
let baseUrl: string;

beforeAll(async () => {
  server = new MockIngestionServer({ apiKey: API_KEY });
  baseUrl = await server.start();
});

afterAll(async () => {
  await server.stop();
});

afterEach(() => {
  server.clear();
});

function newAgent(overrides: Record<string, unknown> = {}): GuardAgent {
  return new GuardAgent({
    ...testAgentConfig({ endpoint: baseUrl }),
    ...overrides,
  } as ConstructorParameters<typeof GuardAgent>[0]);
}

function rulesPayload(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    rule_id: "rule-123",
    version: 7,
    timestamp: "2026-09-27T00:00:00+00:00",
    expires_at: null,
    ttl: 300,
    ip_blacklist: ["10.0.0.1", "10.0.0.2"],
    ip_whitelist: ["192.168.1.1"],
    ip_ban_duration: 7200,
    blocked_countries: ["XX"],
    whitelist_countries: ["YY"],
    global_rate_limit: 100,
    global_rate_window: 60,
    endpoint_rate_limits: { "/api/login": [5, 60] },
    blocked_cloud_providers: ["AWS", "GCP"],
    blocked_user_agents: ["curl/*"],
    suspicious_patterns: ["union select"],
    enable_penetration_detection: true,
    enable_ip_banning: null,
    enable_rate_limiting: false,
    auto_ban_threshold: 10,
    auto_ban_duration: 3600,
    enable_rate_limit_auto_ban: null,
    emergency_mode: false,
    emergency_whitelist: ["127.0.0.1"],
    emergency_whitelist_only: true,
    message: "hello",
    ...overrides,
  };
}

describe("DynamicRules model", () => {
  it("parses a full snake_case wire payload", () => {
    const rules = normalizeDynamicRules(rulesPayload());
    expect(rules.ruleId).toBe("rule-123");
    expect(rules.version).toBe(7);
    expect(rules.timestamp.toISOString()).toBe("2026-09-27T00:00:00.000Z");
    expect(rules.expiresAt).toBeNull();
    expect(rules.ttl).toBe(300);
    expect(rules.ipBlacklist).toEqual(["10.0.0.1", "10.0.0.2"]);
    expect(rules.ipWhitelist).toEqual(["192.168.1.1"]);
    expect(rules.ipBanDuration).toBe(7200);
    expect(rules.blockedCountries).toEqual(["XX"]);
    expect(rules.whitelistCountries).toEqual(["YY"]);
    expect(rules.globalRateLimit).toBe(100);
    expect(rules.globalRateWindow).toBe(60);
    expect(rules.endpointRateLimits).toEqual({ "/api/login": [5, 60] });
    expect(rules.blockedCloudProviders).toEqual(new Set(["AWS", "GCP"]));
    expect(rules.blockedUserAgents).toEqual(["curl/*"]);
    expect(rules.suspiciousPatterns).toEqual(["union select"]);
    expect(rules.enablePenetrationDetection).toBe(true);
    expect(rules.enableIpBanning).toBeNull();
    expect(rules.enableRateLimiting).toBe(false);
    expect(rules.autoBanThreshold).toBe(10);
    expect(rules.autoBanDuration).toBe(3600);
    expect(rules.enableRateLimitAutoBan).toBeNull();
    expect(rules.emergencyMode).toBe(false);
    expect(rules.emergencyWhitelist).toEqual(["127.0.0.1"]);
    expect(rules.emergencyWhitelistOnly).toBe(true);
    expect(rules.message).toBe("hello");
  });

  it("applies the Python defaults for an empty payload and ignores unknown fields", () => {
    const rules = normalizeDynamicRules({ something_unheard_of: 1 });
    expect(rules).toBeInstanceOf(DynamicRules);
    expect(rules.ruleId).toBe("default-rule");
    expect(rules.version).toBe(1);
    expect(rules.ttl).toBe(300);
    expect(rules.ipBanDuration).toBe(3600);
    expect(rules.ipBlacklist).toEqual([]);
    expect(rules.blockedCloudProviders).toEqual(new Set());
    expect(rules.globalRateLimit).toBeNull();
    expect(rules.emergencyMode).toBe(false);
    expect(rules.emergencyWhitelistOnly).toBe(false);
    expect(rules.message).toBeNull();
  });

  it("accepts camelCase keys and Date objects", () => {
    const when = new Date("2026-09-27T12:00:00Z");
    const rules = normalizeDynamicRules({
      ruleId: "camel",
      expiresAt: when,
      blockedCloudProviders: ["AZURE"],
      endpointRateLimits: { "/x": [3, 30] },
    });
    expect(rules.ruleId).toBe("camel");
    expect(rules.expiresAt).toBe(when);
    expect(rules.blockedCloudProviders).toEqual(new Set(["AZURE"]));
    expect(rules.endpointRateLimits["/x"]).toEqual([3, 30]);
  });

  it("rejects wrong-typed known fields", () => {
    expect(() => normalizeDynamicRules({ ip_blacklist: "not-a-list" })).toThrow(
      InvalidRulesError,
    );
    expect(() => normalizeDynamicRules({ endpoint_rate_limits: { "/x": [1] } })).toThrow(
      InvalidRulesError,
    );
    expect(() => normalizeDynamicRules({ auto_ban_threshold: 0 })).toThrow(
      InvalidRulesError,
    );
    expect(() => normalizeDynamicRules({ ttl: "soon" })).toThrow(/rule ttl/);
    expect(() => normalizeDynamicRules("nope")).toThrow(InvalidRulesError);
  });
});

describe("HttpTransport.fetchDynamicRules", () => {
  it("fetches and normalizes rules from GET /api/v1/rules", async () => {
    server.behavior = (request) => {
      if (request.method === "GET" && request.url === "/api/v1/rules") {
        return { status: 200, body: rulesPayload() };
      }
      return null;
    };
    const transport = new HttpTransport(
      newAgent().config,
    );
    const rules = await transport.fetchDynamicRules();
    expect(rules).toBeInstanceOf(DynamicRules);
    expect(rules?.ruleId).toBe("rule-123");
    expect(rules?.endpointRateLimits["/api/login"]).toEqual([5, 60]);
    const gets = server.requestsFor("/api/v1/rules");
    expect(gets).toHaveLength(1);
    expect(gets[0]?.headers["x-api-key"]).toBe(API_KEY);
  });

  it("retries transient failures and succeeds on a later attempt", async () => {
    let calls = 0;
    server.behavior = (request) => {
      if (request.method !== "GET" || request.url !== "/api/v1/rules") return null;
      calls += 1;
      if (calls === 1) return { status: 500, body: { detail: "boom" } };
      return { status: 200, body: rulesPayload({ rule_id: "second" }) };
    };
    const transport = new HttpTransport(newAgent({ retryAttempts: 2 }).config);
    const rules = await transport.fetchDynamicRules();
    expect(rules?.ruleId).toBe("second");
    expect(server.requestsFor("/api/v1/rules")).toHaveLength(2);
  });

  it("returns null when all attempts fail and counts the giveup", async () => {
    server.behavior = () => ({ status: 500, body: { detail: "down" } });
    const transport = new HttpTransport(newAgent({ retryAttempts: 1 }).config);
    await expect(transport.fetchDynamicRules()).resolves.toBeNull();
    // retryAttempts + 1 tries; the failed-request counter increments once,
    // on the final giveup (mirrors _get_with_retry).
    expect(server.requestsFor("/api/v1/rules")).toHaveLength(2);
    expect(transport.requestsFailed).toBe(1);
  });

  it("returns null for an empty body result (non-dict 200)", async () => {
    server.behavior = () => ({ status: 204, body: "" });
    const transport = new HttpTransport(newAgent({ retryAttempts: 0 }).config);
    await expect(transport.fetchDynamicRules()).resolves.toBeNull();
  });
});

describe("GuardAgent.getDynamicRules caching", () => {
  it("serves the cached copy within the rules ttl", async () => {
    server.behavior = () => ({ status: 200, body: rulesPayload({ ttl: 300 }) });
    const agent = newAgent({ retryAttempts: 0 });

    const first = await agent.getDynamicRules();
    expect(first?.ruleId).toBe("rule-123");
    const second = await agent.getDynamicRules();
    expect(second?.ruleId).toBe("rule-123");
    expect(server.requestsFor("/api/v1/rules")).toHaveLength(1);
    expect(agent.getStats().rulesFetched).toBe(1);
    expect(agent.getStats().cachedRules).toBe(true);
    expect(agent.getStats().rulesLastUpdate).toBeGreaterThan(0);
  });

  it("refetches once the ttl has expired", async () => {
    let generation = 0;
    server.behavior = () => {
      generation += 1;
      return { status: 200, body: rulesPayload({ ttl: 0, rule_id: `gen-${generation}` }) };
    };
    const agent = newAgent({ retryAttempts: 0 });

    const first = await agent.getDynamicRules();
    expect(first?.ruleId).toBe("gen-1");
    const second = await agent.getDynamicRules();
    expect(second?.ruleId).toBe("gen-2");
    expect(server.requestsFor("/api/v1/rules")).toHaveLength(2);
    expect(agent.getStats().rulesFetched).toBe(2);
  });

  it("returns null on a failed refresh while retaining the previous cache", async () => {
    let healthy = true;
    server.behavior = () => ({
      status: healthy ? 200 : 500,
      body: healthy ? rulesPayload({ ttl: 0 }) : { detail: "down" },
    });
    const agent = newAgent({ retryAttempts: 0 });

    const good = await agent.getDynamicRules();
    expect(good?.ruleId).toBe("rule-123");

    healthy = false;
    // The transport logs and returns null (mirrors fetch_dynamic_rules'
    // blanket except); the agent surfaces null but keeps the last good
    // rules cached for the next poll.
    await expect(agent.getDynamicRules()).resolves.toBeNull();
    expect(agent.getStats().rulesFetched).toBe(1);
    expect(agent.getStats().cachedRules).toBe(true);
  });

  it("returns null when there is no cache and the fetch fails", async () => {
    server.behavior = () => ({ status: 500, body: { detail: "down" } });
    const agent = newAgent({ retryAttempts: 0 });
    await expect(agent.getDynamicRules()).resolves.toBeNull();
    expect(agent.getStats().cachedRules).toBe(false);
  });
});

describe("GuardAgent rules loop", () => {
  it("polls rules on the loop interval and keeps polling through failures", async () => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const pumpUntil = async (condition: () => boolean, maxTurns = 1000): Promise<void> => {
      for (let i = 0; i < maxTurns; i++) {
        if (condition()) return;
        await new Promise((resolve) => setImmediate(resolve));
      }
    };
    try {
      // First cycle fails: the transport logs and returns null, the loop
      // keeps running (mirrors _rules_loop + fetch_dynamic_rules).
      server.behavior = () => ({ status: 500, body: { detail: "rules down" } });
      const agent = newAgent({ retryAttempts: 0, dynamicRuleInterval: 60 });
      await agent.start();

      await vi.advanceTimersByTimeAsync(61_000);
      await pumpUntil(() => server.requestsFor("/api/v1/rules").length === 1);
      expect(agent.getStats().rulesFetched).toBe(0);

      // Second cycle succeeds and the cache is refreshed.
      server.clear();
      server.behavior = () => ({ status: 200, body: rulesPayload({ ttl: 0 }) });
      await vi.advanceTimersByTimeAsync(61_000);
      await pumpUntil(() => agent.getStats().rulesFetched === 1);
      expect(agent.getStats().cachedRules).toBe(true);
      expect(server.requestsFor("/api/v1/rules")).toHaveLength(1);

      await agent.stop();
      vi.useRealTimers();
    } catch (error) {
      vi.useRealTimers();
      throw error;
    }
  });
});

describe("dynamicRuleInterval config", () => {
  it("defaults to 300 seconds", () => {
    const agent = newAgent();
    expect(agent.config.dynamicRuleInterval).toBe(300);
  });

  it("rejects values below the 60-second floor", () => {
    expect(() => newAgent({ dynamicRuleInterval: 59 })).toThrow(
      /dynamicRuleInterval must be at least 60 seconds/,
    );
    expect(() => newAgent({ dynamicRuleInterval: 60 })).not.toThrow();
  });
});
