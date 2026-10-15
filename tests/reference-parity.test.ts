/**
 * Parity with the Python reference agent (guard-agent 3.2.4): the rules loop
 * only runs with a project id (client.py:128-129), Redis keys carry a
 * wall-clock nanosecond stamp (_buffer_redis.py:54), and SecurityEvent keeps
 * unknown fields (models.py:211, extra="allow").
 */
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

import { GuardAgent } from "../src/agent.js";
import { EventBuffer } from "../src/buffer.js";
import { resolveAgentConfig } from "../src/config.js";
import { eventToWire, normalizeSecurityEvent, normalizeSecurityMetric } from "../src/models.js";
import { FakeRedisHandler } from "./helpers/fake-redis.js";
import { MockIngestionServer } from "./helpers/mock-server.js";
import { collectingLogger, makeEvent, testAgentConfig } from "./helpers/test-utils.js";

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

describe("rules loop needs a project id", () => {
  it.each([
    [null, 0],
    ["proj_test", 1],
  ])("projectId=%s polls the rules endpoint %i time(s)", async (projectId, expected) => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    try {
      server.clear();
      const agent = new GuardAgent({
        ...testAgentConfig({ endpoint: baseUrl, retryAttempts: 0, dynamicRuleInterval: 60 }),
        projectId,
      });
      await agent.start();
      await vi.advanceTimersByTimeAsync(61_000);
      for (let i = 0; i < 1000 && server.requestsFor("/api/v1/rules").length < expected; i++) {
        await new Promise((resolve) => setImmediate(resolve));
      }
      expect(server.requestsFor("/api/v1/rules")).toHaveLength(expected);
      await agent.stop();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("Redis key stamp", () => {
  it("is wall-clock epoch nanoseconds like time.time_ns()", async () => {
    const config = resolveAgentConfig({
      apiKey: API_KEY,
      logger: collectingLogger(),
    } as Parameters<typeof resolveAgentConfig>[0]);
    const buffer = new EventBuffer(config);
    const redis = new FakeRedisHandler();
    await buffer.initializeRedis(redis);
    const before = BigInt(Date.now()) * 1_000_000n;
    await buffer.addEvent(normalizeSecurityEvent(makeEvent()));
    await buffer.addMetric(
      normalizeSecurityMetric({ metricType: "request_count", value: 1, timestamp: new Date() }),
    );
    await buffer.drainPersists();
    const after = BigInt(Date.now() + 1) * 1_000_000n;
    const keys = [...redis.store.keys()];
    expect(keys).toHaveLength(2);
    for (const key of keys) {
      const match = /^agent_(?:events|metrics):(?:event|metric)_(\d+)_[0-9a-f]{8}$/.exec(key);
      expect(match, key).not.toBeNull();
      const stamp = BigInt(match![1]!);
      expect(stamp >= before && stamp <= after, `${key} outside [${before}, ${after}]`).toBe(true);
    }
  });
});

describe("SecurityEvent extra fields", () => {
  it("pass through to the wire and survive redaction and a Redis round trip", async () => {
    const input = {
      ...makeEvent(),
      custom_flag: "x",
      nested: { a: 1 },
      metadata: { authorization: "secret", keep: "y" },
    };
    expect(eventToWire(normalizeSecurityEvent(input))).toMatchObject({
      custom_flag: "x",
      nested: { a: 1 },
    });

    server.clear();
    const agent = new GuardAgent({
      ...testAgentConfig({ endpoint: baseUrl, retryAttempts: 0 }),
    });
    await agent.start();
    await agent.sendEvent(input);
    await agent.flushBuffer();
    await agent.stop();
    const sent = (
      server.requestsFor("/api/v1/events")[0]!.body as { events: Record<string, unknown>[] }
    ).events[0]!;
    expect(sent["custom_flag"]).toBe("x");
    expect(sent["nested"]).toEqual({ a: 1 });
    expect(sent["metadata"]).toEqual({ authorization: "[REDACTED]", keep: "y" });

    const config = resolveAgentConfig({
      apiKey: API_KEY,
      logger: collectingLogger(),
    } as Parameters<typeof resolveAgentConfig>[0]);
    const writer = new EventBuffer(config);
    const redis = new FakeRedisHandler();
    await writer.initializeRedis(redis);
    await writer.addEvent(normalizeSecurityEvent(input));
    await writer.drainPersists();
    const reader = new EventBuffer(config);
    await reader.initializeRedis(redis);
    const [events] = await reader.flushEventsWithKeys();
    expect(eventToWire(events[0]!)).toMatchObject({ custom_flag: "x" });
  });

  it("never lets an extra override a known field", () => {
    const wire = eventToWire(
      normalizeSecurityEvent({ ...makeEvent(), eventType: "rate_limited", event_type: "x" }),
    );
    expect(wire["event_type"]).toBe("rate_limited");
  });
});

describe("getStats key set", () => {
  const camel = (key: string): string => key.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
  // The reference get_stats() keys (_client_status.py:70-89, buffer.py:57-74,
  // _transport_lifecycle.py:128-137), camelCased for the host-facing API.
  const top = [
    "running", "uptime", "events_sent", "metrics_sent", "events_failed", "metrics_failed",
    "rules_fetched", "buffer_stats", "transport_stats", "cached_rules", "rules_last_update",
    "loop_failures", "last_status_push_ok",
  ];
  const buffer = [
    "events_buffered", "metrics_buffered", "events_flushed", "metrics_flushed",
    "events_dropped", "metrics_dropped", "current_event_buffer_size",
    "current_metric_buffer_size", "redis_persist_failures", "durability_degraded",
    "last_flush_time", "auto_flush_running",
  ];
  const transport = [
    "requests_sent", "requests_failed", "bytes_sent", "circuit_breaker_state",
    "failure_count", "session_closed",
  ];

  it("is exactly the reference set", () => {
    const stats = new GuardAgent(testAgentConfig({ endpoint: baseUrl })).getStats();
    expect(Object.keys(stats).sort()).toEqual(top.map(camel).sort());
    expect(Object.keys(stats.bufferStats).sort()).toEqual(buffer.map(camel).sort());
    expect(Object.keys(stats.transportStats).sort()).toEqual(transport.map(camel).sort());
    expect(Object.keys(stats.loopFailures).sort()).toEqual(["flush", "rules", "status"]);
  });
});
