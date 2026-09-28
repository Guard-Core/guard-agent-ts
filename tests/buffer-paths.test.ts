/**
 * White-box coverage for EventBuffer paths the contract tests cannot reach
 * deterministically: corrupted redis payloads on load, confirmation and
 * persistence failures, the block-policy poll timeout, the raise/block
 * policies for metrics, redis-buffer clearing failures, and the auto-flush
 * lifecycle edges.
 */
import { describe, expect, it, vi } from "vitest";

import { EventBuffer } from "../src/buffer.js";
import { resolveAgentConfig } from "../src/config.js";
import { BufferFullError } from "../src/errors.js";
import type { SecurityEvent, SecurityMetric } from "../src/models.js";
import {
  eventToWire,
  metricToWire,
  normalizeSecurityEvent,
  normalizeSecurityMetric,
} from "../src/models.js";
import { FakeRedisHandler } from "./helpers/fake-redis.js";
import { collectingLogger, makeEvent } from "./helpers/test-utils.js";

function newBuffer(
  overrides: Record<string, unknown> = {},
  flushCallback: (() => Promise<void>) | null = null,
): EventBuffer {
  const config = resolveAgentConfig({
    apiKey: "test-api-key-1234",
    bufferSize: 3,
    flushInterval: 0.05,
    logger: collectingLogger(),
    ...overrides,
  } as Parameters<typeof resolveAgentConfig>[0]);
  return new EventBuffer(config, flushCallback);
}

function event(n: number) {
  return normalizeSecurityEvent({ ...makeEvent(), eventType: `event_${n}` });
}

function metric(n: number) {
  return normalizeSecurityMetric({
    metricType: "request_count",
    value: n,
    timestamp: new Date(),
  });
}

const settle = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

describe("EventBuffer loading corrupted redis state", () => {
  it("skips missing, unparseable, and invalid entries for both kinds", async () => {
    const redis = new FakeRedisHandler();
    const logger = collectingLogger();
    const buffer = newBuffer({ logger });
    await redis.setKey("agent_events", "e1", JSON.stringify(eventToWire(event(1))), 60);
    await redis.setKey("agent_events", "e2", "", 60); // missing payload
    await redis.setKey("agent_events", "e3", "{not-json", 60); // unparseable
    await redis.setKey("agent_events", "e4", JSON.stringify({ nope: 1 }), 60); // invalid model
    await redis.setKey("agent_metrics", "m1", JSON.stringify(metricToWire(metric(1))), 60);
    await redis.setKey("agent_metrics", "m2", "", 60);
    await redis.setKey("agent_metrics", "m3", "{oops", 60);
    await redis.setKey("agent_metrics", "m4", JSON.stringify({ bad: true }), 60);

    await buffer.initializeRedis(redis);
    expect(buffer.getBufferSize()).toBe(2); // one valid event + one valid metric
    const warnings = logger.warnings().join("\n");
    expect(warnings).toContain("Failed to load event from Redis key");
    expect(warnings).toContain("No data found for key");
    expect(warnings).toContain("Failed to load metric from Redis key");
  });

  it("forgets the oldest persisted key when loading into a full buffer", async () => {
    const redis = new FakeRedisHandler();
    for (let i = 1; i <= 3; i++) {
      await redis.setKey("agent_events", `e${i}`, JSON.stringify(eventToWire(event(i))), 60);
    }
    const buffer = newBuffer({ bufferSize: 2 });
    await buffer.initializeRedis(redis);
    const [events, keys] = await buffer.flushEventsWithKeys();
    expect(events.map((item) => item.eventType)).toEqual(["event_1", "event_2", "event_3"]);
    // The oldest entry lost its redis key while loading; the rest stay paired.
    expect(keys).toEqual(["", "e2", "e3"]);
  });

  it("forgets the oldest persisted metric key when loading into a full buffer", async () => {
    const redis = new FakeRedisHandler();
    for (let i = 1; i <= 3; i++) {
      await redis.setKey("agent_metrics", `m${i}`, JSON.stringify(metricToWire(metric(i))), 60);
    }
    const buffer = newBuffer({ bufferSize: 2 });
    await buffer.initializeRedis(redis);
    const [metrics, keys] = await buffer.flushMetricsWithKeys();
    expect(metrics.map((item) => item.value)).toEqual([1, 2, 3]);
    expect(keys).toEqual(["", "m2", "m3"]);
  });
});

describe("EventBuffer redis failure handling", () => {
  it("short-circuits persistence and load guards without a redis handler", async () => {
    const buffer = newBuffer();
    const cast = buffer as unknown as {
      persistEventToRedis: (event: SecurityEvent) => Promise<string | null>;
      persistMetricToRedis: (metric: SecurityMetric) => Promise<string | null>;
      loadFromRedis: () => Promise<void>;
      deleteMatchingRedisKeys: (
        namespace: string,
        pattern: string,
        limit?: number,
      ) => Promise<void>;
    };
    await expect(cast.persistEventToRedis(event(1))).resolves.toBeNull();
    await expect(cast.persistMetricToRedis(metric(1))).resolves.toBeNull();
    await cast.loadFromRedis();
    await cast.deleteMatchingRedisKeys("agent_events", "agent_events:*");
    await buffer.confirmEventRedisKeys(["k"]);
    await buffer.confirmMetricRedisKeys(["k"]);
    await buffer.confirmMetricRedisKeys([""]);
    expect(buffer.getBufferSize()).toBe(0);
  });

  it("tolerates handlers whose keys() resolves to null", async () => {
    const logger = collectingLogger();
    const nullKeys = new FakeRedisHandler();
    (nullKeys as unknown as { keys: () => Promise<null> }).keys = () =>
      Promise.resolve(null);
    const buffer = newBuffer({ logger });
    await buffer.initializeRedis(nullKeys);
    await buffer.addEvent(event(1));
    await buffer.clearBuffer();
    expect(logger.warnings().some((m) => m.includes("Failed to load from Redis"))).toBe(false);
    expect(logger.warnings().some((m) => m.includes("Failed to clear Redis buffers"))).toBe(false);
  });

  it("degrades metric persistence when redis writes fail", async () => {
    const redis = new FakeRedisHandler();
    redis.failWrites = true;
    const buffer = newBuffer();
    await buffer.initializeRedis(redis);
    await buffer.addMetric(metric(1));
    expect(buffer.redisPersistFailures).toBe(1);
    expect(buffer.getStats().durabilityDegraded).toBe(true);
  });

  it("logs confirmation failures instead of raising", async () => {
    const redis = new FakeRedisHandler();
    const logger = collectingLogger();
    (redis as unknown as { delete: () => Promise<number> }).delete = () =>
      Promise.reject(new Error("del down"));
    const buffer = newBuffer({ logger });
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event(1));
    await buffer.addMetric(metric(1));
    const [, eventKeys] = await buffer.flushEventsWithKeys();
    const [, metricKeys] = await buffer.flushMetricsWithKeys();
    await buffer.confirmEventRedisKeys(eventKeys);
    await buffer.confirmMetricRedisKeys(["", ...metricKeys]);
    const warnings = logger.warnings().join("\n");
    expect(warnings).toContain("Failed to delete confirmed event key");
    expect(warnings).toContain("Failed to delete confirmed metric key");
  });

  it("clears buffers even when the redis wipe fails, and skips wiping without redis", async () => {
    const logger = collectingLogger();
    const broken = new FakeRedisHandler();
    (broken as unknown as { keys: () => Promise<string[]> }).keys = () =>
      Promise.reject(new Error("keys down"));
    const buffer = newBuffer({ logger });
    await buffer.initializeRedis(broken);
    await buffer.addEvent(event(1));
    await buffer.clearBuffer();
    expect(logger.warnings().some((m) => m.includes("Failed to clear Redis buffers"))).toBe(true);
    expect(buffer.getBufferSize()).toBe(0);

    const plain = newBuffer();
    await plain.addEvent(event(2));
    await plain.clearBuffer();
    expect(plain.getBufferSize()).toBe(0);
  });

  it("honours the eviction limit when deleting matching redis keys", async () => {
    const redis = new FakeRedisHandler();
    const buffer = newBuffer();
    await buffer.initializeRedis(redis);
    await redis.setKey("agent_events", "a", "1", 60);
    await redis.setKey("agent_events", "b", "2", 60);
    await (
      buffer as unknown as {
        deleteMatchingRedisKeys: (
          namespace: string,
          pattern: string,
          limit?: number,
        ) => Promise<void>;
      }
    ).deleteMatchingRedisKeys("agent_events", "agent_events:*", 1);
    expect(redis.store.size).toBe(1);
  });
});

describe("EventBuffer overflow policy edges", () => {
  it("re-checks for space after the block-policy poll timeout", async () => {
    const buffer = newBuffer({ bufferSize: 1, bufferOverflowPolicy: "block" });
    await buffer.addEvent(event(1));
    const pending = buffer.addEvent(event(2));
    let settled = false;
    void pending.then(() => {
      settled = true;
    });
    await settle(600); // longer than BLOCK_POLICY_POLL_INTERVAL_MS
    expect(settled).toBe(false);
    await buffer.flushEventsWithKeys();
    await pending;
    expect(settled).toBe(true);
  });

  it("blocks metric writers until space frees", async () => {
    const buffer = newBuffer({ bufferSize: 1, bufferOverflowPolicy: "block" });
    await buffer.addMetric(metric(1));
    const pending = buffer.addMetric(metric(2));
    let settled = false;
    void pending.then(() => {
      settled = true;
    });
    await settle(30);
    expect(settled).toBe(false);
    await buffer.flushMetricsWithKeys();
    await pending;
  });

  it("raises BufferFullError for metrics under the raise policy", async () => {
    const buffer = newBuffer({ bufferSize: 1, bufferOverflowPolicy: "raise" });
    await buffer.addMetric(metric(1));
    await expect(buffer.addMetric(metric(2))).rejects.toThrow(BufferFullError);
  });

  it("confirms the evicted redis key when a full buffer drops under the drop policy", async () => {
    const redis = new FakeRedisHandler();
    const buffer = newBuffer({ bufferSize: 1 });
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event(1));
    await buffer.addEvent(event(2)); // evicts event 1 and confirms its key
    await buffer.addMetric(metric(1));
    await buffer.addMetric(metric(2)); // evicts metric 1 and confirms its key
    expect(redis.store.size).toBe(2);
  });

  it("catches buffer write failures when the persistence logger explodes", async () => {
    const logger = collectingLogger();
    logger.warn = () => {
      throw new Error("warn exploded");
    };
    const redis = new FakeRedisHandler();
    redis.failWrites = true;
    const buffer = newBuffer({ logger });
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event(1));
    expect(buffer.getBufferSize()).toBe(1);
    expect(logger.errors().some((m) => m.includes("Failed to buffer event"))).toBe(true);
    await buffer.addMetric(metric(1));
    expect(buffer.getBufferSize()).toBe(2);
    expect(logger.errors().some((m) => m.includes("Failed to buffer metric"))).toBe(true);
  });
});

describe("EventBuffer legacy flush and requeue edges", () => {
  it("flushEvents/flushMetrics confirm redis keys immediately", async () => {
    const redis = new FakeRedisHandler();
    const buffer = newBuffer();
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event(1));
    await buffer.addMetric(metric(1));
    const events = await buffer.flushEvents();
    const metrics = await buffer.flushMetrics();
    expect(events).toHaveLength(1);
    expect(metrics).toHaveLength(1);
    expect(redis.store.size).toBe(0);
  });

  it("evicts from the tail when requeueing metrics into a full buffer", async () => {
    const redis = new FakeRedisHandler();
    const buffer = newBuffer({ bufferSize: 3 });
    await buffer.initializeRedis(redis);
    await buffer.addMetric(metric(1));
    await buffer.flushMetricsWithKeys();

    const items = [metric(10), metric(11), metric(12), metric(13)];
    const evicted = await buffer.requeueMetricsInMemory(
      items,
      items.map(() => "metric-key"),
    );
    expect(evicted).toEqual(["metric-key"]);
    const [metrics] = await buffer.flushMetricsWithKeys();
    expect(metrics.map((item) => item.value)).toEqual([10, 11, 12]);
  });

  it("tolerates sparse requeue inputs", async () => {
    const buffer = newBuffer({ bufferSize: 5 });
    const sparse = [
      event(20),
      undefined as unknown as SecurityEvent,
      event(21),
    ];
    const evicted = await buffer.requeueEventsInMemory(sparse, ["k20"]);
    expect(evicted).toEqual([]);
    const [events] = await buffer.flushEventsWithKeys();
    expect(events.map((item) => item.eventType)).toEqual(["event_20", "event_21"]);
  });

  it("returns no evicted keys when the evicted tail was never persisted", async () => {
    const buffer = newBuffer({ bufferSize: 1 });
    await buffer.addEvent(event(1));
    const eventEvicted = await buffer.requeueEventsInMemory(
      [event(2), event(3)],
      ["k2", ""],
    );
    expect(eventEvicted).toEqual([]);

    await buffer.addMetric(metric(1));
    const metricEvicted = await buffer.requeueMetricsInMemory(
      [metric(2), metric(3)],
      ["k2", ""],
    );
    expect(metricEvicted).toEqual([]);
  });

  it("tolerates sparse metric requeue inputs", async () => {
    const buffer = newBuffer({ bufferSize: 5 });
    const sparse = [metric(20), undefined as unknown as SecurityMetric, metric(21)];
    const evicted = await buffer.requeueMetricsInMemory(sparse, ["k20"]);
    expect(evicted).toEqual([]);
    const [metrics] = await buffer.flushMetricsWithKeys();
    expect(metrics.map((item) => item.value)).toEqual([20, 21]);
  });

  it("answers null from the key-eviction helpers on empty buffers", () => {
    const buffer = newBuffer();
    const cast = buffer as unknown as {
      forgetOldestEventKey: () => string | null;
      forgetOldestMetricKey: () => string | null;
      forgetNewestEventKey: () => string | null;
      forgetNewestMetricKey: () => string | null;
    };
    expect(cast.forgetOldestEventKey()).toBeNull();
    expect(cast.forgetOldestMetricKey()).toBeNull();
    expect(cast.forgetNewestEventKey()).toBeNull();
    expect(cast.forgetNewestMetricKey()).toBeNull();
  });
});

describe("EventBuffer auto-flush lifecycle", () => {
  it("ignores a second startAutoFlush call", async () => {
    const buffer = newBuffer({ flushInterval: 30 });
    buffer.startAutoFlush();
    buffer.startAutoFlush();
    expect(buffer.getStats().autoFlushRunning).toBe(true);
    await buffer.stopAutoFlush();
    expect(buffer.getStats().autoFlushRunning).toBe(false);
  });

  it("scheduleAutoFlush is a no-op when the loop is stopped", () => {
    const buffer = newBuffer();
    buffer.stopAutoFlush();
    (buffer as unknown as { scheduleAutoFlush: () => void }).scheduleAutoFlush();
  });

  it("the timer callback exits without rescheduling after stop", async () => {
    const flushCallback = vi.fn(async () => {});
    const buffer = newBuffer({ flushInterval: 0.05 }, flushCallback);
    buffer.startAutoFlush();
    (buffer as unknown as { running: boolean }).running = false;
    await settle(150);
    expect(flushCallback).not.toHaveBeenCalled();
    await buffer.stopAutoFlush();
  });

  it("logs auto flush loop errors instead of raising", async () => {
    const logger = collectingLogger();
    const buffer = newBuffer({ flushInterval: 0.05, logger }, async () => {
      throw new Error("flush callback boom");
    });
    await buffer.addEvent(event(1));
    buffer.startAutoFlush();
    await vi.waitFor(() =>
      expect(logger.errors().some((m) => m.includes("Error in auto flush loop"))).toBe(true),
    );
    await buffer.stopAutoFlush();
  });

  it("stopAutoFlush waits for in-flight watermark flushes and logs their failures", async () => {
    const logger = collectingLogger();
    let resolveFlush: () => void = () => {};
    const buffer = newBuffer(
      { bufferSize: 2, highWatermarkRatio: 0.25, flushInterval: 30, logger },
      async () => {
        await new Promise<void>((resolve) => {
          resolveFlush = resolve;
        });
        throw new Error("early flush boom");
      },
    );
    await buffer.addEvent(event(1)); // 1 >= 2 * 0.25 -> watermark flush
    let stopped = false;
    const stopping = buffer.stopAutoFlush().then(() => {
      stopped = true;
    });
    await settle(30);
    expect(stopped).toBe(false);
    resolveFlush();
    await stopping;
    await vi.waitFor(() =>
      expect(logger.errors().some((m) => m.includes("Error during early flush"))).toBe(true),
    );
  });

  it("flushIfNeeded short-circuits on every guard branch", async () => {
    const noCallback = newBuffer({ flushInterval: 30 });
    await noCallback.flushIfNeeded(); // no flush callback wired

    const throttled = newBuffer(
      { flushInterval: 30, maxConcurrentFlushes: 1 },
      async () => {},
    );
    (throttled as unknown as { activeFlushes: number }).activeFlushes = 1;
    await throttled.flushIfNeeded(); // concurrency cap reached

    const empty = newBuffer({ flushInterval: 30 }, async () => {});
    await empty.flushIfNeeded(); // nothing buffered

    const quiet = newBuffer({ flushInterval: 30, bufferSize: 100 }, async () => {});
    await quiet.addEvent(event(1));
    (quiet as unknown as { lastFlushTime: number | null }).lastFlushTime = Date.now() / 1000;
    await quiet.flushIfNeeded(); // below watermark, interval not elapsed
  });
});
