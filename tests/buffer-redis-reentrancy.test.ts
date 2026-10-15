import { describe, expect, it } from "vitest";

import { EventBuffer } from "../src/buffer.js";
import { resolveAgentConfig } from "../src/config.js";
import { EncryptionConfigError } from "../src/encryption.js";
import { normalizeSecurityEvent, normalizeSecurityMetric } from "../src/models.js";
import type { RedisHandler } from "../src/redis.js";
import { HttpTransport } from "../src/transport.js";
import { FakeRedisHandler } from "./helpers/fake-redis.js";
import { collectingLogger, makeEvent } from "./helpers/test-utils.js";

function newBuffer(overrides: Record<string, unknown> = {}): EventBuffer {
  const config = resolveAgentConfig({
    apiKey: "test-api-key-1234",
    bufferSize: 100,
    logger: collectingLogger(),
    ...overrides,
  } as Parameters<typeof resolveAgentConfig>[0]);
  return new EventBuffer(config);
}

const event = (reason = "r") => normalizeSecurityEvent({ ...makeEvent(), reason });
const metric = () =>
  normalizeSecurityMetric({ metricType: "request_count", value: 1, timestamp: new Date() });

/** setKey blocks until release(), so ordering is deterministic. */
class GatedRedis extends FakeRedisHandler {
  private gate: () => void = () => {};
  private readonly opened = new Promise<void>((resolve) => {
    this.gate = resolve;
  });
  private enteredResolve: () => void = () => {};
  readonly entered = new Promise<void>((resolve) => {
    this.enteredResolve = resolve;
  });

  release(): void {
    this.gate();
  }

  override async setKey(
    namespace: string,
    key: string,
    value: string,
    ttl?: number | null,
  ): Promise<boolean | null> {
    this.enteredResolve();
    await this.opened;
    return super.setKey(namespace, key, value, ttl);
  }
}

describe("EventBuffer redis persistence is off the request path", () => {
  it("a redis failure reporting through the buffer cannot recurse", async () => {
    const buffer = newBuffer();
    let calls = 0;
    const redis: RedisHandler = {
      async keys() {
        return [];
      },
      async getKey() {
        return null;
      },
      async delete() {
        return 0;
      },
      async setKey() {
        calls += 1;
        await new Promise((resolve) => setImmediate(resolve));
        await buffer.addEvent(event("redis_error"));
        await buffer.addMetric(metric());
        throw new Error("redis down");
      },
    };
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event());
    await buffer.addMetric(metric());
    await buffer.addEvent(event());
    await buffer.drainPersists();
    expect(calls).toBe(3);
    expect(buffer.getStats().currentEventBufferSize).toBe(5);
    expect(buffer.getStats().currentMetricBufferSize).toBe(4);
  });

  it("an unrelated concurrent add still persists while another persist is in flight", async () => {
    const buffer = newBuffer();
    const redis = new GatedRedis();
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event());
    await redis.entered;
    await buffer.addEvent(event());
    redis.release();
    await buffer.drainPersists();
    expect(redis.store.size).toBe(2);
  });

  it("addEvent and addMetric return before a slow setKey completes", async () => {
    const buffer = newBuffer();
    const redis = new GatedRedis();
    await buffer.initializeRedis(redis);
    await Promise.all([buffer.addEvent(event()), buffer.addMetric(metric())]);
    expect(buffer.getBufferSize()).toBe(2);
    expect(redis.store.size).toBe(0);
    redis.release();
    await buffer.drainPersists();
    expect(redis.store.size).toBe(2);
    const [, keys] = await buffer.flushEventsWithKeys();
    expect(keys[0]).not.toBe("");
  });

  it("stopAutoFlush drains pending persists", async () => {
    const buffer = newBuffer();
    const redis = new GatedRedis();
    await buffer.initializeRedis(redis);
    buffer.startAutoFlush();
    await buffer.addEvent(event());
    await redis.entered;
    let stopped = false;
    const stopping = buffer.stopAutoFlush().then(() => {
      stopped = true;
    });
    await new Promise((resolve) => setImmediate(resolve));
    expect(stopped).toBe(false);
    redis.release();
    await stopping;
    expect(redis.store.size).toBe(1);
  });

  it("a flush during the persist deletes the key instead of orphaning it", async () => {
    const buffer = newBuffer();
    const redis = new GatedRedis();
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event());
    await buffer.addMetric(metric());
    await redis.entered;
    const [, ekeys] = await buffer.flushEventsWithKeys();
    const [, mkeys] = await buffer.flushMetricsWithKeys();
    expect(ekeys).toEqual([""]);
    expect(mkeys).toEqual([""]);
    redis.release();
    await buffer.drainPersists();
    expect(redis.store.size).toBe(0);
  });

  it("an eviction during the persist deletes the key", async () => {
    const buffer = newBuffer({ bufferSize: 1 });
    const redis = new GatedRedis();
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event("first"));
    await redis.entered;
    await buffer.addEvent(event("second"));
    redis.release();
    await buffer.drainPersists();
    // the evicted first key is deleted; the second hit the in-flight cap and stays memory-only
    expect(redis.store.size).toBe(0);
    const [events, keys] = await buffer.flushEventsWithKeys();
    expect(events.map((e) => e.reason)).toEqual(["second"]);
    expect(keys).toEqual([""]);
  });

  it("dropping a persisted oldest item deletes its tracked key", async () => {
    const buffer = newBuffer({ bufferSize: 1 });
    const redis = new FakeRedisHandler();
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event("first"));
    await buffer.drainPersists();
    await buffer.addMetric(metric());
    await buffer.drainPersists();
    expect(redis.store.size).toBe(2);
    await buffer.addEvent(event("second"));
    await buffer.drainPersists();
    await buffer.addMetric(metric());
    await buffer.drainPersists();
    expect(redis.store.size).toBe(2);
  });

  it("clearing the buffer during the persist deletes the key", async () => {
    const buffer = newBuffer();
    const redis = new GatedRedis();
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event());
    await redis.entered;
    await buffer.clearBuffer();
    redis.release();
    await buffer.drainPersists();
    expect(redis.store.size).toBe(0);
  });

  it("a requeue during the persist tracks the key", async () => {
    const buffer = newBuffer();
    const redis = new GatedRedis();
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event());
    await buffer.addMetric(metric());
    await redis.entered;
    const [events, ekeys] = await buffer.flushEventsWithKeys();
    const [metrics, mkeys] = await buffer.flushMetricsWithKeys();
    await buffer.requeueEventsInMemory(events, ekeys);
    await buffer.requeueMetricsInMemory(metrics, mkeys);
    redis.release();
    await buffer.drainPersists();
    expect(redis.store.size).toBe(2);
    const [, keys] = await buffer.flushEventsWithKeys();
    const [, mk] = await buffer.flushMetricsWithKeys();
    expect(keys[0]).not.toBe("");
    expect(mk[0]).not.toBe("");
  });

  it("a failed persist is not tracked", async () => {
    const buffer = newBuffer();
    const redis = new FakeRedisHandler();
    redis.failWrites = true;
    await buffer.initializeRedis(redis);
    await buffer.addEvent(event());
    await buffer.drainPersists();
    const [, keys] = await buffer.flushEventsWithKeys();
    expect(keys).toEqual([""]);
    expect(buffer.redisPersistFailures).toBe(1);
  });

  it("creates no persist promise without a redis handler", async () => {
    const buffer = newBuffer();
    await buffer.addEvent(event());
    await buffer.addMetric(metric());
    expect((buffer as unknown as { inflightPersists: Set<unknown> }).inflightPersists.size).toBe(0);
  });
});

describe("HttpTransport startup encryption failure", () => {
  it("includes the underlying cause in the message and chains it", () => {
    const config = resolveAgentConfig({
      apiKey: "test-api-key-1234",
      projectEncryptionKey: "not-a-valid-key",
      logger: collectingLogger(),
    } as never);
    const t = new HttpTransport(config);
    return t.initialize().then(
      () => {
        throw new Error("expected rejection");
      },
      (error: unknown) => {
        expect(error).toBeInstanceOf(EncryptionConfigError);
        const e = error as EncryptionConfigError;
        expect(e.message).toMatch(/refusing plaintext fallback \(cause: .+\)/);
        expect(e.cause).toBeInstanceOf(Error);
      },
    );
  });
});

describe("EventBuffer bounds in-flight redis persists", () => {
  const inflight = (b: EventBuffer) =>
    (b as unknown as { inflightPersists: Set<unknown> }).inflightPersists.size;
  const backlogWarnings = (log: ReturnType<typeof collectingLogger>) =>
    log.warnings().filter((m) => m.includes("persist backlog"));

  it("never exceeds bufferSize, counts the overflow and warns once per episode", async () => {
    const logger = collectingLogger();
    const buffer = newBuffer({ bufferSize: 3, logger });
    const redis = new GatedRedis();
    await buffer.initializeRedis(redis);
    for (let i = 0; i < 20; i += 1) await buffer.addEvent(event());
    for (let i = 0; i < 3; i += 1) await buffer.addMetric(metric());
    expect(inflight(buffer)).toBe(3);
    expect(buffer.redisPersistFailures).toBe(20);
    expect(backlogWarnings(logger)).toEqual([
      "Redis persist backlog at buffer_size=3; buffering in memory only until it drains",
    ]);
    redis.release();
    await buffer.drainPersists();
    expect(inflight(buffer)).toBe(0);

    const second = new GatedRedis();
    await buffer.initializeRedis(second);
    for (let i = 0; i < 5; i += 1) await buffer.addEvent(event());
    expect(inflight(buffer)).toBe(3);
    expect(backlogWarnings(logger)).toHaveLength(2);
    second.release();
    await buffer.drainPersists();
  });
});
