/**
 * White-box coverage for GuardAgent failure paths the public contract tests
 * cannot reach deterministically: loop catch handlers, transport exceptions
 * raised mid-flush, redis persistence degradation at start(), and the
 * health/status edge branches. Private seams are overridden on instances;
 * the source itself stays untouched.
 *
 * ioredis is mocked out for this module so the config-driven persistence
 * path can be driven into its degradation branch without a real server.
 */
import { randomUUID } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { GuardAgent } from "../src/agent.js";
import { HttpTransport } from "../src/transport.js";
import { nowSeconds } from "../src/utils.js";
import { SecurityEvent, SecurityMetric } from "../src/models.js";
import { FakeRedisHandler } from "./helpers/fake-redis.js";
import { MockIngestionServer } from "./helpers/mock-server.js";
import { collectingLogger, makeEvent, testAgentConfig } from "./helpers/test-utils.js";

vi.mock("ioredis", () => {
  throw new Error("ioredis unavailable in this test module");
});

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

function event(n: number, extra: Record<string, unknown> = {}) {
  return { ...makeEvent(), eventType: `event_${n}`, ...extra };
}

function metric(n: number) {
  return { metricType: "request_count", value: n, timestamp: new Date() };
}

type TransportOverride = {
  sendEvents?: () => Promise<boolean>;
  sendMetrics?: () => Promise<boolean>;
};

function overrideTransport(agent: GuardAgent, methods: TransportOverride): void {
  for (const [name, fn] of Object.entries(methods)) {
    (agent.transport as unknown as TransportOverride)[name as keyof TransportOverride] =
      fn as () => Promise<boolean>;
  }
}

function restoreTransport(agent: GuardAgent, name: keyof TransportOverride): void {
  const prototype = HttpTransport.prototype as unknown as TransportOverride;
  const original = prototype[name];
  if (original) {
    (agent.transport as unknown as TransportOverride)[name] =
      original.bind(agent.transport) as () => Promise<boolean>;
  }
}

describe("GuardAgent redis degradation at start", () => {
  it("degrades to memory-only buffering when the redis adapter cannot be created", async () => {
    const logger = collectingLogger();
    const agent = newAgent({
      logger,
      flushInterval: 300,
      redis: { url: "redis://127.0.0.1:6379" },
    });
    await agent.start();
    expect(logger.warnings().some((m) => m.includes("Redis persistence disabled"))).toBe(true);
    expect(agent.redisHandler).toBeNull();
    await agent.stop();
  });
});

describe("GuardAgent start/stop failure paths", () => {
  it("rethrows transport initialization failures and leaves the agent stopped", async () => {
    const logger = collectingLogger();
    const agent = newAgent({ logger });
    (agent.transport as unknown as { initialize: () => Promise<void> }).initialize = () =>
      Promise.reject(new Error("transport init failed"));
    await expect(agent.start()).rejects.toThrow("transport init failed");
    expect(logger.errors().some((m) => m.includes("Failed to start agent"))).toBe(true);
    expect(agent.getStats().running).toBe(false);
  });

  it("close() is an alias for stop() and flushes what is buffered", async () => {
    const agent = newAgent();
    await agent.sendEvent(event(1));
    await agent.close();
    expect(agent.getStats().running).toBe(false);
    expect(server.requestsFor("/api/v1/events")).toHaveLength(1);
  });
});

describe("GuardAgent loop failure handling", () => {
  it("counts flush loop failures, escalates to error level, and formats non-Error causes", async () => {
    const logger = collectingLogger();
    const agent = newAgent({ flushInterval: 0.05, logger });
    const realFlush = agent.flushBuffer.bind(agent);
    (agent as unknown as { flushBuffer: () => Promise<void> }).flushBuffer = () =>
      Promise.reject("flush-boom");
    try {
      await agent.start();
      await vi.waitFor(() =>
        expect(agent.getStats().loopFailures.flush).toBeGreaterThanOrEqual(3),
      );
      expect(
        logger.warnings().some((m) => m.includes("flush loop failed 1") && m.includes("Error: flush-boom")),
      ).toBe(true);
      expect(logger.errors().some((m) => m.includes("flush loop failed 3"))).toBe(true);
    } finally {
      (agent as unknown as { flushBuffer: () => Promise<void> }).flushBuffer = realFlush;
      await agent.stop();
    }
  });

  it("breaks a loop out when the abort signal fires while the failure is pending", async () => {
    const agent = newAgent({ flushInterval: 0.05 });
    (agent as unknown as { flushBuffer: () => Promise<void> }).flushBuffer = () =>
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error("slow flush boom")), 250);
      });
    await agent.start();
    // First tick starts the slow flush; stop() aborts while it is pending so
    // the eventual rejection lands on an aborted signal and must not count.
    await new Promise((resolve) => setTimeout(resolve, 80));
    await agent.stop().catch(() => {});
    expect(agent.getStats().loopFailures.flush).toBe(0);
  });

  it("counts status loop failures with non-Error causes and escalates to error level", async () => {
    const logger = collectingLogger();
    const agent = newAgent({ logger });
    (agent.config as { statusInterval: number }).statusInterval = 0.05;
    (agent as unknown as { getStatus: () => Promise<unknown> }).getStatus = () =>
      Promise.reject("status-boom");
    await agent.start();
    await vi.waitFor(() =>
      expect(agent.getStats().loopFailures.status).toBeGreaterThanOrEqual(3),
    );
    expect(
      logger.warnings().some((m) => m.includes("status loop failed 1") && m.includes("Error: status-boom")),
    ).toBe(true);
    expect(logger.errors().some((m) => m.includes("status loop failed 3"))).toBe(true);
    expect(agent.getStats().lastStatusPushOk).toBe(false);
    await agent.stop();
  });

  it("breaks the status loop when the abort signal fires mid-failure", async () => {
    const agent = newAgent();
    (agent.config as { statusInterval: number }).statusInterval = 0.05;
    (agent as unknown as { getStatus: () => Promise<unknown> }).getStatus = () =>
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error("slow status boom")), 250);
      });
    await agent.start();
    await new Promise((resolve) => setTimeout(resolve, 80));
    await agent.stop();
    expect(agent.getStats().loopFailures.status).toBe(0);
  });

  it("counts rules loop failures with non-Error causes", async () => {
    const logger = collectingLogger();
    const agent = newAgent({ logger });
    (agent.config as { dynamicRuleInterval: number }).dynamicRuleInterval = 0.05;
    (agent as unknown as { getDynamicRules: () => Promise<unknown> }).getDynamicRules = () =>
      new Promise((_, reject) => {
        setTimeout(() => reject("rules-boom"), 100);
      });
    await agent.start();
    await vi.waitFor(() =>
      expect(agent.getStats().loopFailures.rules).toBeGreaterThanOrEqual(1),
    );
    expect(
      logger.warnings().some((m) => m.includes("rules loop failed 1") && m.includes("Error: rules-boom")),
    ).toBe(true);
    await agent.stop();
  });

  it("breaks the rules loop when the abort signal fires mid-failure", async () => {
    const agent = newAgent();
    (agent.config as { dynamicRuleInterval: number }).dynamicRuleInterval = 0.05;
    (agent as unknown as { getDynamicRules: () => Promise<unknown> }).getDynamicRules = () =>
      new Promise((_, reject) => {
        setTimeout(() => reject(new Error("slow rules boom")), 250);
      });
    await agent.start();
    await new Promise((resolve) => setTimeout(resolve, 80));
    await agent.stop();
    expect(agent.getStats().loopFailures.rules).toBe(0);
  });
});

describe("GuardAgent flush exception paths", () => {
  it("requeues events and rethrows transport exceptions through flushBuffer", async () => {
    const logger = collectingLogger();
    const hookErrors: string[] = [];
    const agent = newAgent({
      flushInterval: 300,
      retryAttempts: 0,
      logger,
      onError: (stage: string) => hookErrors.push(stage),
    });
    overrideTransport(agent, {
      sendEvents: () => Promise.reject(new Error("events transport boom")),
    });
    await agent.sendEvent(event(1));
    await agent.flushBuffer();
    expect(agent.buffer.getBufferSize()).toBe(1);
    expect(agent.eventsFailed).toBe(1);
    expect(logger.errors().some((m) => m.includes("Transport raised sending events"))).toBe(true);
    expect(logger.errors().some((m) => m.includes("Error during buffer flush"))).toBe(true);
    expect(hookErrors).toContain("flush_events");

    restoreTransport(agent, "sendEvents");
    (agent as unknown as { eventsRetryAfter: number }).eventsRetryAfter = 0;
    await agent.flushBuffer();
    expect(agent.eventsSent).toBe(1);
    expect(
      logger.warnings().some((m) => m.includes("Events flush recovered after 1")),
    ).toBe(true);
  });

  it("stringifies non-Error transport rejections on both flush kinds", async () => {
    const logger = collectingLogger();
    const agent = newAgent({ flushInterval: 300, retryAttempts: 0, logger });
    overrideTransport(agent, {
      sendEvents: () => Promise.reject("events-string-boom"),
    });
    await agent.sendEvent(event(1));
    await agent.flushBuffer();
    expect(agent.buffer.getBufferSize()).toBe(1);
    expect(logger.errors().some((m) => m.includes("events-string-boom"))).toBe(true);

    overrideTransport(agent, {
      sendEvents: async () => true,
      sendMetrics: () => Promise.reject("metrics-string-boom"),
    });
    (agent as unknown as { eventsRetryAfter: number }).eventsRetryAfter = 0;
    await agent.sendMetric(metric(1));
    await agent.flushBuffer();
    expect(logger.errors().some((m) => m.includes("metrics-string-boom"))).toBe(true);
    restoreTransport(agent, "sendEvents");
    restoreTransport(agent, "sendMetrics");
  });

  it("reports a null last flush before any flush attempt", async () => {
    const agent = newAgent();
    const status = await agent.getStatus();
    expect(status.lastFlush).toBeNull();
  });

  it("confirms evicted keys when a failed event requeue overflows the buffer", async () => {
    const redis = new FakeRedisHandler();
    const logger = collectingLogger();
    const agent = newAgent({
      bufferSize: 3,
      highWatermarkRatio: 0.9,
      flushInterval: 300,
      retryAttempts: 0,
      logger,
    });
    await agent.initializeRedis(redis);
    await agent.sendEvent(event(1));
    await agent.sendEvent(event(2));
    overrideTransport(agent, {
      sendEvents: async () => {
        // Two more items land while the failed batch is "on the wire": the
        // requeue must evict the newest tail and confirm its redis key.
        await agent.sendEvent(event(3));
        await agent.sendEvent(event(4));
        throw new Error("events boom");
      },
    });
    await agent.flushBuffer();
    expect(agent.buffer.getBufferSize()).toBe(3);
    expect(logger.warnings().some((m) => m.includes("Failed to send 2 events"))).toBe(true);
    // Four keys were persisted; the evicted tail was confirmed (deleted).
    expect(redis.store.size).toBe(3);
    restoreTransport(agent, "sendEvents");
  });

  it("suppresses the metrics flush while the retry-after window is active", async () => {
    const agent = newAgent({ flushInterval: 300, retryAttempts: 0 });
    overrideTransport(agent, {
      sendMetrics: () => Promise.reject(new Error("metrics transport boom")),
    });
    await agent.sendMetric(metric(1));
    await agent.flushBuffer();
    expect(agent.metricsFailed).toBe(1);
    expect(agent.buffer.getBufferSize()).toBe(1);

    overrideTransport(agent, {
      sendMetrics: async () => {
        throw new Error("metrics must not be called while backing off");
      },
    });
    (agent as unknown as { metricsRetryAfter: number }).metricsRetryAfter = nowSeconds() + 60;
    await agent.flushBuffer();
    expect(agent.metricsFailed).toBe(1);
  });

  it("requeues metrics, confirms evicted keys, and recovers after transport exceptions", async () => {
    const redis = new FakeRedisHandler();
    const logger = collectingLogger();
    const hookErrors: string[] = [];
    const agent = newAgent({
      bufferSize: 3,
      highWatermarkRatio: 0.9,
      flushInterval: 300,
      retryAttempts: 0,
      logger,
      onError: (stage: string) => hookErrors.push(stage),
    });
    await agent.initializeRedis(redis);
    await agent.sendMetric(metric(1));
    await agent.sendMetric(metric(2));
    overrideTransport(agent, {
      sendMetrics: async () => {
        await agent.sendMetric(metric(3));
        await agent.sendMetric(metric(4));
        throw new Error("metrics transport boom");
      },
    });
    await agent.flushBuffer();
    expect(agent.buffer.getBufferSize()).toBe(3);
    expect(logger.warnings().some((m) => m.includes("Failed to send 2 metrics"))).toBe(true);
    expect(logger.errors().some((m) => m.includes("Transport raised sending metrics"))).toBe(true);
    expect(logger.errors().some((m) => m.includes("Error during buffer flush"))).toBe(true);
    expect(hookErrors).toContain("flush_metrics");
    expect(redis.store.size).toBe(3);

    restoreTransport(agent, "sendMetrics");
    (agent as unknown as { metricsRetryAfter: number }).metricsRetryAfter = 0;
    await agent.flushBuffer();
    expect(agent.metricsSent).toBe(3);
    expect(
      logger.warnings().some((m) => m.includes("Metrics flush recovered after 1")),
    ).toBe(true);
  });
});

describe("GuardAgent flush failure streaks without exceptions", () => {
  it("warns once for a streak of events failures and never raises a false send", async () => {
    const logger = collectingLogger();
    const hookErrors: string[] = [];
    const agent = newAgent({
      flushInterval: 300,
      retryAttempts: 0,
      logger,
      onError: (stage: string) => hookErrors.push(stage),
    });
    // Transient failure the transport reports as false instead of throwing:
    // the batch requeues with no exception routed through flushBuffer.
    overrideTransport(agent, { sendEvents: async () => false });
    await agent.sendEvent(event(1));
    await agent.flushBuffer();
    expect(agent.eventsFailed).toBe(1);
    expect(agent.buffer.getBufferSize()).toBe(1);
    expect(
      logger.warnings().filter((m) => m.includes("Failed to send 1 events")),
    ).toHaveLength(1);
    expect(logger.errors().some((m) => m.includes("Transport raised sending events"))).toBe(
      false,
    );
    expect(hookErrors).not.toContain("flush_events");

    // Second consecutive failure: the backoff warning stays at the first one.
    (agent as unknown as { eventsRetryAfter: number }).eventsRetryAfter = 0;
    await agent.flushBuffer();
    expect(agent.eventsFailed).toBe(2);
    expect(
      logger.warnings().filter((m) => m.includes("Failed to send 1 events")),
    ).toHaveLength(1);
  });

  it("warns once for a streak of metrics failures reported as false", async () => {
    const logger = collectingLogger();
    const agent = newAgent({ flushInterval: 300, retryAttempts: 0, logger });
    overrideTransport(agent, { sendMetrics: async () => false });
    await agent.sendMetric(metric(1));
    await agent.flushBuffer();
    expect(agent.metricsFailed).toBe(1);
    expect(
      logger.warnings().filter((m) => m.includes("Failed to send 1 metrics")),
    ).toHaveLength(1);
    expect(logger.errors().some((m) => m.includes("Transport raised sending metrics"))).toBe(
      false,
    );

    (agent as unknown as { metricsRetryAfter: number }).metricsRetryAfter = 0;
    await agent.flushBuffer();
    expect(agent.metricsFailed).toBe(2);
    expect(
      logger.warnings().filter((m) => m.includes("Failed to send 1 metrics")),
    ).toHaveLength(1);
    restoreTransport(agent, "sendMetrics");
  });

  it("degrades status when the failure rate climbs above ten percent", async () => {
    const agent = newAgent({ flushInterval: 300, retryAttempts: 0 });
    overrideTransport(agent, { sendEvents: async () => false });
    await agent.sendEvent(event(1));
    await agent.flushBuffer();
    const degraded = await agent.getStatus();
    expect(degraded.status).toBe("degraded");
    expect(degraded.eventsFailed).toBe(1);
    expect(degraded.errors.some((e) => e.includes("High failure rate: 100.0%"))).toBe(true);
    restoreTransport(agent, "sendEvents");

    // Once successful sends dilute the failure rate back under ten percent,
    // the same snapshot reports healthy again.
    for (let i = 2; i <= 11; i++) await agent.sendEvent(event(i));
    (agent as unknown as { eventsRetryAfter: number }).eventsRetryAfter = 0;
    await agent.flushBuffer();
    expect(agent.eventsSent).toBe(11);
    const healthy = await agent.getStatus();
    expect(healthy.status).toBe("healthy");
    expect(healthy.errors).toEqual([]);
  });
});

describe("GuardAgent dynamic rules cache", () => {
  it("serves the cached rules when the fetch fails and null when there is no cache", async () => {
    const agent = newAgent();
    overrideTransport(agent, {
      // fetchDynamicRules is not part of TransportOverride; cast below.
    });
    const realFetchRules =
      HttpTransport.prototype.fetchDynamicRules.bind(agent.transport);
    (agent.transport as unknown as { fetchDynamicRules: () => Promise<never> }).fetchDynamicRules =
      () => Promise.reject(new Error("rules down"));
    expect(await agent.getDynamicRules()).toBeNull();

    (agent.transport as unknown as { fetchDynamicRules: () => Promise<unknown> }).fetchDynamicRules =
      realFetchRules as () => Promise<never>;
    const rules = await agent.getDynamicRules();
    expect(rules).not.toBeNull();
    expect(agent.getStats().rulesFetched).toBe(1);

    (agent.transport as unknown as { fetchDynamicRules: () => Promise<never> }).fetchDynamicRules =
      () => Promise.reject(new Error("rules down again"));
    expect(await agent.getDynamicRules()).toBe(rules);
  });
});

describe("GuardAgent status and health edges", () => {
  it("reports degraded on an open circuit breaker and a non-null last flush", async () => {
    const agent = newAgent();
    await agent.sendEvent(event(1));
    await agent.flushBuffer();
    agent.transport.circuitBreaker.state = "OPEN";
    const status = await agent.getStatus();
    expect(status.status).toBe("degraded");
    expect(status.errors).toContain("Transport circuit breaker is open");
    expect(status.lastFlush).toBeInstanceOf(Date);
    agent.transport.circuitBreaker.state = "CLOSED";
  });

  it("healthCheck gates on circuit breaker, buffer pressure, and failure rate", async () => {
    // Dead endpoint: the watermark flush fails and requeues, so the buffer
    // genuinely climbs to capacity.
    const agent = newAgent({ endpoint: "http://127.0.0.1:9", bufferSize: 10, retryAttempts: 0 });
    (agent as unknown as { running: boolean }).running = true;
    expect(await agent.healthCheck()).toBe(true);

    for (let i = 0; i < 10; i++) await agent.sendEvent(event(i));
    await new Promise((resolve) => setTimeout(resolve, 120));
    expect(agent.buffer.getBufferSize()).toBe(10);
    expect(await agent.healthCheck()).toBe(false);

    await agent.buffer.flushEventsWithKeys();
    (agent as unknown as { eventsFailed: number }).eventsFailed = 3;
    expect(await agent.healthCheck()).toBe(false);
    (agent as unknown as { eventsSent: number }).eventsSent = 10;
    expect(await agent.healthCheck()).toBe(true);

    agent.transport.circuitBreaker.state = "OPEN";
    expect(await agent.healthCheck()).toBe(false);
    agent.transport.circuitBreaker.state = "CLOSED";
  });

  it("reports unhealthy when transport stats explode", async () => {
    const logger = collectingLogger();
    const agent = newAgent({ logger });
    (agent as unknown as { running: boolean }).running = true;
    (agent.transport as unknown as { getStats: () => never }).getStats = () => {
      throw new Error("stats boom");
    };
    expect(await agent.healthCheck()).toBe(false);
    expect(logger.errors().some((m) => m.includes("Error during health check"))).toBe(true);
  });

  it("collapses unscannable metadata and tags to empty maps at ingest", async () => {
    const agent = newAgent();
    const explodingMetadata = {
      get authorization(): string {
        throw new Error("metadata getter exploded");
      },
    };
    await agent.sendEvent(
      new SecurityEvent({
        idempotencyKey: randomUUID(),
        timestamp: new Date(),
        eventType: "rate_limited",
        metadata: explodingMetadata,
      }),
    );
    const [events] = await agent.buffer.flushEventsWithKeys();
    expect(events[0]?.metadata).toEqual({});

    await agent.sendMetric(
      new SecurityMetric({
        timestamp: new Date(),
        metricType: "request_count",
        value: 1,
        tags: { n: 5 } as unknown as Record<string, string>,
      }),
    );
    await agent.sendMetric(
      new SecurityMetric({
        timestamp: new Date(),
        metricType: "request_count",
        value: 2,
        tags: {
          get authorization(): string {
            throw new Error("tags getter exploded");
          },
        } as unknown as Record<string, string>,
      }),
    );
    const [metrics] = await agent.buffer.flushMetricsWithKeys();
    expect(metrics[0]?.tags).toEqual({ n: "5" });
    expect(metrics[1]?.tags).toEqual({});
  });
});
