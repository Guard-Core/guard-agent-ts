/**
 * White-box coverage for HttpTransport failure paths the contract tests
 * cannot reach deterministically: local rate-limiter stalls, request
 * timeouts, serialization aborts, status and rules retry exhaustion, the
 * unsupported-method guard, response-body read failures, and the final
 * send catches.
 */
import { createServer, type Server, type IncomingMessage } from "node:http";
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";

import { resolveAgentConfig, type AgentConfigInput } from "../src/config.js";
import { normalizeSecurityEvent, normalizeSecurityMetric } from "../src/models.js";
import { HttpTransport } from "../src/transport.js";
import { RateLimiter } from "../src/utils.js";
import { MockIngestionServer } from "./helpers/mock-server.js";
import { collectingLogger, makeEvent } from "./helpers/test-utils.js";

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

function transport(overrides: Partial<AgentConfigInput> = {}): HttpTransport {
  const config = resolveAgentConfig({
    apiKey: API_KEY,
    endpoint: baseUrl,
    retryAttempts: 0,
    backoffFactor: 0.01,
    timeout: 2,
    logger: collectingLogger(),
    ...overrides,
  });
  return new HttpTransport(config);
}

function events(count: number, padLength = 0) {
  return Array.from({ length: count }, (_, index) =>
    normalizeSecurityEvent({
      ...makeEvent(padLength),
      eventType: `event_${index}`,
    }),
  );
}

function bigMetric(value: number, padLength = 600) {
  return normalizeSecurityMetric({
    metricType: "bandwidth_usage",
    value,
    timestamp: new Date(),
    tags: { pad: "x".repeat(padLength) },
  });
}

/** Run a test against a dedicated mock server (e.g. with a custom 413 cap). */
async function withServer(
  options: ConstructorParameters<typeof MockIngestionServer>[0],
  fn: (scoped: MockIngestionServer, url: string) => Promise<void>,
): Promise<void> {
  const scoped = new MockIngestionServer(options);
  const url = await scoped.start();
  try {
    await fn(scoped, url);
  } finally {
    await scoped.stop();
  }
}

/** A server that accepts connections and never answers, for timeout tests. */
async function withHangingServer(fn: (port: number) => Promise<void>): Promise<void> {
  const hanging = createServer((_request: IncomingMessage, _response) => {
    // Intentionally never ends the response.
  });
  await new Promise<void>((resolve) => hanging.listen(0, "127.0.0.1", resolve));
  const port = (hanging.address() as AddressInfo).port;
  try {
    await fn(port);
  } finally {
    await new Promise((resolve) => hanging.close(resolve));
  }
}

describe("HttpTransport lifecycle", () => {
  it("initializes once and reports the session state", async () => {
    const client = transport();
    expect(client.getStats().sessionClosed).toBe(true);
    await client.initialize();
    await client.initialize();
    expect(client.getStats().sessionClosed).toBe(false);
    await client.close();
    expect(client.getStats().sessionClosed).toBe(true);
  });

  it("rejects unsupported methods and POST batches without a payload", async () => {
    const client = transport();
    await client.initialize();
    const cast = client as unknown as {
      makeRequest: (
        method: "POST" | "GET" | "DELETE",
        endpoint: string,
        data: Record<string, unknown> | null,
      ) => Promise<unknown>;
    };
    await expect(cast.makeRequest("DELETE", "/api/v1/events", null)).rejects.toThrow(
      "Unsupported method: DELETE",
    );
    await expect(cast.makeRequest("POST", "/api/v1/events", null)).rejects.toThrow(
      "Unsupported method: POST",
    );
  });

  it("labels request timeouts distinctly in the error log", async () => {
    const logger = collectingLogger();
    await withHangingServer(async (port) => {
      const client = transport({
        endpoint: `http://127.0.0.1:${port}`,
        timeout: 0.1,
        retryAttempts: 0,
        logger,
      });
      expect(await client.sendEvents(events(1))).toBe(false);
    });
    expect(logger.errors().some((m) => m.includes("Timeout error"))).toBe(true);
    expect(logger.errors().some((m) => m.includes("HTTP client error"))).toBe(false);
  });
});

describe("HttpTransport serialization aborts", () => {
  it("aborts the POST and retains the batch when serialization fails", async () => {
    const hookErrors: string[] = [];
    const logger = collectingLogger();
    const client = transport({ logger, onError: (stage: string) => hookErrors.push(stage) });
    await client.initialize();
    const circular: Record<string, unknown> = {};
    circular["self"] = circular;
    const result = await (
      client as unknown as {
        postJson: (url: string, data: Record<string, unknown>) => Promise<unknown>;
      }
    ).postJson(`${baseUrl}/api/v1/events`, { events: [circular] });
    expect(result).toBe(false);
    expect(server.requestsFor("/api/v1/events")).toHaveLength(0);
    expect(logger.errors().some((m) => m.includes("payload serialization failed"))).toBe(true);
    expect(hookErrors).toContain("transport_send");
  });

  it("aborts the encrypted POST when the envelope cannot be serialized", async () => {
    const hookErrors: string[] = [];
    const logger = collectingLogger();
    const client = transport({
      logger,
      projectEncryptionKey: randomBytes(32).toString("base64url"),
      onError: (stage: string) => hookErrors.push(stage),
    });
    await client.initialize();
    const circular: Record<string, unknown> = {};
    circular["self"] = circular;
    const result = await (
      client as unknown as {
        postEncrypted: (data: Record<string, unknown>) => Promise<unknown>;
      }
    ).postEncrypted({ batch_id: circular, events: [], metrics: [] });
    expect(result).toBe(false);
    expect(logger.errors().some((m) => m.includes("Aborting encrypted POST"))).toBe(true);
    expect(hookErrors).toContain("encryption");
  });

  it("refuses to post an encrypted batch without an initialized encryptor", async () => {
    const client = transport();
    await expect(
      (
        client as unknown as {
          postEncrypted: (data: Record<string, unknown>) => Promise<unknown>;
        }
      ).postEncrypted({ events: [] }),
    ).rejects.toThrow("Encryptor not initialized");
  });

  it("routes non-telemetry endpoints through the plaintext POST path", async () => {
    const client = transport();
    await client.initialize();
    const result = await (
      client as unknown as {
        makeRequest: (
          method: "POST" | "GET",
          endpoint: string,
          data: Record<string, unknown> | null,
        ) => Promise<unknown>;
      }
    ).makeRequest("POST", "/api/v1/status", { status: "healthy" });
    expect(typeof result === "object" || typeof result === "boolean").toBe(true);
    expect(server.requestsFor("/api/v1/status")).toHaveLength(1);
  });
});

describe("HttpTransport local rate limiter", () => {
  it("waits and retries when the local limiter stalls a POST", async () => {
    const logger = collectingLogger();
    const client = transport({ retryAttempts: 0, logger });
    client.rateLimiter = new RateLimiter(0, 0.02);
    expect(await client.sendEvents(events(1))).toBe(false);
    expect(logger.warnings().some((m) => m.includes("Rate limit exceeded"))).toBe(true);
    expect(server.requestsFor("/api/v1/events")).toHaveLength(0);
  });

  it("waits and retries when the local limiter stalls a GET", async () => {
    const logger = collectingLogger();
    const client = transport({ retryAttempts: 0, logger });
    client.rateLimiter = new RateLimiter(0, 0.02);
    expect(await client.fetchDynamicRules()).toBeNull();
    expect(logger.warnings().some((m) => m.includes("Rate limit exceeded"))).toBe(true);
  });
});

describe("HttpTransport status and rules retry exhaustion", () => {
  it("reports failure when the status endpoint is permanently rejected", async () => {
    const logger = collectingLogger();
    const client = transport({ logger });
    server.behavior = () => ({ status: 400, body: { detail: "bad status payload" } });
    const status = {
      timestamp: new Date(),
      status: "healthy" as const,
      uptime: 1,
      eventsSent: 0,
      eventsFailed: 0,
      bufferSize: 0,
      lastFlush: null,
      errors: [],
    };
    expect(await client.sendStatus(status)).toBe(false);
    expect(logger.errors().some((m) => m.includes("Failed to send status"))).toBe(true);
  });

  it("exhausts retries when the rules endpoint keeps answering 429", async () => {
    const logger = collectingLogger();
    const client = transport({ retryAttempts: 1, backoffFactor: 0.001, logger });
    server.behavior = () => ({
      status: 429,
      body: { detail: "slow down" },
      headers: { "Retry-After": "0" },
    });
    expect(await client.fetchDynamicRules()).toBeNull();
    expect(client.requestsFailed).toBe(1);
    expect(
      logger.warnings().some((m) => m.includes("Server rate-limited GET /api/v1/rules")),
    ).toBe(true);
  });

  it("exhausts retries when the rules endpoint is unreachable", async () => {
    const logger = collectingLogger();
    const client = transport({
      endpoint: "http://127.0.0.1:9",
      retryAttempts: 1,
      backoffFactor: 0.001,
      logger,
    });
    expect(await client.fetchDynamicRules()).toBeNull();
    expect(client.requestsFailed).toBe(1);
    expect(logger.warnings().some((m) => m.includes("GET attempt 1 failed"))).toBe(true);
  });

  it("returns null and logs when the rules payload cannot be normalized", async () => {
    const logger = collectingLogger();
    const client = transport({ logger });
    server.behavior = () => ({ status: 200, body: { ip_blacklist: 5 } });
    expect(await client.fetchDynamicRules()).toBeNull();
    expect(logger.errors().some((m) => m.includes("Failed to fetch dynamic rules"))).toBe(true);
  });
});

describe("HttpTransport final send catches", () => {
  it("accepts empty batches without any request", async () => {
    const client = transport();
    expect(await client.sendEvents([])).toBe(true);
    expect(await client.sendMetrics([])).toBe(true);
    expect(server.requestsFor("/api/v1/events")).toHaveLength(0);
    expect(server.requestsFor("/api/v1/metrics")).toHaveLength(0);
  });

  it("reports failure when the events retry loop itself explodes", async () => {
    const logger = collectingLogger();
    const client = transport({ logger });
    (client as unknown as { sendWithRetry: () => Promise<boolean> }).sendWithRetry = () =>
      Promise.reject(new Error("retry loop boom"));
    expect(await client.sendEvents(events(1))).toBe(false);
    expect(client.requestsFailed).toBe(1);
    expect(logger.errors().some((m) => m.includes("Failed to send events"))).toBe(true);
  });

  it("reports failure when the metrics retry loop itself explodes", async () => {
    const logger = collectingLogger();
    const client = transport({ logger });
    (client as unknown as { sendWithRetry: () => Promise<boolean> }).sendWithRetry = () =>
      Promise.reject(new Error("retry loop boom"));
    expect(await client.sendMetrics([bigMetric(1)])).toBe(false);
    expect(client.requestsFailed).toBe(1);
    expect(logger.errors().some((m) => m.includes("Failed to send metrics"))).toBe(true);
  });
});

describe("HttpTransport metrics 413 split-or-drop", () => {
  it("splits oversized metric batches and delivers both halves", async () => {
    await withServer({ apiKey: API_KEY, maxPayloadBytes: 3000 }, async (scoped, url) => {
      const client = transport({ endpoint: url, retryAttempts: 0 });
      const batch = [bigMetric(1), bigMetric(2), bigMetric(3), bigMetric(4)];
      expect(await client.sendMetrics(batch)).toBe(true);
      const sizes = scoped.requests
        .filter((request) => request.url === "/api/v1/metrics")
        .map((request) => (request.body as { metrics?: unknown[] } | null)?.metrics?.length ?? 0)
        .filter((size) => size > 0);
      expect(sizes).toEqual([2, 2]);
    });
  });

  it("drops an oversized singleton metric and reports success", async () => {
    await withServer({ apiKey: API_KEY, maxPayloadBytes: 300 }, async (scoped, url) => {
      const hookErrors: string[] = [];
      const client = transport({
        endpoint: url,
        retryAttempts: 0,
        onError: (stage: string) => hookErrors.push(stage),
      });
      expect(await client.sendMetrics([bigMetric(1)])).toBe(true);
      expect(scoped.requestsFor("/api/v1/metrics")).toHaveLength(1);
      expect(client.requestsFailed).toBe(1);
      expect(hookErrors).toContain("transport_send");
    });
  });

  it("drops permanently rejected metric batches without retrying", async () => {
    const hookErrors: string[] = [];
    const client = transport({
      retryAttempts: 3,
      onError: (stage: string) => hookErrors.push(stage),
    });
    server.behavior = () => ({ status: 422, body: { detail: "invalid metrics" } });
    expect(await client.sendMetrics([bigMetric(1)])).toBe(true);
    expect(server.requestsFor("/api/v1/metrics")).toHaveLength(1);
    expect(client.requestsFailed).toBe(1);
    expect(hookErrors).toContain("transport_send");
  });
});

describe("HttpTransport response body edge", () => {
  it("summarizes an empty body when the response stream cannot be read", async () => {
    const client = transport();
    await client.initialize();
    const broken = new Response("ignored", { status: 500 });
    Object.defineProperty(broken, "text", {
      value: () => Promise.reject(new Error("stream broken")),
    });
    await expect(
      (
        client as unknown as {
          handleResponse: (response: Response, url: string) => Promise<unknown>;
        }
      ).handleResponse(broken, `${baseUrl}/api/v1/events`),
    ).rejects.toThrow("Server error 500");
  });
});
