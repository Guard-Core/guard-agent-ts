/**
 * Coverage for the redis seam: the IoredisHandler key operations and close
 * fallback, plus the ioredis module-shape tolerance in
 * createIoredisHandler (namespace, default, double-wrapped, missing, and
 * throwing interop shapes) driven through a mocked "ioredis" module.
 */
import { describe, expect, it, vi } from "vitest";

import { IoredisHandler } from "../src/redis.js";
import { collectingLogger, type CollectingLogger } from "./helpers/test-utils.js";

const ioredisState = vi.hoisted(() => ({
  lastUrl: null as string | null,
  lastOptions: null as Record<string, unknown> | null,
}));

type IoredisShape =
  | "default-fn"
  | "nested-default"
  | "empty"
  | "default-object"
  | "boom";

/**
 * Install a per-test "ioredis" mock exposing one of the module shapes
 * connectIoredis tolerates. vi.doMock pairs with the fresh dynamic import of
 * the redis module so every test gets its own factory evaluation.
 */
function mockIoredis(mode: IoredisShape): void {
  vi.resetModules();
  vi.doMock("ioredis", () => {
    class FakeRedis {
      constructor(url: string, options: Record<string, unknown>) {
        ioredisState.lastUrl = url;
        ioredisState.lastOptions = options;
      }
    }
    switch (mode) {
      case "nested-default":
        return { default: { default: FakeRedis } };
      case "empty":
        return {};
      case "default-object":
        return { default: {} };
      case "boom":
        throw new Error("ioredis import failed");
      default:
        return { default: FakeRedis };
    }
  });
}

interface ClientCalls {
  method: string;
  args: unknown[];
}

function makeClient(overrides: Record<string, unknown> = {}): {
  client: Record<string, unknown>;
  calls: ClientCalls[];
  store: Map<string, string>;
} {
  const calls: ClientCalls[] = [];
  const store = new Map<string, string>();
  const client: Record<string, unknown> = {
    get: async (key: string) => {
      calls.push({ method: "get", args: [key] });
      return store.get(key) ?? null;
    },
    set: async (...args: unknown[]) => {
      calls.push({ method: "set", args });
      const [key, value] = args as [string, string];
      store.set(key, value);
      return "OK";
    },
    del: async (key: string) => {
      calls.push({ method: "del", args: [key] });
      return store.delete(key) ? 1 : 0;
    },
    keys: async (pattern: string) => {
      calls.push({ method: "keys", args: [pattern] });
      const prefix = pattern.replace(/\*/g, "");
      return [...store.keys()].filter((key) => key.startsWith(prefix));
    },
    ping: async () => {
      calls.push({ method: "ping", args: [] });
      return "PONG";
    },
    quit: async () => {
      calls.push({ method: "quit", args: [] });
      return "OK";
    },
    disconnect: () => {
      calls.push({ method: "disconnect", args: [] });
    },
    ...overrides,
  };
  return { client, calls, store };
}

type HandlerClient = ConstructorParameters<typeof IoredisHandler>[0];

function asClient(client: Record<string, unknown>): HandlerClient {
  return client as unknown as HandlerClient;
}

describe("IoredisHandler key operations", () => {
  it("namespaces keys under the configured prefix and honours TTLs", async () => {
    const { client, calls } = makeClient();
    const handler = new IoredisHandler(asClient(client), {
      keyPrefix: "pfx",
      commandTimeoutMs: 250,
      logger: collectingLogger(),
    });
    await handler.setKey("agent_events", "k1", "v1", 60);
    await handler.setKey("agent_events", "k2", "v2");
    await handler.setKey("agent_events", "k3", "v3", null);
    const setCalls = calls.filter((call) => call.method === "set");
    expect(setCalls[0]?.args).toEqual(["pfx:agent_events:k1", "v1", "EX", 60]);
    expect(setCalls[1]?.args).toEqual(["pfx:agent_events:k2", "v2"]);
    expect(setCalls[2]?.args).toEqual(["pfx:agent_events:k3", "v3"]);

    expect(await handler.getKey("agent_events", "k1")).toBe("v1");
    expect(await handler.delete("agent_events", "k1")).toBe(1);
    expect(await handler.delete("agent_events", "missing")).toBe(0);
    expect(await handler.keys("agent_events:*")).toEqual([
      "pfx:agent_events:k2",
      "pfx:agent_events:k3",
    ]);
  });

  it("falls back to the default prefix and timeout", async () => {
    const { client, calls } = makeClient();
    const handler = new IoredisHandler(asClient(client), {
      logger: collectingLogger(),
    });
    await handler.getKey("agent_events", "k1");
    expect(calls[0]?.args).toEqual(["guard:agent:agent_events:k1"]);
  });

  it("pings on initialize", async () => {
    const { client, calls } = makeClient();
    const handler = new IoredisHandler(asClient(client), {
      logger: collectingLogger(),
    });
    await handler.initialize();
    expect(calls.some((call) => call.method === "ping")).toBe(true);
  });

  it("routes connection errors through the logger", () => {
    const listeners: Record<string, (error: Error) => void> = {};
    const { client } = makeClient({
      on: (event: string, listener: (error: Error) => void) => {
        listeners[event] = listener;
      },
    });
    const logger = collectingLogger();
    void new IoredisHandler(asClient(client), { logger });
    listeners["error"]?.(new Error("connection reset"));
    expect(logger.warnings().join("\n")).toContain("redis connection error");
  });

  it("quits cleanly on close", async () => {
    const { client, calls } = makeClient();
    const handler = new IoredisHandler(asClient(client), {
      logger: collectingLogger(),
    });
    await handler.close();
    expect(calls.some((call) => call.method === "quit")).toBe(true);
    expect(calls.some((call) => call.method === "disconnect")).toBe(false);
  });

  it("falls back to disconnect when quit fails", async () => {
    const { client, calls } = makeClient({
      quit: () => Promise.reject(new Error("quit refused")),
    });
    const logger = collectingLogger();
    const handler = new IoredisHandler(asClient(client), { logger });
    await handler.close();
    expect(calls.some((call) => call.method === "disconnect")).toBe(true);
    expect(logger.warnings().join("\n")).toContain("redis.close failed");
  });
});

describe("createIoredisHandler module interop", () => {
  async function freshCreate(): Promise<
    typeof import("../src/redis.js")["createIoredisHandler"]
  > {
    const module = await import("../src/redis.js");
    return module.createIoredisHandler;
  }

  it("resolves the default-export constructor", async () => {
    mockIoredis("default-fn");
    const create = await freshCreate();
    const handler = await create({
      url: "redis://localhost:6379/2",
      password: "secret",
      db: 2,
      commandTimeoutMs: 250,
      logger: collectingLogger(),
    });
    expect(typeof handler.getKey).toBe("function");
    expect(ioredisState.lastUrl).toBe("redis://localhost:6379/2");
    expect(ioredisState.lastOptions).toMatchObject({
      password: "secret",
      db: 2,
      commandTimeout: 250,
      maxRetriesPerRequest: 1,
      lazyConnect: false,
      enableOfflineQueue: true,
    });
  });

  it("unwraps a double-wrapped default export", async () => {
    mockIoredis("nested-default");
    const create = await freshCreate();
    const handler = await create({ url: "redis://localhost:6379", logger: collectingLogger() });
    expect(typeof handler.delete).toBe("function");
  });

  it("throws a configuration error when no constructor can be found", async () => {
    mockIoredis("empty");
    const create = await freshCreate();
    await expect(
      create({ url: "redis://localhost:6379", logger: collectingLogger() }),
    ).rejects.toThrow("Redis persistence requested but ioredis is not installed");
  });

  it("throws a configuration error when the default export is not a constructor", async () => {
    mockIoredis("default-object");
    const create = await freshCreate();
    await expect(
      create({ url: "redis://localhost:6379", logger: collectingLogger() }),
    ).rejects.toThrow("Redis persistence requested but ioredis is not installed");
  });

  it("surfaces import failures as the same configuration error", async () => {
    mockIoredis("boom");
    const create = await freshCreate();
    await expect(
      create({ url: "redis://localhost:6379", logger: collectingLogger() }),
    ).rejects.toThrow("Redis persistence requested but ioredis is not installed");
  });
});
