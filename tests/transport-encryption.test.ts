/**
 * Encrypted-ingest transport contract: the /api/v1/events/encrypted envelope,
 * the no-plaintext-fallback startup rule, and the encryption failure paths.
 * The encryption module is partially mocked so verifyKey()/constructor
 * failures can be injected; every other export stays the real implementation.
 */
import { createHmac } from "node:crypto";
import { randomBytes } from "node:crypto";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { resolveAgentConfig, type AgentConfigInput } from "../src/config.js";
import type { PayloadEncryptor as PayloadEncryptorType } from "../src/encryption.js";
import { EncryptionConfigError } from "../src/encryption.js";
import { normalizeSecurityEvent, normalizeSecurityMetric } from "../src/models.js";
import { HttpTransport } from "../src/transport.js";
import { MockIngestionServer } from "./helpers/mock-server.js";
import { collectingLogger, makeEvent } from "./helpers/test-utils.js";

const encryptionState = vi.hoisted(() => ({
  verifyKeyResult: true,
  createError: null as Error | null,
}));

vi.mock("../src/encryption.js", async (importOriginal) => {
  const actual =
    await importOriginal<typeof import("../src/encryption.js")>();
  return {
    ...actual,
    createEncryptor: (projectKey: string | null | undefined) => {
      if (encryptionState.createError) throw encryptionState.createError;
      const encryptor = actual.createEncryptor(projectKey);
      if (encryptor) {
        Object.defineProperty(encryptor, "verifyKey", {
          value: () => encryptionState.verifyKeyResult,
        });
      }
      return encryptor;
    },
  };
});

const API_KEY = "test-api-key-1234";
const VALID_KEY = randomBytes(32).toString("base64url");

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
  encryptionState.verifyKeyResult = true;
  encryptionState.createError = null;
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

async function realEncryptor(): Promise<typeof PayloadEncryptorType> {
  return (await vi.importActual<typeof import("../src/encryption.js")>(
    "../src/encryption.js",
  )).PayloadEncryptor;
}

describe("HttpTransport encryption startup rules", () => {
  it("refuses to start when the key fails its round-trip verification", async () => {
    encryptionState.verifyKeyResult = false;
    const client = transport({ projectEncryptionKey: VALID_KEY });
    await expect(client.initialize()).rejects.toThrow(EncryptionConfigError);
  });

  it("wraps an unusable encryptor as an EncryptionConfigError", async () => {
    encryptionState.createError = new Error("encryptor exploded");
    const client = transport({ projectEncryptionKey: VALID_KEY });
    await expect(client.initialize()).rejects.toThrow(EncryptionConfigError);
  });
});

describe("HttpTransport encrypted ingest", () => {
  it("posts event batches encrypted, gzipped, and signed to /events/encrypted", async () => {
    const client = transport({
      projectEncryptionKey: VALID_KEY,
      payloadSigningSecret: "enc-secret",
      compressionThreshold: 256,
    });
    expect(await client.sendEvents(events(2, 300))).toBe(true);

    const [request] = server.requestsFor("/api/v1/events/encrypted");
    expect(request?.contentEncoding).toBe("gzip");
    expect(request?.headers["x-payload-signature"]).toMatch(/^v1=/);
    const expected = `v1=${
      createHmac("sha256", "enc-secret")
        .update(JSON.stringify(request?.body))
        .digest("hex")
    }`;
    expect(request?.headers["x-payload-signature"]).toBe(expected);

    const body = request?.body as {
      encrypted_payload: string;
      batch_id: string;
      agent_version: string;
      guard_version: string | null;
      guard_core_version: string | null;
    };
    const Encryptor = await realEncryptor();
    const decrypted = new Encryptor(VALID_KEY).decrypt(body.encrypted_payload);
    expect(decrypted["events"] as unknown[]).toHaveLength(2);
    expect(decrypted["metrics"] as unknown[]).toEqual([]);
    expect(body.batch_id).toBeTruthy();
    expect(body.agent_version).toMatch(/^\d+\.\d+\.\d+/);
    expect(body.guard_version).toBeNull();
    expect(body.guard_core_version).toBeNull();
  });

  it("posts metric batches encrypted as well", async () => {
    const client = transport({ projectEncryptionKey: VALID_KEY });
    expect(
      await client.sendMetrics([
        normalizeSecurityMetric({
          metricType: "request_count",
          value: 9,
          timestamp: new Date(),
        }),
      ]),
    ).toBe(true);
    const [request] = server.requestsFor("/api/v1/events/encrypted");
    const body = request?.body as { encrypted_payload: string };
    const Encryptor = await realEncryptor();
    const decrypted = new Encryptor(VALID_KEY).decrypt(body.encrypted_payload);
    expect((decrypted["metrics"] as { value: number }[])[0]?.value).toBe(9);
  });

  it("posts an empty envelope when the batch carries no arrays", async () => {
    const client = transport({ projectEncryptionKey: VALID_KEY });
    await client.initialize();
    const result = await (
      client as unknown as {
        postEncrypted: (data: Record<string, unknown>) => Promise<unknown>;
      }
    ).postEncrypted({ batch_id: "batch-1" });
    expect(result).not.toBe(false);
    const [request] = server.requestsFor("/api/v1/events/encrypted");
    const body = request?.body as { encrypted_payload: string };
    const Encryptor = await realEncryptor();
    const decrypted = new Encryptor(VALID_KEY).decrypt(body.encrypted_payload);
    expect(decrypted["events"]).toEqual([]);
    expect(decrypted["metrics"]).toEqual([]);
  });

  it("leaves status pushes plaintext even when encryption is enabled", async () => {
    const client = transport({ projectEncryptionKey: VALID_KEY });
    expect(
      await client.sendStatus({
        timestamp: new Date(),
        status: "healthy",
        uptime: 1,
        eventsSent: 0,
        eventsFailed: 0,
        bufferSize: 0,
        lastFlush: null,
        errors: [],
      }),
    ).toBe(true);
    const [request] = server.requestsFor("/api/v1/status");
    expect(request?.contentEncoding).toBeNull();
    const body = request?.body as Record<string, unknown>;
    expect(body["encrypted_payload"]).toBeUndefined();
    expect(body["status"]).toBe("healthy");
  });
});
