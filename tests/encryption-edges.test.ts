/**
 * Edge coverage for AES-256-GCM payload encryption: canonical JSON
 * serialization (sorted keys, Python ensure_ascii escapes, serializability
 * failures), key validation, associated data, tamper rejection, and the
 * verifyKey round trip.
 */
import { createCipheriv, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";

import {
  canonicalizeJson,
  createEncryptor,
  EncryptionError,
  PayloadEncryptor,
} from "../src/encryption.js";

const KEY = randomBytes(32).toString("base64url");

describe("canonicalizeJson wire format", () => {
  it("renders scalars exactly like Python json.dumps", () => {
    expect(canonicalizeJson(null)).toBe("null");
    expect(canonicalizeJson(true)).toBe("true");
    expect(canonicalizeJson(false)).toBe("false");
    expect(canonicalizeJson(1)).toBe("1");
    expect(canonicalizeJson(1.5)).toBe("1.5");
    expect(canonicalizeJson("plain")).toBe('"plain"');
  });

  it("sorts object keys recursively without whitespace", () => {
    expect(canonicalizeJson({ b: 1, a: { d: 2, c: 3 } })).toBe('{"a":{"c":3,"d":2},"b":1}');
    expect(canonicalizeJson([1, "two", null, false])).toBe('[1,"two",null,false]');
  });

  it("escapes short escapes and non-ASCII like ensure_ascii", () => {
    expect(canonicalizeJson('quote " backslash \\')).toBe('"quote \\" backslash \\\\"');
    expect(canonicalizeJson("line\n\ttab")).toBe('"line\\n\\ttab"');
    expect(canonicalizeJson("é")).toBe('"\\u00e9"');
    expect(canonicalizeJson("中文")).toBe('"\\u4e2d\\u6587"');
    expect(canonicalizeJson("\u0001")).toBe('"\\u0001"');
    expect(canonicalizeJson("~")).toBe('"~"');
  });

  it("escapes astral characters as surrogate pairs", () => {
    // U+1F600 -> high \ud83d low \ude00, matching Python ensure_ascii.
    expect(canonicalizeJson("\u{1F600}")).toBe('"\\ud83d\\ude00"');
  });

  it("rejects non-finite numbers and unsupported types", () => {
    expect(() => canonicalizeJson(Number.NaN)).toThrow(
      "Object of type number is not JSON serializable: NaN",
    );
    expect(() => canonicalizeJson(Number.POSITIVE_INFINITY)).toThrow(
      "Object of type number is not JSON serializable: Infinity",
    );
    expect(() => canonicalizeJson(() => {})).toThrow(
      "Object of type function is not JSON serializable",
    );
    expect(() => canonicalizeJson(Symbol("s"))).toThrow(
      "Object of type symbol is not JSON serializable",
    );
  });
});

describe("PayloadEncryptor key validation", () => {
  it("rejects empty keys", () => {
    expect(() => new PayloadEncryptor("")).toThrow("Project key cannot be empty");
  });

  it("rejects keys that are not 32 bytes", () => {
    const short = randomBytes(16).toString("base64url");
    expect(() => new PayloadEncryptor(short)).toThrow(
      "Invalid key size: 16 bytes, expected 32",
    );
  });

  it("wraps undecodable keys in an EncryptionError", () => {
    // A non-string key makes the base64url decode itself throw.
    expect(() => new PayloadEncryptor(42 as unknown as string)).toThrow(
      "Invalid project key format",
    );
  });
});

describe("PayloadEncryptor round trips", () => {
  it("encrypts and decrypts with nonce||ciphertext||tag framing", () => {
    const encryptor = new PayloadEncryptor(KEY);
    const encrypted = encryptor.encrypt({ b: 2, a: "one" });
    const combined = Buffer.from(encrypted, "base64url");
    expect(combined.length).toBeGreaterThan(PayloadEncryptor.NONCE_SIZE + 16);
    expect(encryptor.decrypt(encrypted)).toEqual({ a: "one", b: 2 });
  });

  it("binds associated data into the authentication tag", () => {
    const encryptor = new PayloadEncryptor(KEY);
    const encrypted = encryptor.encrypt({ a: 1 }, "batch-42");
    expect(encryptor.decrypt(encrypted, "batch-42")).toEqual({ a: 1 });
    expect(() => encryptor.decrypt(encrypted, "batch-43")).toThrow(EncryptionError);
    expect(() => encryptor.decrypt(encrypted)).toThrow(EncryptionError);
  });

  it("raises EncryptionError when the payload is not serializable", () => {
    const encryptor = new PayloadEncryptor(KEY);
    expect(() => encryptor.encrypt({ n: Number.NaN })).toThrow(
      "Failed to encrypt payload",
    );
    // Non-Error throwables get the same treatment.
    expect(() =>
      encryptor.encrypt({
        get boom(): string {
          throw "not-an-error";
        },
      }),
    ).toThrow("Failed to encrypt payload: not-an-error");
  });

  it("rejects tampered and non-object payloads", () => {
    const encryptor = new PayloadEncryptor(KEY);
    const encrypted = encryptor.encrypt({ a: 1 });
    const bytes = Buffer.from(encrypted, "base64url");
    const last = bytes.length - 1;
    bytes[last] = (bytes[last] ?? 0) ^ 0xff;
    expect(() => encryptor.decrypt(bytes.toString("base64url"))).toThrow(
      "Invalid or tampered payload",
    );

    // A ciphertext whose plaintext is valid JSON but not an object.
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", Buffer.from(KEY, "base64url"), nonce);
    const plaintext = Buffer.from("123", "utf8");
    const forged = Buffer.concat([
      nonce,
      cipher.update(plaintext),
      cipher.final(),
      cipher.getAuthTag(),
    ]);
    const forgedUrl = forged
      .toString("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
    expect(() => encryptor.decrypt(forgedUrl)).toThrow("Invalid or tampered payload");
  });

  it("verifies the key with a round trip and reports failures", () => {
    const encryptor = new PayloadEncryptor(KEY);
    expect(encryptor.verifyKey()).toBe(true);

    const broken = new PayloadEncryptor(KEY);
    (broken as unknown as { encrypt: () => never }).encrypt = () => {
      throw new Error("encrypt exploded");
    };
    expect(broken.verifyKey()).toBe(false);
  });
});

describe("createEncryptor factory", () => {
  it("returns null without a key and an encryptor with one", () => {
    expect(createEncryptor(null)).toBeNull();
    expect(createEncryptor(undefined)).toBeNull();
    expect(createEncryptor("")).toBeNull();
    expect(createEncryptor(KEY)).toBeInstanceOf(PayloadEncryptor);
  });
});
