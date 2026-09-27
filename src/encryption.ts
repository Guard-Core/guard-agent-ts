/**
 * AES-256-GCM payload encryption, mirroring guard_agent/encryption.py
 * byte-for-byte on the wire.
 *
 * Scheme (identical to the Python agent):
 * - 256-bit keys, urlsafe-base64-encoded, supplied by the core backend.
 * - Payloads are serialized to canonical JSON: keys sorted, no whitespace
 *   separators (Python json.dumps(..., separators=(",", ":"), sort_keys=True)).
 * - A fresh 12-byte random nonce prefixes every ciphertext; the 16-byte
 *   GCM auth tag is appended by the cipher (Node's AES-256-GCM matches the
 *   Python cryptography AESGCM framing of nonce || ciphertext || tag).
 * - The combined blob is urlsafe-base64-encoded for transmission.
 * - An optional associated-data string authenticates without encryption.
 * - Plaintext fallback is forbidden: when `projectEncryptionKey` is set but
 *   invalid, the transport raises EncryptionConfigError at initialization
 *   (mirrors _transport_lifecycle.py:_init_encryption).
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const NONCE_SIZE = 12;
const KEY_SIZE = 32;

/** Base class for encryption-related errors. */
export class EncryptionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncryptionError";
  }
}

/**
 * Raised when encryption initialization fails; plaintext fallback is
 * forbidden (mirrors the Python EncryptionConfigError).
 */
export class EncryptionConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EncryptionConfigError";
  }
}

/**
 * Canonicalize a value into the exact JSON the Python agent encrypts:
 * object keys sorted recursively, arrays in order, no whitespace, and
 * Python json.dumps ensure_ascii escaping (\uXXXX for non-ASCII).
 * Exported for tests so the byte-level wire format stays pinned.
 */
export function canonicalizeJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error(`Object of type number is not JSON serializable: ${value}`);
    }
    if (Number.isInteger(value)) return String(value);
    return String(value);
  }
  if (typeof value === "string") return `"${ensureAscii(value)}"`;
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeJson).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    const parts = keys.map(
      (key) => `"${ensureAscii(key)}":${canonicalizeJson(record[key])}`,
    );
    return `{${parts.join(",")}}`;
  }
  throw new Error(`Object of type ${typeof value} is not JSON serializable`);
}

// Short escapes used by Python json.dumps, then \uXXXX for everything
// non-printable or non-ASCII (surrogate pairs for astral characters).
const SHORT_ESCAPES: Record<string, string> = {
  '"': '\\"',
  "\\": "\\\\",
  "\n": "\\n",
  "\r": "\\r",
  "\t": "\\t",
  "\b": "\\b",
  "\f": "\\f",
};

function ensureAscii(text: string): string {
  let out = "";
  for (const ch of text) {
    const short = SHORT_ESCAPES[ch];
    if (short !== undefined) {
      out += short;
      continue;
    }
    const code = ch.codePointAt(0) as number;
    if (code < 0x20 || code > 0x7e) {
      if (code > 0xffff) {
        // Surrogate pair escape, matching Python's ensure_ascii.
        const high = Math.floor((code - 0x10000) / 0x400) + 0xd800;
        const low = ((code - 0x10000) % 0x400) + 0xdc00;
        out += `\\u${high.toString(16).padStart(4, "0")}\\u${low
          .toString(16)
          .padStart(4, "0")}`;
      } else {
        out += `\\u${code.toString(16).padStart(4, "0")}`;
      }
    } else {
      out += ch;
    }
  }
  return out;
}

export class PayloadEncryptor {
  static readonly NONCE_SIZE = NONCE_SIZE;
  static readonly KEY_SIZE = KEY_SIZE;

  private readonly keyBytes: Buffer;

  constructor(projectKey: string) {
    if (!projectKey) {
      throw new EncryptionError("Project key cannot be empty");
    }
    let keyBytes: Buffer;
    try {
      // Accept both padded and unpadded urlsafe keys; Node's "base64url"
      // decoder handles the padding variants.
      keyBytes = Buffer.from(projectKey, "base64url");
    } catch (error) {
      throw new EncryptionError(
        `Invalid project key format: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    if (keyBytes.length !== KEY_SIZE) {
      throw new EncryptionError(
        `Invalid key size: ${keyBytes.length} bytes, expected ${KEY_SIZE}`,
      );
    }
    this.keyBytes = keyBytes;
  }

  /**
   * Encrypt a telemetry payload. Returns the urlsafe-base64-encoded
   * nonce || ciphertext || tag string, byte-compatible with the Python
   * agent's PayloadEncryptor.encrypt.
   */
  encrypt(data: Record<string, unknown>, associatedData?: string | null): string {
    try {
      const json = canonicalizeJson(data);
      const nonce = randomBytes(NONCE_SIZE);
      const cipher = createCipheriv("aes-256-gcm", this.keyBytes, nonce);
      if (associatedData) cipher.setAAD(Buffer.from(associatedData, "utf8"));
      const ciphertext = Buffer.concat([
        cipher.update(Buffer.from(json, "utf8")),
        cipher.final(),
        cipher.getAuthTag(),
      ]);
      // Python's base64.urlsafe_b64encode pads to a multiple of 4, so the
      // shared wire format is padded urlsafe-base64, not Node's unpadded
      // "base64url": start from padded std base64 and swap the alphabet.
      return Buffer.concat([nonce, ciphertext])
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
    } catch (error) {
      if (error instanceof EncryptionError) throw error;
      throw new EncryptionError(
        `Failed to encrypt payload: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }

  /**
   * Decrypt an encrypted payload (primarily for testing; in normal
   * operation only the core backend decrypts).
   */
  decrypt(
    encryptedData: string,
    associatedData?: string | null,
  ): Record<string, unknown> {
    try {
      const combined = Buffer.from(encryptedData, "base64url");
      const nonce = combined.subarray(0, NONCE_SIZE);
      const ciphertext = combined.subarray(NONCE_SIZE, combined.length - 16);
      const tag = combined.subarray(combined.length - 16);
      const decipher = createDecipheriv("aes-256-gcm", this.keyBytes, nonce);
      if (associatedData) decipher.setAAD(Buffer.from(associatedData, "utf8"));
      decipher.setAuthTag(tag);
      const plaintext = Buffer.concat([
        decipher.update(ciphertext),
        decipher.final(),
      ]).toString("utf8");
      const parsed: unknown = JSON.parse(plaintext);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error("decrypted payload is not a JSON object");
      }
      return parsed as Record<string, unknown>;
    } catch {
      throw new EncryptionError("Invalid or tampered payload");
    }
  }

  /** Verify the key with an encrypt/decrypt round trip. */
  verifyKey(): boolean {
    try {
      const testData = { test: "verification" };
      const encrypted = this.encrypt(testData);
      const decrypted = this.decrypt(encrypted);
      return JSON.stringify(decrypted) === JSON.stringify(testData);
    } catch {
      return false;
    }
  }
}

/**
 * Factory: returns null when no key is configured; throws EncryptionError
 * when a key is provided but invalid (mirrors create_encryptor).
 */
export function createEncryptor(
  projectKey: string | null | undefined,
): PayloadEncryptor | null {
  if (!projectKey) return null;
  return new PayloadEncryptor(projectKey);
}
