/**
 * EventBuffer, mirroring guard_agent/buffer.py and its mixin split:
 * _buffer_queue.py (add/flush/requeue), _buffer_lifecycle.py (auto flush),
 * _buffer_overflow.py (drop/block/raise policies), _buffer_redis.py
 * (crash-recovery persistence).
 *
 * Semantics mirrored exactly:
 * - Per-kind bounded queues (events and metrics each capped at bufferSize).
 * - Overflow policies: "drop" evicts the oldest entry (default), "block"
 *   backpressures the caller until space frees, "raise" throws
 *   BufferFullError. A requeue after a failed send keeps its slot under the
 *   block policy (durability wins over new writers).
 * - High-watermark early flush: occupancy >= bufferSize * highWatermarkRatio
 *   schedules a flush, throttled by maxConcurrentFlushes.
 * - At-least-once handshake: flush*_with_keys drains and returns aligned
 *   Redis keys; confirm* deletes keys after a successful send; requeue*
 *   pushes unsent items back to the front, evicting from the tail when full
 *   and returning those evicted keys so the caller can confirm them.
 * - Redis persistence: every accepted item is written under a
 *   globally-unique key with a 3600s TTL; on startup the buffer reloads
 *   pending items from Redis.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";

import type { AgentConfig } from "./config.js";
import { BufferFullError } from "./errors.js";
import { errorMessage } from "./logger.js";
import type { AgentLogger } from "./logger.js";
import type { RedisHandler } from "./redis.js";
import {
  type SecurityEvent,
  type SecurityMetric,
  eventToWire,
  metricToWire,
  normalizeSecurityEvent,
  normalizeSecurityMetric,
} from "./models.js";
import { safeJsonParse, safeJsonStringify } from "./utils.js";

/** How often a "block" waiter re-checks for space (Python: 0.5s). */
const BLOCK_POLICY_POLL_INTERVAL_MS = 500;

/** Log every Nth drop when the buffer overflows under "drop" policy. */
const DROP_LOG_INTERVAL = 100;

/** TTL for persisted buffer entries in Redis (seconds). */
const REDIS_PERSIST_TTL_SECONDS = 3600;

type Waiter = () => void;

/**
 * True inside the async context of a Redis persist. guard-core's Redis
 * manager reports a failed operation through the agent's sendEvent, which
 * would persist again and fail again without bound; an event emitted inside
 * a persist is buffered in memory only. AsyncLocalStorage scopes this to the
 * persist's own async chain, so unrelated concurrent requests still persist.
 */
const persisting = new AsyncLocalStorage<boolean>();

function uniqueKey(prefix: string): string {
  const nanos = process.hrtime.bigint().toString();
  const rand = randomUUID().replace(/-/g, "").slice(0, 8);
  return `${prefix}_${nanos}_${rand}`;
}

/** Strip a full Redis key down to its short (per-item) segment. */
function shortKey(fullKey: string): string {
  const parts = fullKey.split(":");
  // String.split always returns at least one element, so the fallback only
  // exists to satisfy noUncheckedIndexedAccess; it can never execute.
  // (start/stop hints are parsed from the original source; "ignore next" is
  // dropped from the transpiled code and never reaches the coverage remap.)
  /* v8 ignore start */
  return parts[parts.length - 1] ?? fullKey;
  /* v8 ignore stop */
}

export interface BufferStats {
  eventsBuffered: number;
  metricsBuffered: number;
  eventsFlushed: number;
  metricsFlushed: number;
  eventsDropped: number;
  metricsDropped: number;
  currentEventBufferSize: number;
  currentMetricBufferSize: number;
  redisPersistFailures: number;
  durabilityDegraded: boolean;
  lastFlushTime: number | null;
  autoFlushRunning: boolean;
}

export class EventBuffer {
  readonly config: AgentConfig;
  private readonly logger: AgentLogger;
  private readonly flushCallback: (() => Promise<void>) | null;

  private readonly eventBuffer: SecurityEvent[] = [];
  private readonly metricBuffer: SecurityMetric[] = [];
  private readonly maxSize: number;

  redisHandler: RedisHandler | null = null;

  private readonly eventRedisKeys = new Map<SecurityEvent, string>();
  private readonly metricRedisKeys = new Map<SecurityMetric, string>();

  private readonly eventWaiters: Waiter[] = [];
  private readonly metricWaiters: Waiter[] = [];

  private activeFlushes = 0;
  private autoFlushTimer: NodeJS.Timeout | null = null;
  private running = false;
  private readonly inflightFlushes = new Set<Promise<void>>();
  private readonly inflightPersists = new Set<Promise<void>>();
  private persistOverflowLogged = false;
  /**
   * Items with a persist in flight, mapped to whether they are still in the
   * buffer. Every path that takes an item out (drop, flush drain, clear)
   * flips it and a requeue flips it back, so the post-write check is O(1)
   * instead of scanning the buffer.
   */
  private readonly pendingPersists = new Map<SecurityEvent | SecurityMetric, boolean>();

  eventsBuffered = 0;
  metricsBuffered = 0;
  eventsFlushed = 0;
  metricsFlushed = 0;
  eventsDropped = 0;
  metricsDropped = 0;
  redisPersistFailures = 0;
  lastFlushTime: number | null = null;

  constructor(
    config: AgentConfig,
    flushCallback: (() => Promise<void>) | null = null,
  ) {
    this.config = config;
    this.logger = config.logger;
    this.flushCallback = flushCallback;
    this.maxSize = config.bufferSize;
  }

  // ------------------------------------------------------------------
  // Redis integration
  // ------------------------------------------------------------------

  /** Attach the durable backend and reload pending items from Redis. */
  async initializeRedis(redisHandler: RedisHandler): Promise<void> {
    this.redisHandler = redisHandler;
    await this.loadFromRedis();
  }

  private async persistEventToRedis(event: SecurityEvent): Promise<string | null> {
    if (!this.redisHandler) return null;
    try {
      const key = uniqueKey("event");
      const serialized = safeJsonStringify(eventToWire(event));
      await this.redisHandler.setKey(
        "agent_events",
        key,
        serialized,
        REDIS_PERSIST_TTL_SECONDS,
      );
      return key;
    } catch (error) {
      this.redisPersistFailures += 1;
      this.logger.warn(`Failed to persist event to Redis: ${errorMessage(error)}`);
      return null;
    }
  }

  private async persistMetricToRedis(metric: SecurityMetric): Promise<string | null> {
    if (!this.redisHandler) return null;
    try {
      const key = uniqueKey("metric");
      const serialized = safeJsonStringify(metricToWire(metric));
      await this.redisHandler.setKey(
        "agent_metrics",
        key,
        serialized,
        REDIS_PERSIST_TTL_SECONDS,
      );
      return key;
    } catch (error) {
      this.redisPersistFailures += 1;
      this.logger.warn(`Failed to persist metric to Redis: ${errorMessage(error)}`);
      return null;
    }
  }

  /**
   * Run a Redis persist as a tracked background promise so the request path
   * never waits on Redis; stopAutoFlush drains it. Nothing is created
   * without a Redis handler or while a persist is in flight in this async
   * context. In-flight persists are capped at bufferSize (shared by events
   * and metrics): past it the item stays in memory only and counts as a
   * persist failure, so a slow Redis cannot pile up unbounded tasks.
   */
  private spawnPersist(persist: () => Promise<void>): void {
    if (!this.redisHandler || persisting.getStore()) return;
    if (this.inflightPersists.size >= this.config.bufferSize) {
      this.redisPersistFailures += 1;
      if (!this.persistOverflowLogged) {
        this.persistOverflowLogged = true;
        this.logger.warn(
          `Redis persist backlog at buffer_size=${this.config.bufferSize}; buffering in memory only until it drains`,
        );
      }
      return;
    }
    const task = persisting.run(true, persist).then(() => {
      this.inflightPersists.delete(task);
      if (this.inflightPersists.size === 0) this.persistOverflowLogged = false;
    });
    this.inflightPersists.add(task);
  }

  /** Wait for every pending background persist (never rejects). */
  async drainPersists(): Promise<void> {
    while (this.inflightPersists.size > 0) {
      await Promise.allSettled([...this.inflightPersists]);
    }
  }

  /**
   * Persist an already-buffered event. If it left the buffer meanwhile
   * (flushed or evicted) the new key is deleted instead of tracked, so it
   * neither orphans nor replays after a restart.
   */
  private async persistAndTrackEvent(event: SecurityEvent): Promise<void> {
    try {
      this.pendingPersists.set(event, true);
      const key = await this.persistEventToRedis(event);
      if (key === null) return;
      if (this.pendingPersists.get(event)) this.eventRedisKeys.set(event, key);
      else await this.confirmEventRedisKeys([key]);
    } catch (error) {
      this.logger.error(`Failed to buffer event: ${errorMessage(error)}`);
    } finally {
      this.pendingPersists.delete(event);
    }
  }

  private async persistAndTrackMetric(metric: SecurityMetric): Promise<void> {
    try {
      this.pendingPersists.set(metric, true);
      const key = await this.persistMetricToRedis(metric);
      if (key === null) return;
      if (this.pendingPersists.get(metric)) this.metricRedisKeys.set(metric, key);
      else await this.confirmMetricRedisKeys([key]);
    } catch (error) {
      this.logger.error(`Failed to buffer metric: ${errorMessage(error)}`);
    } finally {
      this.pendingPersists.delete(metric);
    }
  }

  /**
   * Load persisted events/metrics from Redis on startup and track their keys.
   * All network reads happen before any mutation, so the synchronous replay
   * below cannot interleave with live addEvent/addMetric traffic.
   */
  private async loadFromRedis(): Promise<void> {
    if (!this.redisHandler) return;

    try {
      const eventKeys = (await this.redisHandler.keys("agent_events:*")) ?? [];
      const eventPayloads = await Promise.all(
        eventKeys.map(async (fullKey) => ({
          fullKey,
          data: await this.redisHandler!.getKey("agent_events", shortKey(fullKey)),
        })),
      );
      for (const { fullKey, data } of eventPayloads) {
        this.loadOneEventFromRedis(fullKey, data);
      }

      const metricKeys = (await this.redisHandler.keys("agent_metrics:*")) ?? [];
      const metricPayloads = await Promise.all(
        metricKeys.map(async (fullKey) => ({
          fullKey,
          data: await this.redisHandler!.getKey("agent_metrics", shortKey(fullKey)),
        })),
      );
      for (const { fullKey, data } of metricPayloads) {
        this.loadOneMetricFromRedis(fullKey, data);
      }

      if (this.eventBuffer.length > 0 || this.metricBuffer.length > 0) {
        this.logger.info(
          `Loaded ${this.eventBuffer.length} events and ` +
            `${this.metricBuffer.length} metrics from Redis`,
        );
      }
    } catch (error) {
      this.logger.warn(`Failed to load from Redis: ${errorMessage(error)}`);
    }
  }

  private loadOneEventFromRedis(fullKey: string, data: string | null): void {
    try {
      if (!data) {
        this.logger.warn(
          `Failed to load event from Redis key ${fullKey}: No data found for key`,
        );
        return;
      }
      const parsed = safeJsonParse(data);
      if (!parsed) return;
      const event = normalizeSecurityEvent(parsed);
      if (this.isEventBufferFull()) this.forgetOldestEventKey();
      this.eventBuffer.push(event);
      this.eventsBuffered += 1;
      this.eventRedisKeys.set(event, shortKey(fullKey));
    } catch (error) {
      this.logger.warn(`Failed to load event from Redis key ${fullKey}: ${errorMessage(error)}`);
    }
  }

  private loadOneMetricFromRedis(fullKey: string, data: string | null): void {
    try {
      if (!data) {
        this.logger.warn(
          `Failed to load metric from Redis key ${fullKey}: No data found for key`,
        );
        return;
      }
      const parsed = safeJsonParse(data);
      if (!parsed) return;
      const metric = normalizeSecurityMetric(parsed);
      if (this.isMetricBufferFull()) this.forgetOldestMetricKey();
      this.metricBuffer.push(metric);
      this.metricsBuffered += 1;
      this.metricRedisKeys.set(metric, shortKey(fullKey));
    } catch (error) {
      this.logger.warn(`Failed to load metric from Redis key ${fullKey}: ${errorMessage(error)}`);
    }
  }

  private async deleteMatchingRedisKeys(
    namespace: string,
    pattern: string,
    limit?: number,
  ): Promise<void> {
    if (!this.redisHandler) return;
    const keys = (await this.redisHandler.keys(pattern)) ?? [];
    const selected =
      limit === undefined ? keys : [...keys].sort().slice(0, limit);
    for (const key of selected) {
      await this.redisHandler.delete(namespace, shortKey(key));
    }
  }

  /** Delete the given event keys from Redis after the transport confirms. */
  async confirmEventRedisKeys(keys: string[]): Promise<void> {
    if (!this.redisHandler) return;
    for (const key of keys) {
      if (!key) continue;
      try {
        await this.redisHandler.delete("agent_events", key);
      } catch (error) {
        this.logger.warn(`Failed to delete confirmed event key ${key}: ${errorMessage(error)}`);
      }
    }
  }

  /** Delete the given metric keys from Redis after the transport confirms. */
  async confirmMetricRedisKeys(keys: string[]): Promise<void> {
    if (!this.redisHandler) return;
    for (const key of keys) {
      if (!key) continue;
      try {
        await this.redisHandler.delete("agent_metrics", key);
      } catch (error) {
        this.logger.warn(`Failed to delete confirmed metric key ${key}: ${errorMessage(error)}`);
      }
    }
  }

  // ------------------------------------------------------------------
  // Overflow policy
  // ------------------------------------------------------------------

  private isEventBufferFull(): boolean {
    return this.eventBuffer.length >= this.maxSize;
  }

  private isMetricBufferFull(): boolean {
    return this.metricBuffer.length >= this.maxSize;
  }

  /** Flip a pending persist's in-buffer flag (no-op for items without one). */
  private markPending(item: SecurityEvent | SecurityMetric, inBuffer: boolean): void {
    if (this.pendingPersists.has(item)) this.pendingPersists.set(item, inBuffer);
  }

  private forgetOldestEventKey(): string | null {
    const oldest = this.eventBuffer[0];
    if (oldest === undefined) return null;
    this.markPending(oldest, false);
    const key = this.eventRedisKeys.get(oldest) ?? null;
    this.eventRedisKeys.delete(oldest);
    return key;
  }

  private forgetOldestMetricKey(): string | null {
    const oldest = this.metricBuffer[0];
    if (oldest === undefined) return null;
    this.markPending(oldest, false);
    const key = this.metricRedisKeys.get(oldest) ?? null;
    this.metricRedisKeys.delete(oldest);
    return key;
  }

  private forgetNewestEventKey(): string | null {
    const newest = this.eventBuffer[this.eventBuffer.length - 1];
    if (newest === undefined) return null;
    this.markPending(newest, false);
    const key = this.eventRedisKeys.get(newest) ?? null;
    this.eventRedisKeys.delete(newest);
    return key;
  }

  private forgetNewestMetricKey(): string | null {
    const newest = this.metricBuffer[this.metricBuffer.length - 1];
    if (newest === undefined) return null;
    this.markPending(newest, false);
    const key = this.metricRedisKeys.get(newest) ?? null;
    this.metricRedisKeys.delete(newest);
    return key;
  }

  private notifyWaiters(waiters: Waiter[]): void {
    while (waiters.length > 0) {
      const waiter = waiters.pop();
      // pop() on a non-empty array is always defined; the guard only exists
      // for the type checker and can never take its false arm.
      /* v8 ignore start */
      if (waiter) waiter();
      /* v8 ignore stop */
    }
  }

  private async waitForSpace(waiters: Waiter[]): Promise<void> {
    await new Promise<void>((resolve) => {
      const waiter = (): void => {
        const index = waiters.indexOf(waiter);
        // notifyWaiters pops the waiter before invoking it, so the index is
        // always -1 here; the splice only exists for safety.
        /* v8 ignore start */
        if (index >= 0) waiters.splice(index, 1);
        /* v8 ignore stop */
        resolve();
      };
      waiters.push(waiter);
      setTimeout(() => {
        const index = waiters.indexOf(waiter);
        if (index >= 0) waiters.splice(index, 1);
        resolve();
      }, BLOCK_POLICY_POLL_INTERVAL_MS);
    });
  }

  // ------------------------------------------------------------------
  // Queue operations
  // ------------------------------------------------------------------

  /**
   * Add a security event to the buffer honoring the configured overflow
   * policy. Under "block", a requeue after a failed send always keeps its
   * slot (durability wins over a new writer); this caller never stalls past
   * BLOCK_POLICY_POLL_INTERVAL_MS before re-checking for space.
   */
  async addEvent(event: SecurityEvent): Promise<void> {
    for (;;) {
      if (!this.isEventBufferFull()) {
        this.eventBuffer.push(event);
        this.eventsBuffered += 1;
        this.spawnPersist(() => this.persistAndTrackEvent(event));
        break;
      }

      const policy = this.config.bufferOverflowPolicy;
      if (policy === "raise") {
        throw new BufferFullError(
          `Event buffer full at maxSize=${this.maxSize} and bufferOverflowPolicy='raise'`,
        );
      }
      if (policy === "block") {
        await this.waitForSpace(this.eventWaiters);
        continue;
      }

      this.eventsDropped += 1;
      if (this.eventsDropped % DROP_LOG_INTERVAL === 1) {
        this.logger.warn(
          `Event buffer full at maxSize=${this.maxSize}; dropping oldest event ` +
            `(${this.eventsDropped} dropped total)`,
        );
      }
      const droppedKey = this.forgetOldestEventKey();
      this.eventBuffer.shift();
      if (droppedKey) {
        await this.confirmEventRedisKeys([droppedKey]);
      }
      continue;
    }

    if (this.eventBuffer.length >= this.maxSize * this.config.highWatermarkRatio) {
      this.trackInflightFlush();
    }
  }

  /** Add a metric to the buffer; see addEvent for the overflow rules. */
  async addMetric(metric: SecurityMetric): Promise<void> {
    for (;;) {
      if (!this.isMetricBufferFull()) {
        this.metricBuffer.push(metric);
        this.metricsBuffered += 1;
        this.spawnPersist(() => this.persistAndTrackMetric(metric));
        break;
      }

      const policy = this.config.bufferOverflowPolicy;
      if (policy === "raise") {
        throw new BufferFullError(
          `Metric buffer full at maxSize=${this.maxSize} and bufferOverflowPolicy='raise'`,
        );
      }
      if (policy === "block") {
        await this.waitForSpace(this.metricWaiters);
        continue;
      }

      this.metricsDropped += 1;
      if (this.metricsDropped % DROP_LOG_INTERVAL === 1) {
        this.logger.warn(
          `Metric buffer full at maxSize=${this.maxSize}; dropping oldest metric ` +
            `(${this.metricsDropped} dropped total)`,
        );
      }
      const droppedKey = this.forgetOldestMetricKey();
      this.metricBuffer.shift();
      if (droppedKey) {
        await this.confirmMetricRedisKeys([droppedKey]);
      }
      continue;
    }

    if (this.metricBuffer.length >= this.maxSize * this.config.highWatermarkRatio) {
      this.trackInflightFlush();
    }
  }

  /**
   * Flush events and immediately forget Redis keys (legacy semantics,
   * mirroring flush_events).
   */
  async flushEvents(): Promise<SecurityEvent[]> {
    const [events, keys] = await this.flushEventsWithKeys();
    await this.confirmEventRedisKeys(keys);
    return events;
  }

  /**
   * Flush metrics and immediately forget Redis keys (legacy semantics,
   * mirroring flush_metrics).
   */
  async flushMetrics(): Promise<SecurityMetric[]> {
    const [metrics, keys] = await this.flushMetricsWithKeys();
    await this.confirmMetricRedisKeys(keys);
    return metrics;
  }

  /**
   * Drain events plus their Redis keys (one entry per event, "" when the
   * event was never persisted); keys stay aligned with events so a failed
   * send can requeue correctly with or without Redis configured.
   */
  async flushEventsWithKeys(): Promise<[SecurityEvent[], string[]]> {
    const events = [...this.eventBuffer];
    for (const event of events) this.markPending(event, false);
    const keys = events.map((event) => this.eventRedisKeys.get(event) ?? "");
    this.eventBuffer.length = 0;
    this.eventRedisKeys.clear();
    this.eventsFlushed += events.length;
    this.lastFlushTime = Date.now() / 1000;
    if (events.length > 0) this.notifyWaiters(this.eventWaiters);
    return [events, keys];
  }

  /**
   * Drain metrics plus their Redis keys (one entry per metric, "" when the
   * metric was never persisted); keys stay aligned with metrics so a failed
   * send can requeue correctly with or without Redis configured.
   */
  async flushMetricsWithKeys(): Promise<[SecurityMetric[], string[]]> {
    const metrics = [...this.metricBuffer];
    for (const metric of metrics) this.markPending(metric, false);
    const keys = metrics.map((metric) => this.metricRedisKeys.get(metric) ?? "");
    this.metricBuffer.length = 0;
    this.metricRedisKeys.clear();
    this.metricsFlushed += metrics.length;
    this.lastFlushTime = Date.now() / 1000;
    if (metrics.length > 0) this.notifyWaiters(this.metricWaiters);
    return [metrics, keys];
  }

  /**
   * Push unsent events back to the front of the buffer; keep Redis keys.
   * The tail is evicted when the buffer is full, so that is the side whose
   * key gets forgotten; the caller must confirm (delete) the returned keys
   * so their Redis records do not orphan.
   */
  async requeueEventsInMemory(events: SecurityEvent[], keys: string[]): Promise<string[]> {
    const evictedKeys: string[] = [];
    for (let i = events.length - 1; i >= 0; i--) {
      const event = events[i];
      const key = keys[i] ?? "";
      if (event === undefined) continue;
      if (this.isEventBufferFull()) {
        this.eventsDropped += 1;
        // Forget the tail's key while the tail is still in place, then evict
        // it (mirrors the deque's appendleft eviction side).
        const evictedKey = this.forgetNewestEventKey();
        if (evictedKey) evictedKeys.push(evictedKey);
        this.eventBuffer.pop();
      }
      this.eventBuffer.unshift(event);
      this.markPending(event, true);
      if (key) this.eventRedisKeys.set(event, key);
    }
    return evictedKeys;
  }

  /**
   * Push unsent metrics back to the front of the buffer; keep Redis keys.
   * See requeueEventsInMemory for the eviction rule.
   */
  async requeueMetricsInMemory(metrics: SecurityMetric[], keys: string[]): Promise<string[]> {
    const evictedKeys: string[] = [];
    for (let i = metrics.length - 1; i >= 0; i--) {
      const metric = metrics[i];
      const key = keys[i] ?? "";
      if (metric === undefined) continue;
      if (this.isMetricBufferFull()) {
        this.metricsDropped += 1;
        const evictedKey = this.forgetNewestMetricKey();
        if (evictedKey) evictedKeys.push(evictedKey);
        this.metricBuffer.pop();
      }
      this.metricBuffer.unshift(metric);
      this.markPending(metric, true);
      if (key) this.metricRedisKeys.set(metric, key);
    }
    return evictedKeys;
  }

  /**
   * Clear all buffers, including the Redis-key maps, and wipe the persisted
   * namespaces (mirroring clear_buffer).
   */
  async clearBuffer(): Promise<void> {
    for (const item of this.pendingPersists.keys()) this.pendingPersists.set(item, false);
    this.eventBuffer.length = 0;
    this.eventRedisKeys.clear();
    this.notifyWaiters(this.eventWaiters);

    this.metricBuffer.length = 0;
    this.metricRedisKeys.clear();
    this.notifyWaiters(this.metricWaiters);

    if (this.redisHandler) {
      try {
        await this.deleteMatchingRedisKeys("agent_events", "agent_events:*");
        await this.deleteMatchingRedisKeys("agent_metrics", "agent_metrics:*");
        this.logger.info("Cleared all Redis buffers");
      } catch (error) {
        this.logger.warn(`Failed to clear Redis buffers: ${errorMessage(error)}`);
      }
    }
  }

  // ------------------------------------------------------------------
  // Lifecycle
  // ------------------------------------------------------------------

  /** Start the automatic flush loop. */
  startAutoFlush(): void {
    if (this.autoFlushTimer !== null) return;
    this.running = true;
    this.scheduleAutoFlush();
  }

  private scheduleAutoFlush(): void {
    if (!this.running) return;
    const timer = setTimeout(() => {
      void (async () => {
        if (!this.running) return;
        try {
          await this.flushIfNeeded();
        } catch (error) {
          this.logger.error(`Error in auto flush loop: ${errorMessage(error)}`);
        }
        this.scheduleAutoFlush();
      })();
    }, this.config.flushInterval * 1000);
    timer.unref?.();
    this.autoFlushTimer = timer;
  }

  /** Stop the automatic flush loop and wait for in-flight flushes. */
  async stopAutoFlush(): Promise<void> {
    this.running = false;
    if (this.autoFlushTimer !== null) {
      clearTimeout(this.autoFlushTimer);
      this.autoFlushTimer = null;
    }
    if (this.inflightFlushes.size > 0) {
      await Promise.allSettled([...this.inflightFlushes]);
    }
    this.inflightFlushes.clear();
    await this.drainPersists();
    this.activeFlushes = 0;
  }

  /** Total buffered items across both queues. */
  getBufferSize(): number {
    return this.eventBuffer.length + this.metricBuffer.length;
  }

  /**
   * Trigger a flush when the buffer is at the watermark or the flush
   * interval has elapsed, throttled by maxConcurrentFlushes (mirrors
   * _flush_if_needed). Never throws.
   */
  async flushIfNeeded(): Promise<void> {
    if (this.flushCallback === null) return;
    if (this.activeFlushes >= this.config.maxConcurrentFlushes) return;

    const timeSinceLastFlush = this.lastFlushTime
      ? Date.now() / 1000 - this.lastFlushTime
      : this.config.flushInterval + 1;

    const bufferSize = this.getBufferSize();
    if (bufferSize === 0) return;

    const atWatermark = bufferSize >= this.config.bufferSize * this.config.highWatermarkRatio;
    const timeElapsed = timeSinceLastFlush >= this.config.flushInterval;

    if (!(atWatermark || timeElapsed)) return;

    this.logger.debug(`Triggering buffer flush - size: ${bufferSize}`);
    this.activeFlushes += 1;
    try {
      await this.flushCallback();
    } finally {
      this.activeFlushes -= 1;
    }
  }

  private trackInflightFlush(): void {
    const flush = this.flushIfNeeded()
      .catch((error: unknown) => {
        this.logger.error(`Error during early flush: ${errorMessage(error)}`);
      })
      .then(() => {
        this.inflightFlushes.delete(flush);
      });
    this.inflightFlushes.add(flush);
  }

  /** Get buffer statistics. */
  getStats(): BufferStats {
    return {
      eventsBuffered: this.eventsBuffered,
      metricsBuffered: this.metricsBuffered,
      eventsFlushed: this.eventsFlushed,
      metricsFlushed: this.metricsFlushed,
      eventsDropped: this.eventsDropped,
      metricsDropped: this.metricsDropped,
      currentEventBufferSize: this.eventBuffer.length,
      currentMetricBufferSize: this.metricBuffer.length,
      redisPersistFailures: this.redisPersistFailures,
      durabilityDegraded: this.redisHandler !== null && this.redisPersistFailures > 0,
      lastFlushTime: this.lastFlushTime,
      autoFlushRunning: this.running,
    };
  }
}
