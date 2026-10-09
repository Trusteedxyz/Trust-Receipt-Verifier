export interface TokenBucketOptions {
  readonly sustainedPerSecond: number;
  readonly burst: number;
  readonly queueDepth: number;
  readonly queueTimeoutMs: number;
  readonly now?: () => number;
}

export class TokenBucket {
  readonly #capacity: number;
  readonly #refillPerMs: number;
  readonly #queueDepth: number;
  readonly #queueTimeoutMs: number;
  readonly #now: () => number;
  #tokens: number;
  #updatedAt: number;
  #queued = 0;

  constructor(options: TokenBucketOptions) {
    this.#capacity = options.burst;
    this.#refillPerMs = options.sustainedPerSecond / 1000;
    this.#queueDepth = options.queueDepth;
    this.#queueTimeoutMs = options.queueTimeoutMs;
    this.#now = options.now ?? Date.now;
    this.#tokens = options.burst;
    this.#updatedAt = this.#now();
  }

  async take(): Promise<boolean> {
    this.#refill();
    if (this.#tokens >= 1) {
      this.#tokens -= 1;
      return true;
    }
    if (this.#queued >= this.#queueDepth) return false;
    this.#queued += 1;
    try {
      const waitMs = Math.min(
        this.#queueTimeoutMs,
        Math.ceil((1 - this.#tokens) / this.#refillPerMs)
      );
      await new Promise((resolve) => setTimeout(resolve, waitMs));
      this.#refill();
      if (this.#tokens >= 1) {
        this.#tokens -= 1;
        return true;
      }
      return false;
    } finally {
      this.#queued -= 1;
    }
  }

  #refill(): void {
    const now = this.#now();
    const elapsed = Math.max(0, now - this.#updatedAt);
    this.#tokens = Math.min(
      this.#capacity,
      this.#tokens + elapsed * this.#refillPerMs
    );
    this.#updatedAt = now;
  }
}

export const defaultTsaTokenBucket = new TokenBucket({
  sustainedPerSecond: 0.8,
  burst: 5,
  queueDepth: 50,
  queueTimeoutMs: 250,
});
