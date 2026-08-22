import { HttpException, HttpStatus, Injectable } from '@nestjs/common';

interface AttemptWindow {
  attempts: number;
  resetAt: number;
}

@Injectable()
export class LoginRateLimiter {
  private readonly windows = new Map<string, AttemptWindow>();
  private readonly limit = Number(process.env.IDENTITY_LOGIN_ATTEMPT_LIMIT || 5);
  private readonly sourceLimit = Number(process.env.IDENTITY_LOGIN_SOURCE_ATTEMPT_LIMIT || 50);
  private readonly windowMs = Number(process.env.IDENTITY_LOGIN_ATTEMPT_WINDOW_MS || 300_000);
  private readonly sweepIntervalMs = Math.min(this.windowMs, 60_000);
  private nextSweepAt = 0;

  assertAllowed(remoteAddress: string, email: string, now = Date.now()): void {
    this.sweep(now);
    this.assertWindow(this.sourceKey(remoteAddress), this.sourceLimit, now);
    this.assertWindow(this.accountKey(email), this.limit, now);
  }

  recordFailure(remoteAddress: string, email: string, now = Date.now()): void {
    this.sweep(now);
    this.increment(this.sourceKey(remoteAddress), now);
    this.increment(this.accountKey(email), now);
  }

  clear(email: string): void {
    this.windows.delete(this.accountKey(email));
  }

  private assertWindow(key: string, limit: number, now: number): void {
    const current = this.windows.get(key);
    if (!current || current.resetAt <= now) {
      this.windows.set(key, { attempts: 0, resetAt: now + this.windowMs });
      return;
    }
    if (current.attempts >= limit) {
      throw new HttpException('Too many authentication attempts', HttpStatus.TOO_MANY_REQUESTS);
    }
  }

  private increment(key: string, now: number): void {
    const current = this.windows.get(key);
    if (!current || current.resetAt <= now) {
      this.windows.set(key, { attempts: 1, resetAt: now + this.windowMs });
      return;
    }
    current.attempts += 1;
  }

  private sweep(now: number): void {
    if (now < this.nextSweepAt) return;
    for (const [key, window] of this.windows) {
      if (window.resetAt <= now) this.windows.delete(key);
    }
    this.nextSweepAt = now + this.sweepIntervalMs;
  }

  private sourceKey(remoteAddress: string): string {
    return `source:${remoteAddress}`;
  }

  private accountKey(email: string): string {
    return `account:${email}`;
  }
}
