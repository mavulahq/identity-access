import { HttpException, HttpStatus, Injectable } from '@nestjs/common';

interface AttemptWindow {
  attempts: number;
  resetAt: number;
}

@Injectable()
export class LoginRateLimiter {
  private readonly windows = new Map<string, AttemptWindow>();
  private readonly limit = Number(process.env.IDENTITY_LOGIN_ATTEMPT_LIMIT || 5);
  private readonly windowMs = Number(process.env.IDENTITY_LOGIN_ATTEMPT_WINDOW_MS || 300_000);

  assertAllowed(key: string, now = Date.now()): void {
    const current = this.windows.get(key);
    if (!current || current.resetAt <= now) {
      this.windows.set(key, { attempts: 0, resetAt: now + this.windowMs });
      return;
    }
    if (current.attempts >= this.limit) {
      throw new HttpException('Too many authentication attempts', HttpStatus.TOO_MANY_REQUESTS);
    }
  }

  recordFailure(key: string, now = Date.now()): void {
    const current = this.windows.get(key);
    if (!current || current.resetAt <= now) {
      this.windows.set(key, { attempts: 1, resetAt: now + this.windowMs });
      return;
    }
    current.attempts += 1;
  }

  clear(key: string): void {
    this.windows.delete(key);
  }
}
