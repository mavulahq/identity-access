import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpException, HttpStatus } from '@nestjs/common';
import { LoginRateLimiter } from '../src/login-rate-limiter.js';

test('limits repeated failed login attempts and resets after success', () => {
  process.env.IDENTITY_LOGIN_ATTEMPT_LIMIT = '2';
  process.env.IDENTITY_LOGIN_ATTEMPT_WINDOW_MS = '1000';
  const limiter = new LoginRateLimiter();
  limiter.assertAllowed('ip:user', 10);
  limiter.recordFailure('ip:user', 10);
  limiter.recordFailure('ip:user', 10);
  assert.throws(
    () => limiter.assertAllowed('ip:user', 10),
    (error) => error instanceof HttpException && error.getStatus() === HttpStatus.TOO_MANY_REQUESTS,
  );
  limiter.clear('ip:user');
  assert.doesNotThrow(() => limiter.assertAllowed('ip:user', 10));
});

test('opens a new attempt window after expiration', () => {
  process.env.IDENTITY_LOGIN_ATTEMPT_LIMIT = '1';
  process.env.IDENTITY_LOGIN_ATTEMPT_WINDOW_MS = '100';
  const limiter = new LoginRateLimiter();
  limiter.recordFailure('ip:user', 10);
  assert.throws(
    () => limiter.assertAllowed('ip:user', 10),
    (error) => error instanceof HttpException && error.getStatus() === HttpStatus.TOO_MANY_REQUESTS,
  );
  assert.doesNotThrow(() => limiter.assertAllowed('ip:user', 111));
});
