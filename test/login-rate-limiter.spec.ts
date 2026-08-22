import assert from 'node:assert/strict';
import test from 'node:test';
import { HttpException, HttpStatus } from '@nestjs/common';
import { LoginRateLimiter } from '../src/login-rate-limiter.js';

test('limits repeated failed login attempts and resets after success', () => {
  process.env.IDENTITY_LOGIN_ATTEMPT_LIMIT = '2';
  process.env.IDENTITY_LOGIN_SOURCE_ATTEMPT_LIMIT = '10';
  process.env.IDENTITY_LOGIN_ATTEMPT_WINDOW_MS = '1000';
  const limiter = new LoginRateLimiter();
  limiter.assertAllowed('ip', 'user', 10);
  limiter.recordFailure('ip', 'user', 10);
  limiter.recordFailure('ip', 'user', 10);
  assert.throws(
    () => limiter.assertAllowed('ip', 'user', 10),
    (error) => error instanceof HttpException && error.getStatus() === HttpStatus.TOO_MANY_REQUESTS,
  );
  limiter.clear('user');
  assert.doesNotThrow(() => limiter.assertAllowed('ip', 'user', 10));
});

test('opens a new attempt window after expiration', () => {
  process.env.IDENTITY_LOGIN_ATTEMPT_LIMIT = '1';
  process.env.IDENTITY_LOGIN_SOURCE_ATTEMPT_LIMIT = '10';
  process.env.IDENTITY_LOGIN_ATTEMPT_WINDOW_MS = '100';
  const limiter = new LoginRateLimiter();
  limiter.recordFailure('ip', 'user', 10);
  assert.throws(
    () => limiter.assertAllowed('ip', 'user', 10),
    (error) => error instanceof HttpException && error.getStatus() === HttpStatus.TOO_MANY_REQUESTS,
  );
  assert.doesNotThrow(() => limiter.assertAllowed('ip', 'user', 111));
});

test('limits one source rotating through unique account identifiers', () => {
  process.env.IDENTITY_LOGIN_ATTEMPT_LIMIT = '5';
  process.env.IDENTITY_LOGIN_SOURCE_ATTEMPT_LIMIT = '3';
  process.env.IDENTITY_LOGIN_ATTEMPT_WINDOW_MS = '1000';
  const limiter = new LoginRateLimiter();

  for (let index = 0; index < 3; index += 1) {
    const email = `user-${index}@example.test`;
    limiter.assertAllowed('203.0.113.10', email, 10);
    limiter.recordFailure('203.0.113.10', email, 10);
  }

  assert.throws(
    () => limiter.assertAllowed('203.0.113.10', 'next-user@example.test', 10),
    (error) => error instanceof HttpException && error.getStatus() === HttpStatus.TOO_MANY_REQUESTS,
  );
});

test('sweeps expired account and source windows', () => {
  process.env.IDENTITY_LOGIN_ATTEMPT_LIMIT = '5';
  process.env.IDENTITY_LOGIN_SOURCE_ATTEMPT_LIMIT = '10';
  process.env.IDENTITY_LOGIN_ATTEMPT_WINDOW_MS = '100';
  const limiter = new LoginRateLimiter();
  limiter.recordFailure('203.0.113.10', 'old-user@example.test', 10);

  assert.equal((limiter as unknown as { windows: Map<string, unknown> }).windows.size, 2);
  limiter.assertAllowed('203.0.113.11', 'new-user@example.test', 111);
  assert.equal((limiter as unknown as { windows: Map<string, unknown> }).windows.size, 2);
});
