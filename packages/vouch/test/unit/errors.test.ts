import { describe, it, expect } from 'vitest';
import {
  AgentAuthError,
  ServiceUnavailableError,
  isAgentAuthError,
  reject,
} from '../../src/errors.js';

describe('AgentAuthError (SPEC §10.3 / §10.4)', () => {
  it('round-trips through toJSON in the wire shape', () => {
    const err = new AgentAuthError(401, 'invalid_secret', 'bad secret', {
      request_id: 'r1',
      documentation_url: 'https://example/docs#invalid_secret',
      details: { stage: 'hmac' },
    });
    expect(err.toJSON()).toEqual({
      error: {
        code: 'invalid_secret',
        message: 'bad secret',
        request_id: 'r1',
        documentation_url: 'https://example/docs#invalid_secret',
        details: { stage: 'hmac' },
      },
    });
  });

  it('omits optional fields when not provided', () => {
    const err = new AgentAuthError(404, 'account_not_found');
    expect(err.toJSON()).toEqual({
      error: { code: 'account_not_found', message: 'account_not_found' },
    });
  });

  it('isAgentAuthError narrows in catch blocks', () => {
    let caught: unknown;
    try {
      throw new AgentAuthError(409, 'already_revoked');
    } catch (err) {
      caught = err;
    }
    expect(isAgentAuthError(caught)).toBe(true);
  });

  it('reject() throws AgentAuthError', () => {
    expect(() => reject(401, 'invalid_key')).toThrowError(
      expect.objectContaining({ status: 401, code: 'invalid_key' }),
    );
  });

  it('preserves cause for internal logging without leaking it', () => {
    const cause = new Error('db connection lost');
    const err = new AgentAuthError(500, 'internal_error', undefined, { cause });
    expect((err as { cause?: unknown }).cause).toBe(cause);
    expect(err.toJSON().error).not.toHaveProperty('cause');
  });
});

describe('ServiceUnavailableError', () => {
  it('uses status 503 and only accepts 503 codes (compile-time guard)', () => {
    const err = new ServiceUnavailableError(
      'durability_unconfirmed',
      'awaiting standby ack',
    );
    expect(err.status).toBe(503);
    expect(err.code).toBe('durability_unconfirmed');
    expect(err).toBeInstanceOf(AgentAuthError);
  });

  it('headers are surfaced for routes (e.g. Retry-After)', () => {
    const err = new ServiceUnavailableError('idp_circuit_open', undefined, {
      headers: { 'Retry-After': '13' },
    });
    expect(err.headers).toEqual({ 'Retry-After': '13' });
  });
});
