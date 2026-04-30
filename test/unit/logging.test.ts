import { describe, it, expect } from 'vitest';
import { makeArrayLogger, createLogger } from '../../src/observability/logging.js';

describe('Logger (SPEC §7.2 + §6.6)', () => {
  it('emits structured JSON records', () => {
    const { logger, records } = makeArrayLogger();
    logger.info('hello', { foo: 'bar' });
    expect(records).toHaveLength(1);
    expect(records[0]).toMatchObject({ level: 'info', msg: 'hello', foo: 'bar' });
    expect(records[0]!.ts).toMatch(/T/);
  });

  it('runs message + meta through the scrubber (no secret leakage)', () => {
    const { logger, records } = makeArrayLogger();
    logger.warn('Authorization: Bearer agk_xxxx1234.' + 'a'.repeat(43), {
      Authorization: 'Bearer agk_xxxx1234.' + 'a'.repeat(43),
      user: { token: 'sk-' + 'a'.repeat(40), name: 'octocat' },
    });
    const r = records[0]! as unknown as {
      msg: string;
      Authorization: string;
      user: { token: string; name: string };
    };
    expect(r.msg).toContain('[REDACTED:PATTERN]');
    expect(r.Authorization).toBe('[REDACTED:KEY]');
    expect(r.user.token).toBe('[REDACTED:KEY]');
    expect(r.user.name).toBe('octocat');
  });

  it('meta keys never override the canonical top-level fields (SPEC §7.2)', () => {
    // SPEC §7.2 mandates `ts`, `level`, `msg` as canonical fields. A
    // SaaS that accidentally includes the same key in `meta` (e.g.
    // logging an event whose payload happens to have `level` in it)
    // must not silently rewrite the record's level — that would make
    // log analytics report the wrong severity.
    const { logger, records } = makeArrayLogger();
    logger.warn('hello', {
      level: 'debug',         // attacker / accident
      ts: 'fake-ts',          // attacker / accident
      msg: 'overridden',      // attacker / accident
      foo: 'bar',
    });
    expect(records).toHaveLength(1);
    expect(records[0]!.level).toBe('warn');
    expect(records[0]!.msg).toBe('hello');
    // Canonical ts is an ISO date string, not the user-supplied 'fake-ts'.
    expect(records[0]!.ts).not.toBe('fake-ts');
    expect(records[0]!.ts).toMatch(/T/);
    // Other meta keys still flow through.
    expect(records[0]!.foo).toBe('bar');
  });

  it('respects minLevel', () => {
    const records: unknown[] = [];
    const logger = createLogger({
      minLevel: 'warn',
      emit: (rec) => records.push(rec),
    });
    logger.debug('drop me');
    logger.info('drop me');
    logger.warn('keep me');
    logger.error('keep me');
    logger.alert('keep me');
    expect(records).toHaveLength(3);
  });
});
