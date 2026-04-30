import { describe, it, expect } from 'vitest';
import { buildScrubber, defaultScrubber } from '../../src/observability/scrubber.js';

describe('scrubber — value patterns (§6.6 / RT-44)', () => {
  it('redacts an agent-auth wire key', () => {
    const out = defaultScrubber.scrubLine('Authorization: Bearer agk_abc12345.' + 'a'.repeat(43));
    expect(out).toContain('[REDACTED:PATTERN]');
    expect(out).not.toMatch(/agk_/);
  });

  it('redacts a GitHub PAT', () => {
    const out = defaultScrubber.scrubLine(
      'token=ghp_' + 'a'.repeat(36) + ' rest=ok',
    );
    expect(out).toContain('[REDACTED:PATTERN]');
    expect(out).toContain('rest=ok');
  });

  it('redacts an Anthropic key', () => {
    expect(defaultScrubber.scrubLine('sk-ant-api03-XXXX')).toContain('[REDACTED:PATTERN]');
  });

  it('redacts an OpenAI key', () => {
    expect(defaultScrubber.scrubLine('sk-' + 'a'.repeat(40))).toContain('[REDACTED:PATTERN]');
  });
});

describe('scrubber — key-name patterns', () => {
  it('redacts the value of an authorization key', () => {
    const out = defaultScrubber.scrub({ Authorization: 'Bearer xyz' }) as { Authorization: string };
    expect(out.Authorization).toBe('[REDACTED:KEY]');
  });

  it('redacts the value of nested secret/password/token keys', () => {
    const out = defaultScrubber.scrub({
      meta: { token: 'abc', password: 'p', not_secret: 'plaintext' },
    }) as { meta: { token: string; password: string; not_secret: string } };
    expect(out.meta.token).toBe('[REDACTED:KEY]');
    expect(out.meta.password).toBe('[REDACTED:KEY]');
    expect(out.meta.not_secret).toBe('plaintext');
  });
});

describe('scrubber — high-entropy heuristic', () => {
  it('redacts a high-entropy 40+ char base64-shaped string', () => {
    const high = 'wK9aV/xQz+rT2Lp4yHnB8mC1eF7uG3iJ0kL2mN6oP8qR4sT6vX8z';
    const out = defaultScrubber.scrubLine(`token: ${high}`);
    expect(out).toContain('[REDACTED:ENTROPY]');
  });

  it('keeps short alphanumeric strings (UUIDs would otherwise false-positive)', () => {
    const uuid = '550e8400-e29b-41d4-a716-446655440000';
    expect(defaultScrubber.scrubLine(uuid)).toBe(uuid);
  });

  it('keeps prose with whitespace even if shannon entropy is high', () => {
    const text = 'This is a perfectly normal log line with many letters but spaces and so on';
    expect(defaultScrubber.scrubLine(text)).toBe(text);
  });
});

describe('scrubber — structural caps', () => {
  it('truncates strings beyond max_string_length', () => {
    const sc = buildScrubber({ max_string_length: 10 });
    const out = sc.scrubLine('x'.repeat(100));
    expect(out).toContain('TRUNCATED:LEN');
    expect(out.length).toBeLessThan(100);
  });

  it('truncates objects/arrays beyond max_jsonb_depth', () => {
    const sc = buildScrubber({ max_jsonb_depth: 2 });
    const out = sc.scrub({ a: { b: { c: { d: 1 } } } }) as Record<string, unknown>;
    // depth 0=root, 1=a, 2=b → c gets truncated
    expect(JSON.stringify(out)).toContain('TRUNCATED:DEPTH');
  });

  it('caps total serialized size', () => {
    const sc = buildScrubber({ max_serialized_size_kb: 0 });
    const out = sc.scrub({ big: 'x'.repeat(2000) }) as Record<string, unknown>;
    expect(out).toMatchObject({ truncated: true, reason: 'max_serialized_size_kb' });
  });
});

describe('scrubber — primitives + buffers', () => {
  it('passes through numbers, booleans, null, undefined', () => {
    expect(defaultScrubber.scrub(1)).toBe(1);
    expect(defaultScrubber.scrub(true)).toBe(true);
    expect(defaultScrubber.scrub(null)).toBeNull();
    expect(defaultScrubber.scrub(undefined)).toBeUndefined();
  });

  it('redacts Buffers without leaking content', () => {
    const out = defaultScrubber.scrub({ key_hash: Buffer.from([1, 2, 3]) }) as {
      key_hash: string;
    };
    expect(out.key_hash).toMatch(/^\[REDACTED:BUFFER:3b\]$/);
  });
});
