import { describe, it, expect } from 'vitest';
import {
  generatePkcePair,
  deriveChallenge,
  verifyVerifier,
} from '../../src/crypto/pkce.js';

describe('PKCE S256 (RFC 7636)', () => {
  it('generated verifier is 43 base64url chars and method is S256', () => {
    const p = generatePkcePair();
    expect(p.verifier.length).toBe(43);
    expect(p.method).toBe('S256');
    expect(/^[A-Za-z0-9_-]+$/.test(p.verifier)).toBe(true);
    expect(/^[A-Za-z0-9_-]+$/.test(p.challenge)).toBe(true);
  });

  it('challenge is sha256(verifier) base64url-encoded — round-trip', () => {
    const p = generatePkcePair();
    expect(deriveChallenge(p.verifier)).toBe(p.challenge);
    expect(verifyVerifier(p.verifier, p.challenge)).toBe(true);
  });

  it('matches RFC 7636 Appendix B test vector', () => {
    // RFC 7636 Appendix B uses verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    // and expects challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".
    const verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
    expect(deriveChallenge(verifier)).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });

  it('rejects too-short verifier', () => {
    expect(() => deriveChallenge('short')).toThrow();
  });

  it('rejects verifier with disallowed chars', () => {
    const bad = 'a'.repeat(43).slice(0, 42) + '!';
    expect(() => deriveChallenge(bad)).toThrow();
  });

  it('verifyVerifier returns false on mismatch (no throw)', () => {
    expect(verifyVerifier('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk', 'wrong')).toBe(false);
  });
});
