import { describe, it, expect } from 'vitest';
import {
  createCoSignerEnvelope,
  signCoSignerEnvelope,
  verifyCoSignature,
} from '../../src/admin/two-person.js';

const SECRET = Buffer.alloc(32, 9);

describe('two-person rule (SPEC §8.1 / RT-10 / RT-41)', () => {
  it('round-trips: envelope → signature → verify', () => {
    const env = createCoSignerEnvelope({
      op: 'close-account',
      target: 'acc-1',
      initiator: 'admin@saas',
      payload: 'reason=abuse',
    });
    const sig = signCoSignerEnvelope(env, SECRET);
    expect(() => verifyCoSignature(env, sig, SECRET)).not.toThrow();
  });

  it('rejects when target differs (canonical bytes mismatch)', () => {
    const env = createCoSignerEnvelope({
      op: 'close-account',
      target: 'acc-1',
      initiator: 'admin@saas',
      payload: '',
    });
    const sig = signCoSignerEnvelope(env, SECRET);
    const tampered = { ...env, target: 'acc-2', canonical: env.canonical.replace('acc-1', 'acc-2') };
    expect(() => verifyCoSignature(tampered, sig, SECRET)).toThrow(/co_signer_signature_mismatch/);
  });

  it('rejects malformed signature (wrong length / wrong charset)', () => {
    const env = createCoSignerEnvelope({
      op: 'flush-cache',
      target: '*',
      initiator: 'admin@saas',
      payload: '',
    });
    expect(() => verifyCoSignature(env, 'abc', SECRET)).toThrow(/malformed/);
  });

  it('rejects signature with timestamp older than 10 min', () => {
    const env = createCoSignerEnvelope({
      op: 'flush-cache',
      target: '*',
      initiator: 'a',
      payload: '',
      now_ms: Date.now() - 11 * 60 * 1000,
    });
    const sig = signCoSignerEnvelope(env, SECRET);
    expect(() => verifyCoSignature(env, sig, SECRET)).toThrow(/skew/);
  });
});
