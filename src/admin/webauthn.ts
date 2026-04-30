/**
 * WebAuthn / FIDO2 verifier interface for the admin CLI. SPEC §8.1.
 *
 * The lib does NOT bundle a full FIDO2 verifier (depends on the SaaS's
 * relying-party policy, attested keys, U2F vs platform authenticators).
 * Instead we expose:
 *
 *   - the data shape required by `assertWebAuthn()`
 *   - a pluggable `WebAuthnVerifier` interface the CLI calls before any
 *     destructive admin op
 *   - a `noopWebAuthnVerifier` for tests + dev
 *
 * Production deployments wire in @simplewebauthn/server (or their own
 * verifier) and pass that into the AdminCLIConfig. The interface is
 * stable so we can plug different verifiers without changing callers.
 */

import { AgentAuthError } from '../errors.js';

export interface WebAuthnAssertion {
  /** RP-supplied challenge that's part of the canonical bytes the
   *  authenticator signed. */
  readonly challenge: string;
  /** Origin (e.g. https://admin.saas.example). RP enforces an allow-list. */
  readonly origin: string;
  /** base64url(authenticator's response). Format depends on platform. */
  readonly response_b64: string;
  /** Credential ID the authenticator self-identified as. */
  readonly credential_id: string;
}

export interface WebAuthnVerifier {
  verify(input: {
    admin_id: string;
    operation: string;
    assertion: WebAuthnAssertion;
  }): Promise<void>;
}

/** Pass-through verifier — accepts any assertion. ONLY for tests. */
export const noopWebAuthnVerifier: WebAuthnVerifier = {
  async verify() {
    /* accept */
  },
};

/**
 * Convenience: throws AgentAuthError(401) if the verifier rejects.
 * Caller layer has already extracted the assertion from request input.
 */
export async function assertWebAuthn(
  verifier: WebAuthnVerifier,
  input: { admin_id: string; operation: string; assertion: WebAuthnAssertion },
): Promise<void> {
  try {
    await verifier.verify(input);
  } catch (err) {
    throw new AgentAuthError(
      401,
      'invalid_request',
      'webauthn_assertion_failed',
      { cause: err },
    );
  }
}
