# Break-glass admin procedure

Authoritative reference for the SPEC §8.1 break-glass path. Use only
when normal admin login (SSO + JIT-RBAC) is unavailable or compromised.
Mitigates **RT-38** (SSO/IdP compromise).

## When this applies

Trigger conditions:

1. Identity provider (Okta / Google Workspace / Azure AD) is offline or
   suspected compromised.
2. JIT-RBAC grant pipeline cannot issue a fresh grant (e.g., the
   grant-issuer service is wedged or its credentials are believed
   leaked).
3. A P0 security incident requires immediate revoke / suspend / cache
   flush before SSO can be restored or rotated.

If none of the above apply, do **not** use break-glass. Use the normal
`agent-auth admin grant` flow instead.

## Independence invariant

The break-glass path MUST NOT share a trust root with SSO. The
mechanism is:

- A pair of **physical YubiKeys** held by the CISO and the VP of
  Engineering, locked in two separate firesafes in two separate
  buildings. Each YubiKey is enrolled as a WebAuthn authenticator for
  a dedicated `admin_id` (`break_glass_a`, `break_glass_b`).
- A **break-glass JIT-RBAC seed** stored in a sealed envelope alongside
  each YubiKey. The seed lets the operator manually `JitRbac.grant(...)`
  without contacting the grant-issuer service.
- The break-glass admin IDs are pre-provisioned in the database; no
  account creation is required at incident time.

Both must be physically retrieved by two different people. Neither
person alone can use the path.

## Procedure

### Step 1 — Convene the two-person team

- **Initiator** (CISO): retrieves YubiKey A + seed envelope A.
- **Co-signer** (VP Eng): retrieves YubiKey B + seed envelope B.
- They meet in person OR over a recorded video call. **Both must be
  visually present for the entire procedure.**
- Open an incident ticket; both names recorded.

### Step 2 — Issue a JIT grant manually

On a clean engineering laptop (not the initiator's daily laptop —
fresh image, no SSO):

```bash
agent-auth admin grant \
  --admin-id break_glass_a \
  --role agent_auth_admin \
  --ttl-seconds 1800 \
  --reason "RT-38 incident #INC-2026-04-30 — SSO suspected compromised" \
  --break-glass
```

The `--break-glass` flag:

- bypasses the SSO check on `agent-auth admin grant`,
- requires the seed-envelope token instead,
- writes an audit row with `event_type='admin_grant'` and
  `meta.break_glass=true`.

### Step 3 — Run the destructive command

Every break-glass command requires the two-person co-signature
envelope (see `src/admin/two-person.ts`). For example, force-revoke a
single key:

```bash
# Initiator drafts the envelope:
agent-auth admin co-signer-envelope \
  --op revoke-key \
  --target agk_aB1cD2eF \
  --initiator break_glass_a > envelope.json

# Co-signer signs it on their own laptop:
agent-auth admin co-signer-sign \
  --envelope envelope.json \
  --admin-id break_glass_b > envelope.signed.json

# Initiator runs the command:
agent-auth admin revoke-key \
  --key-id agk_aB1cD2eF \
  --reason "RT-38 incident #INC-2026-04-30" \
  --webauthn-assertion-file ./yubikey-a.webauthn.json \
  --co-signer-envelope envelope.signed.json \
  --break-glass
```

The audit row carries `meta.break_glass=true` so post-incident audit
tooling can list every break-glass action in one query:

```sql
SELECT id, ts, event_type, meta->>'admin_id', meta->>'reason'
  FROM agent_audit_log
 WHERE meta @> '{"break_glass": true}'
   AND ts > now() - interval '7 days'
 ORDER BY ts DESC;
```

### Step 4 — Restore SSO and revoke break-glass grants

Within the same session:

```bash
agent-auth admin revoke-grants --admin-id break_glass_a --reason "incident closed"
agent-auth admin revoke-grants --admin-id break_glass_b --reason "incident closed"
```

This zeroes the in-memory JitRbac entries and writes
`event_type='admin_revoke'` audit rows. Confirm with:

```bash
agent-auth admin show-grants --admin-id break_glass_a   # expect: empty
```

### Step 5 — Post-mortem (within 24 hours)

Per SPEC §8.1 (`incident_post_mortem: required_within_24h`):

- Convene the on-call team + CISO.
- Write a blameless post-mortem in `incidents/INC-YYYY-MM-DD.md`.
- Cover:
  1. **Trigger** — what made SSO unavailable / suspect.
  2. **Detection** — alert source + timestamp.
  3. **Actions** — every break-glass command + audit row id.
  4. **Recovery** — SSO restoration steps + key rotation if compromise
     was real.
  5. **Follow-ups** — Jira tickets for any gaps the procedure exposed.
- Attach the audit-log query above as Appendix A.
- Distribute to engineering leadership + board within the 24h window.

## Forbidden uses

- Bypassing JIT-RBAC for routine work (e.g., "SSO is slow, let's just
  break-glass") — this defeats the audit trail and trains operators to
  reach for the wrong tool.
- Single-person break-glass — even if the co-signer is asleep. If the
  incident truly cannot wait, page the on-call backup co-signer; do
  not skip the second human.
- Re-using break-glass YubiKeys for non-incident tasks — they are
  burned to incident response. Rotate the YubiKeys after every use
  (re-enroll as new authenticators, replace the seed envelopes).

## Quarterly drill

Per SPEC §8.3.3 quarterly DR drills include a break-glass tabletop
exercise:

- Simulate the SSO-compromise trigger.
- Walk through Steps 1-5 against the staging environment.
- Time the end-to-end procedure; target ≤ 30 minutes from "trigger
  detected" to "destructive command issued".
- Update this doc if the procedure was inadequate.

## See also

- SPEC.md §8.1 (admin auth model) and §8.3.3 (DR drill)
- `src/admin/jit-rbac.ts` (grant store)
- `src/admin/two-person.ts` (co-signer envelope + signature)
- `src/admin/webauthn.ts` (WebAuthn verifier interface)
- `docs/runbooks/INDEX.md` (RB-1 through RB-9)
