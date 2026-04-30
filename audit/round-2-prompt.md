# Audit request: technical design of agent-auth library

DO NOT evaluate whether this market should be entered. DO NOT recommend pivots.
ONLY audit the TECHNICAL DESIGN of this specific solution. Find bugs, security holes, edge cases, race conditions, abstraction problems.

## The specific solution we designed

A TypeScript library that a SaaS provider drops into their backend (alongside their existing human auth, NOT replacing it). The library exposes endpoints that AI agents (e.g. Claude Code, Cursor agents) can hit to register an account on behalf of a human user, then receive an API key for subsequent calls.

This is NOT about: agent's own identity, MCP server auth, agent-to-agent comms, or holding tokens for already-authorized SaaS APIs. It IS specifically about: solving the "Claude Code can't autonomously sign up a user for vercel.com because of CAPTCHA / email verification" problem, by giving SaaS providers a way to expose an agent-native signup endpoint that bypasses those human-flow gates safely.

### Design decisions to audit

**1. Identity model: delegated KYC via upstream**
- Agent presents proof of holding an upstream identity:
  - Option A: GitHub OAuth bearer token (with read:user scope)
  - Option B: Anthropic API key (verified by call to Anthropic API)
  - Option C (future): Anthropic-signed attestation JWT
- Library verifies the proof, extracts a stable user_id (e.g. github:shizhigu), discards the proof
- One upstream identity = one SaaS account (enforced via DB unique constraint)

**2. Token lifecycle**
- After verification, library issues a SaaS-specific API key (random secret, prefixed)
- Key has scopes determined by SaaS owner config
- Key is revocable via /revoke endpoint
- Key validity verified by middleware on every request

**3. Spam prevention via tiered keys**
- Cold tier: just-registered. 100 calls/day. No paid features.
- Warm tier: auto-promoted after N days of clean usage. 1000 calls/day.
- Hot tier: requires SaaS owner approval (they call lib.promote(key, 'hot') from their own webhook handler, after their own verification — could be Stripe, could be GitHub repo verification, could be manual review).
- Library does NOT integrate Stripe or any payment system itself.

**4. Abuse signals (auto-detect, auto-revoke)**
- Velocity: same IP registers ≥5 agents in 1 hour → freeze all
- Behavior: error rate >50% over 24h → revoke
- Pattern: scraping-like read-only patterns → rate limit aggressively
- Owner alert: SaaS owner gets dashboard with suspicious agents to flag

**5. Architecture: parallel rail**
- SaaS keeps existing human auth completely unchanged
- They mount agent-auth on separate routes: /api/agent-auth/* (registration) and /api/agent/v1/* (protected)
- Agent endpoints expose a SUBSET of human endpoints, SaaS owner decides

**6. DX (3-line install)**
```ts
const agents = agentAuth({
  identityProviders: [githubOAuth({...}), anthropicApiKey()],
  storage: postgresAdapter(db),
  rateLimit: { perAccount: '1000/day' }
})
app.use('/api/agent-auth', agents.routes())
app.use('/api/agent/v1', agents.middleware, agentRoutes)
```

**7. Storage**
- Postgres table: `agent_accounts(id, upstream_identity, tier, created_at, last_active_at, revoked_at)`
- Redis: rate limit counters (sliding window)
- Audit log table: `agent_calls(id, account_id, ts, endpoint, ip, status, meta_jsonb)`

**8. Library does NOT hold long-term:**
- User's GitHub OAuth tokens (only verifies once, discards)
- User's Anthropic API key (only verifies once, discards)
- Any user PII beyond the upstream user_id reference

### Audit questions

1. Security: any holes in the identity verification flow? Token replay? TOCTOU between verification and key issuance? CSRF on /register?

2. Spam: will tier-based auto-promotion actually work? Can a determined attacker farm warm-tier accounts? What's the floor on attacker cost?

3. Edge cases:
   - User regenerates GitHub OAuth (revokes old token) — does our user_id binding still work?
   - Anthropic API key holder transfers their key (sells to spammer) — how does this propagate?
   - User signs up via GitHub, later wants to add Anthropic API key as second proof for higher tier — supported?
   - Multiple agents from same user (Claude Code + Cursor + custom) — same account or separate?

4. Storage / scaling:
   - Sliding window rate limit in Redis at high QPS — concurrency issues?
   - Audit log volume — partitioning? retention?
   - Key validation latency — caching strategy?

5. Abstraction:
   - Is the identityProvider plugin interface flexible enough for future protocols (x402, Anthropic attestation)?
   - Is the storage adapter abstraction right (Postgres + Redis)?
   - Is rateLimit config too coarse (only perAccount)?

6. DX gaps:
   - How does SaaS owner test this locally?
   - How does agent developer integrate without trial-and-error?
   - Migration path for SaaS that already has some agent traffic?

7. Threat model:
   - What does an attacker who compromises the library see?
   - What does an attacker who compromises a SaaS that USES the library see?
   - What does an attacker who steals an issued API key see?

Find the bugs and gaps in this DESIGN. Don't second-guess whether to build it.
