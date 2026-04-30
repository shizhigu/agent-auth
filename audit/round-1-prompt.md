# Audit request: agent-auth OSS thesis

Please audit the following product thesis and tell me honestly whether it's worth shipping. Be brutal. The user is solo, no network, has $2M family backing but needs W2 legitimacy, considering this as a side OSS project to land a senior eng job at agent infra companies (Anthropic, Orthogonal, Vercel, etc.). Not as a full-time startup.

## The thesis we developed (over a long conversation)

**Product positioning:**
"agent-auth: the parallel auth rail for AI agents. Drop it next to your existing human auth in 5 minutes. Your humans keep using what they have. Your agents use us."

**Key design decisions:**
1. Build from scratch, agent-native pure (no human auth flows: no passwords, no sessions, no cookies, no OAuth browser redirects)
2. ~1200 lines TypeScript, 2-3 weekends to ship v0.1
3. Parallel rail: SaaS keeps existing auth, mounts agent-auth as separate routes (e.g. /api/agent/v1)
4. 3-line install DX:
   ```ts
   const agents = agentAuth({
     identityProviders: [githubOAuth(...), anthropicApiKey()],
     storage: postgresAdapter(db),
     rateLimit: { perAccount: '1000/day' }
   })
   app.use('/api/agent-auth', agents.routes())
   app.use('/api/agent/v1', agents.middleware, agentRoutes)
   ```
5. Identity model: delegate KYC to upstream (GitHub OAuth, Anthropic API key, eventually Anthropic-signed attestations). Library does NOT hold user credentials long-term.
6. Spam prevention: tiered keys (cold/warm/hot) with auto-promotion based on time + clean behavior. No payment integration. SaaS owner provides their own payment hook if they want fast-track promotion.
7. Phase 1: pure OSS self-hostable. Phase 3 (12+ months out): hosted SaaS like Cal.com / Plausible / Supabase pattern.
8. Goal: not revenue. Goal is OSS portfolio piece to land W2 senior eng offer at Anthropic/Orthogonal/Vercel/etc.

## What I found doing market research

The space is crowded. Direct/adjacent competitors I found:

**Direct OSS competitors:**
1. **KavachOS** (github.com/kavachos/kavachos, MIT) - exact thesis already shipped. Agent identity tokens, per-agent permission scoping, delegation chains, trust scoring, audit trails, MCP OAuth 2.1 (PKCE, RFC 9728). "Only library designed with agents as primary concept." Smaller community, docs developing.
2. **Microsoft Agent Governance Toolkit** (github.com/microsoft/agent-governance-toolkit, MIT) - 7 packages, Python/TS/.NET/Rust/Go. Sub-millisecond policy engine, Ed25519 + quantum-safe identity, OWASP Agentic Top 10 coverage, EU AI Act / NIST AI RMF compliance. v3.3.0 released April 2026.
3. **Nango** (open source) - 700+ APIs pre-integrated for agents. Token refresh, white-label, no vendor lock-in.
4. **Arcade** (open source, self-hostable) - 21 APIs, API key + OAuth, "auto-checks permissions" before tool execution.
5. **ZeroID** - open-source identity platform for autonomous AI agents and multi-agent systems.

**Commercial competitors:**
1. **Auth0 for AI Agents** (Okta) - secure token vault, Vercel AI SDK + LangGraph integrations, 26 OAuth APIs.
2. **Stytch, Descope, WorkOS, Scalekit, Composio** - all have agent-specific products.

**YC-funded competitors:**
1. **Orthogonal (YC W26)** - API marketplace + payment for agents. 30+ partners (ScrapeGraph, People Data Labs, Apollo.io, Composio). Founders: ex-Coinbase payments + ex-Vercel billing + ex-Google reCAPTCHA. 2-person team. $10 free credits.

**Standards:**
1. **MCP-Auth** (Anthropic spec) - OAuth 2.0 is the only authentication method specified in MCP standard.
2. **x402** (Coinbase) - HTTP 402 Payment Required protocol with TS/Python/Go SDKs. Adopted by Cloudflare, Solana, Google A2A.

**Adjacent OSS:**
1. Better Auth - dominant TS auth lib, no agent support yet (but could add)
2. MCP TypeScript SDK - official, ships with auth helpers and OAuth helpers

## Specific questions I want you to audit

1. **Is the differentiation still meaningful?** "Parallel rail, drop-in 5 min, doesn't replace existing auth" — is this real differentiation or is KavachOS / Microsoft / Nango already covering this?

2. **Is the OSS-first then hosted Phase 3 path realistic given competition?** Better Auth, Cal.com, Plausible, Supabase took the OSS-first pattern. Will it work here when 5+ players are already shipping OSS?

3. **The W2 legitimacy goal:** would shipping this OSS lib actually move the needle for landing a senior eng job at Anthropic / Orthogonal / Vercel? Or is it now too "me too" given existing OSS competition?

4. **Honest go/no-go:** Should the user ship this or pick something less crowded? If pick something else, what's the actual unaddressed niche in agent infra OSS right now (April 2026)?

5. **If go, what specific angle/positioning would still get attention?** Is there a narrow scope (e.g. specific framework integration, specific identity provider niche) that's not covered by the existing 5+ players?

6. **Time-to-attention realistic estimate:** for a solo founder shipping an OSS lib in this crowded space starting April 2026, what's the realistic timeline to get 100 stars / 1000 stars / first commercial inquiry?

Please be brutal and specific. Don't sugarcoat. The user values honest pushback over encouragement.
