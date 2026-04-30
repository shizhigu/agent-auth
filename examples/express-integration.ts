// agent-auth Express integration example
// See SPEC.md Part XI for full implementation plan.

import express from 'express';
import { agentAuth, githubApp } from 'agent-auth';
import { postgresAdapter, redisAdapter, kmsAdapter, s3WormAdapter } from 'agent-auth/adapters';

const app = express();
app.use(express.json({ limit: '4kb' }));

// ============================================================================
// Configure agent-auth
// ============================================================================

const agents = agentAuth({
  internal_secret: Buffer.from(process.env.AGENT_AUTH_INTERNAL_SECRET!, 'base64'),

  identity_providers: [
    githubApp({
      client_id: process.env.GH_CLIENT_ID!,
      client_secret: process.env.GH_CLIENT_SECRET!,
      webhook_secret: process.env.GH_WEBHOOK_SECRET!,
      app_private_key_pem: process.env.GH_APP_PRIVATE_KEY!,
      redirect_uri: 'https://saas.com/api/agent-auth/callback/github_app',
      default_assurance: 'medium',
      api_version: '2026-03-10',
      scopes: ['read:user']
    })
  ],

  storage: {
    postgres: postgresAdapter({ connection_string: process.env.DATABASE_URL! }),
    redis: redisAdapter({ url: process.env.REDIS_URL! }),
    kms: kmsAdapter({ region: 'us-east-1', pepper_key_alias: 'alias/agent-auth-pepper' }),
    audit_worm: s3WormAdapter({
      bucket: 'my-audit-worm',
      account_id: '222222222222',
      kms_key_alias: 'alias/audit-encryption',
      retention_years: 7
    })
  },

  rate_limit: {
    per_key: { burst: 100, period_seconds: 60 },
    per_account: { burst: 5000, period_seconds: 86400 },
    per_ip_registration: { burst: 5, period_seconds: 3600 },
    global_emergency: { burst: 1000000, period_seconds: 3600 }
  },

  validation: {
    barrier_mode: 'strict_uncached'  // production default
  },

  recover_account: {
    require_owner_approval: true,
    approval_webhook_url: 'https://saas.com/internal/agent-auth/approve-recovery',
    approval_timeout_seconds: 86400
  },

  revalidation: {
    policies: {
      default: { cadence_days: 14, forced_on_webhook_revoke: true },
      high_risk: { cadence_days: 1 }
    }
  }
});

// ============================================================================
// Existing human auth — UNTOUCHED
// ============================================================================

import { humanAuth } from './my-existing-auth';
app.use('/api/v1', humanAuth.middleware, /* ...existing routes... */);

// ============================================================================
// Mount agent-auth (3 lines)
// ============================================================================

app.use('/api/agent-auth', agents.routes());
app.use('/api/agent/v1', agents.middleware, agentRoutes);

// ============================================================================
// Agent-side route handlers use req.agent (NOT req.user)
// ============================================================================

const agentRoutes = express.Router();

agentRoutes.get('/data', (req, res) => {
  // req.agent is populated by agents.middleware
  // req.user is intentionally NOT populated by agent-auth (confused-deputy prevention)
  const agent = req.agent!;

  if (!agent.has_scope('read')) {
    return res.status(403).json({ error: { code: 'insufficient_scope', message: 'requires read' }});
  }

  // Tenant isolation: every query scoped by agent.account_id
  const data = await db.query(
    'SELECT * FROM customer_data WHERE account_id = $1',
    [agent.account_id]
  );
  res.json({ data: data.rows });
});

agentRoutes.post('/expensive', (req, res) => {
  const agent = req.agent!;
  agent.require_scope('write');  // throws AgentAuthError 403 if missing

  if (agent.tier !== 'hot') {
    return res.status(402).json({
      error: {
        code: 'requires_hot_tier',
        message: 'Upgrade to hot tier; contact admin'
      }
    });
  }

  // Implementation
  res.json({ status: 'ok' });
});

// ============================================================================
// Start server
// ============================================================================

agents.scheduled_jobs.start();  // background worker pool

const port = process.env.PORT || 8080;
app.listen(port, () => {
  console.log(`Listening on ${port} (agent-auth ${agents.version})`);
});

// ============================================================================
// Graceful shutdown
// ============================================================================

process.on('SIGTERM', async () => {
  await agents.shutdown();
  await app.close();
  process.exit(0);
});
