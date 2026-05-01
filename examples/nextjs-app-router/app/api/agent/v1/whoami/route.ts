/**
 * Example protected route: GET /api/agent/v1/whoami
 *
 * Validates the Bearer token via auth.lifecycle.validateBearer and
 * returns the resolved AgentContext.
 *
 * Drop at: app/api/agent/v1/whoami/route.ts
 */
import { NextRequest, NextResponse } from 'next/server';
import { vouch, type VouchInstance } from '@vouch/server';

let _auth: Promise<VouchInstance> | null = null;
function getAuth() {
  if (!_auth) {
    _auth = vouch({
      database: { url: process.env.DATABASE_URL! },
      redis: { url: process.env.REDIS_URL! },
      kms: {
        provider: 'aws',
        region: process.env.AWS_REGION ?? 'us-east-1',
        pepper_alias: process.env.KMS_PEPPER_ALIAS!,
        device_alias: process.env.KMS_DEVICE_ALIAS!,
        pepperFetcher: async (_v) => {
          throw new Error('pepperFetcher not implemented');
        },
      },
      identity: {
        github: {
          client_id: process.env.GH_CLIENT_ID!,
          client_secret: process.env.GH_CLIENT_SECRET!,
          webhook_secret: process.env.GH_WEBHOOK_SECRET!,
          app_private_key_pem: process.env.GH_APP_PRIVATE_KEY!,
        },
      },
      internal_secret: process.env.AGENT_AUTH_INTERNAL_SECRET!,
      base_url: process.env.PUBLIC_BASE_URL!,
    });
  }
  return _auth;
}

export async function GET(req: NextRequest) {
  const m = /^Bearer\s+(.+)$/i.exec(req.headers.get('authorization') ?? '');
  const bearer = m?.[1]?.trim();
  if (!bearer) {
    return NextResponse.json({ error: { code: 'invalid_key' } }, { status: 401 });
  }

  try {
    const auth = await getAuth();
    const agent = await auth.lifecycle.validateBearer(bearer);
    return NextResponse.json({
      account_id: agent.account_id,
      key_id: agent.key_id,
      identity: {
        provider: agent.identity.provider,
        subject: agent.identity.subject,
        display_handle: agent.identity.display_handle,
      },
      scopes: agent.scopes,
      tier: agent.tier,
    });
  } catch (err) {
    const e = err as { status?: number; code?: string; message?: string };
    return NextResponse.json(
      { error: { code: e.code ?? 'invalid_key', message: e.message ?? 'auth failed' } },
      { status: e.status ?? 401 },
    );
  }
}
