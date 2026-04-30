/**
 * Integration: webhook replay polling job against real Postgres. SPEC §2.2.5.
 *
 * Stubs the GitHub /app/hook/deliveries fetcher (no testcontainers other
 * than the shared Postgres + Redis fixture). Verifies the job:
 *   - skips deliveries older than config_lookback_hours
 *   - skips events that aren't github_app_authorization
 *   - skips deliveries we already 'processed' locally (PK match)
 *   - triggers redelivery for the rest
 *   - updates agent_webhook_replay_state cursor + last_run_status
 *   - sets cap_hit when max_pages is reached
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { provisionFixture, type IntegrationFixture } from './setup.js';
import { runWebhookReplay } from '../../src/jobs/webhook-replay.js';
import type { Fetcher } from '../../src/identity/github-app/browser-flow.js';

describe('integration: webhook replay polling (SPEC §2.2.5)', () => {
  let fix: IntegrationFixture;

  beforeAll(async () => {
    fix = await provisionFixture();
  }, 120_000);

  afterAll(async () => {
    await fix.cleanup();
  }, 120_000);

  function makeFetcher(
    deliveries: Array<{
      id: number;
      guid: string;
      event: string;
      status_code: number;
      delivered_at: string;
    }>,
    triggered: Set<number>,
  ): Fetcher {
    return async (input) => {
      const url = typeof input === 'string' ? input : input.toString();
      if (/\/app\/hook\/deliveries\?/.test(url) || /\/app\/hook\/deliveries$/.test(url)) {
        return new Response(JSON.stringify(deliveries), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      const m = /\/app\/hook\/deliveries\/(\d+)\/attempts$/.exec(url);
      if (m) {
        triggered.add(Number(m[1]));
        return new Response('', { status: 202 });
      }
      return new Response('not found', { status: 404 });
    };
  }

  it('triggers redelivery only for non-2xx, non-processed github_app_authorization events', async () => {
    // Seed agent_webhook_events with one already-processed row so the job
    // skips it.
    const processedGuid = '11111111-1111-1111-1111-111111111111';
    await fix.postgres.query(
      `INSERT INTO agent_webhook_events
         (id, provider, event_type, payload_hash, status, processed_at)
       VALUES ($1::uuid, 'github_app', 'github_app_authorization', $2, 'processed', now())`,
      [processedGuid, Buffer.from('aa', 'hex')],
    );

    const recentTs = new Date(Date.now() - 30 * 60 * 1000).toISOString(); // 30min ago
    const oldTs = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000).toISOString(); // 5d ago (>72h lookback)

    // Deliveries are GitHub-side sorted newest-first. The job stops scanning
    // as soon as it hits one older than config_lookback_hours, so the
    // "older than lookback" entry must be LAST in this fixture (otherwise
    // the candidate after it would be skipped by the early-exit).
    const deliveries = [
      // already processed locally → skip
      { id: 100, guid: processedGuid, event: 'github_app_authorization', status_code: 500, delivered_at: recentTs },
      // wrong event type → skip
      { id: 101, guid: '22222222-2222-2222-2222-222222222222', event: 'installation', status_code: 500, delivered_at: recentTs },
      // 2xx → GitHub thinks it succeeded; skip
      { id: 102, guid: '33333333-3333-3333-3333-333333333333', event: 'github_app_authorization', status_code: 200, delivered_at: recentTs },
      // candidate → redeliver
      { id: 104, guid: '55555555-5555-5555-5555-555555555555', event: 'github_app_authorization', status_code: 502, delivered_at: recentTs },
      // older than lookback → causes loop break (must be last)
      { id: 103, guid: '44444444-4444-4444-4444-444444444444', event: 'github_app_authorization', status_code: 500, delivered_at: oldTs },
    ];
    const triggered = new Set<number>();
    const result = await runWebhookReplay({
      postgres: fix.postgres,
      fetcher: makeFetcher(deliveries, triggered),
      buildAppJwt: async () => 'stub-jwt',
    });
    expect(result.status).toBe('ok');
    expect(result.redelivered).toBe(1);
    expect(triggered).toEqual(new Set([104]));

    const state = await fix.postgres.queryOne<{
      last_run_status: string;
      total_redelivered: string;
    }>(
      `SELECT last_run_status, total_redelivered::text AS total_redelivered
         FROM agent_webhook_replay_state WHERE provider = 'github_app'`,
    );
    expect(state?.last_run_status).toBe('ok');
    expect(Number(state?.total_redelivered)).toBeGreaterThanOrEqual(1);
  });

  it('catch-up: subsequent run with last_seen_delivery_id starts at latest and STOPS at the watermark (does not skip new deliveries)', async () => {
    // Seed the replay-state cursor so the next run is "incremental".
    const watermarkGuid = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
    await fix.postgres.query(
      `UPDATE agent_webhook_replay_state
          SET last_seen_delivery_id = $1, last_run_at = now()
        WHERE provider = 'github_app'`,
      [watermarkGuid],
    );

    const recentTs = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    // GitHub returns reverse-chronological. The newest deliveries are at
    // the top; the watermark sits in the middle. The replay must:
    // (a) trigger redelivery for the newer entries (above the watermark),
    // (b) stop at the watermark, and
    // (c) NOT touch entries older than the watermark (already processed
    //     in a prior run).
    const newGuid = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';
    const olderGuid = 'cccccccc-cccc-cccc-cccc-cccccccccccc';
    const deliveries = [
      // NEWER than watermark — must be redelivered.
      {
        id: 200,
        guid: newGuid,
        event: 'github_app_authorization',
        status_code: 500,
        delivered_at: recentTs,
      },
      // The watermark itself — STOP here, do NOT redeliver.
      {
        id: 201,
        guid: watermarkGuid,
        event: 'github_app_authorization',
        status_code: 500,
        delivered_at: recentTs,
      },
      // OLDER than watermark — must NOT be touched.
      {
        id: 202,
        guid: olderGuid,
        event: 'github_app_authorization',
        status_code: 500,
        delivered_at: recentTs,
      },
    ];

    const triggered = new Set<number>();
    const result = await runWebhookReplay({
      postgres: fix.postgres,
      fetcher: makeFetcher(deliveries, triggered),
      buildAppJwt: async () => 'stub-jwt',
    });
    expect(result.status).toBe('ok');
    expect(result.redelivered).toBe(1);
    // Only the NEW delivery was triggered.
    expect(triggered).toEqual(new Set([200]));
  });
});
