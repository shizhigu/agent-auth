/**
 * Webhook replay job. SPEC §2.2.5.
 *
 * GitHub does NOT auto-redeliver failed webhooks. We poll
 * `GET /app/hook/deliveries` and ask GitHub to re-send any delivery that
 * matches `github_app_authorization` AND that we have NOT successfully
 * processed (status 'received'/'failed' or no row at all).
 *
 * The job is idempotent: re-attempting a delivery is a GitHub-side no-op
 * if we already processed it (our `agent_webhook_events` PK is the
 * delivery UUID), so a redelivery is at worst a duplicate-detection at
 * /webhooks/:provider.
 */

import type { PostgresAdapter } from '../storage/postgres-adapter.js';
import type { Fetcher } from '../identity/github-app/browser-flow.js';

interface ReplayState {
  provider: string;
  last_seen_delivery_id: string | null;
  last_run_at: Date | null;
  last_run_status: 'ok' | 'partial' | 'failed' | 'cap_hit' | null;
  catch_up_pages: number;
  total_redelivered: string; // BIGINT comes back as text
  config_max_pages: number;
  config_lookback_hours: number;
  config_poll_interval_seconds: number;
}

interface DeliverySummary {
  /** GitHub-side delivery row id (different from `guid`). */
  id: number;
  /** UUID also stored as our PK. */
  guid: string;
  delivered_at: string;
  status_code: number;
  event: string;
  /** Optional fields irrelevant to redelivery decision. */
}

export interface WebhookReplayDeps {
  readonly postgres: PostgresAdapter;
  readonly fetcher?: Fetcher;
  /** Builds the App JWT for /app/hook/deliveries. Provided by app config. */
  readonly buildAppJwt: () => Promise<string>;
  /** GitHub API host; default api.github.com (overridable for tests). */
  readonly github_api_host?: string;
  /** API version header. */
  readonly api_version?: string;
  /** Now for tests. */
  readonly now?: () => Date;
  /** Optional metric / alert hook. */
  readonly onAlert?: (label: string, meta: Record<string, unknown>) => void;
}

export interface WebhookReplayResult {
  readonly inspected_pages: number;
  readonly redelivered: number;
  readonly cap_hit: boolean;
  readonly status: 'ok' | 'partial' | 'failed' | 'cap_hit';
}

export async function runWebhookReplay(
  deps: WebhookReplayDeps,
): Promise<WebhookReplayResult> {
  const fetcher = deps.fetcher ?? fetch;
  const host = deps.github_api_host ?? 'https://api.github.com';
  const apiVersion = deps.api_version ?? '2022-11-28';
  const now = deps.now ? deps.now() : new Date();

  const state = await deps.postgres.queryOne<ReplayState>(
    `SELECT provider, last_seen_delivery_id, last_run_at, last_run_status,
            catch_up_pages, total_redelivered::text AS total_redelivered,
            config_max_pages, config_lookback_hours, config_poll_interval_seconds
       FROM agent_webhook_replay_state
      WHERE provider = 'github_app'`,
  );
  if (!state) {
    throw new Error('webhook_replay_state_missing: github_app row not seeded');
  }

  const cutoff = new Date(now.getTime() - state.config_lookback_hours * 3600 * 1000);

  const jwt = await deps.buildAppJwt();
  // GitHub's `cursor` query param fetches deliveries OLDER than the given
  // guid — pagination is reverse-chronological. So we always START at the
  // latest (cursor=null) and let `last_seen_delivery_id` act as the inner-
  // loop EARLY-STOP marker once we recognize previously-processed territory.
  // Initial bug: cursor was seeded from `state.last_seen_delivery_id`,
  // which made the catch-up run skip past every NEW delivery and only
  // re-scan already-processed older ones.
  let cursor: string | null = null;
  const stopAtGuid = state.last_seen_delivery_id;
  let pageCount = 0;
  let redelivered = 0;
  let firstDeliveryThisPage: string | null = null;
  // We exited the loop "naturally" if any of the inner break paths
  // fired (empty page, watermark hit, cutoff, partial page). cap_hit
  // is the WHILE condition failing on its own — i.e., we ran the full
  // budget AND the last page was full AND we never hit the watermark
  // or cutoff. Without this flag, exits via partial-page-on-iteration-N
  // (where N == max_pages) would falsely report cap_hit and page
  // operators about a backlog that doesn't exist.
  let stoppedEarly = false;

  while (pageCount < state.config_max_pages) {
    pageCount++;
    const url = new URL(`${host}/app/hook/deliveries`);
    url.searchParams.set('per_page', '100');
    if (cursor) url.searchParams.set('cursor', cursor);

    const resp = await fetcher(url, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${jwt}`,
        Accept: 'application/vnd.github+json',
        'X-GitHub-Api-Version': apiVersion,
        'User-Agent': 'agent-auth/0.1 webhook-replay',
      },
    });
    if (!resp.ok) {
      await markRunStatus(deps.postgres, 'failed', { redelivered });
      return { inspected_pages: pageCount, redelivered, cap_hit: false, status: 'failed' };
    }
    const page = (await resp.json()) as DeliverySummary[];
    if (!Array.isArray(page) || page.length === 0) {
      stoppedEarly = true;
      break;
    }

    if (firstDeliveryThisPage === null) {
      firstDeliveryThisPage = page[0]!.guid;
    }

    let stop = false;
    for (const delivery of page) {
      // Reach previously-processed territory? Stop. Subsequent deliveries
      // (older) were already handled by a prior run.
      if (stopAtGuid !== null && delivery.guid === stopAtGuid) {
        stop = true;
        break;
      }
      const deliveredAt = Date.parse(delivery.delivered_at);
      if (Number.isFinite(deliveredAt) && deliveredAt < cutoff.getTime()) {
        stop = true;
        break;
      }
      if (delivery.event !== 'github_app_authorization') continue;
      if (delivery.status_code >= 200 && delivery.status_code < 300) continue;

      const local = await deps.postgres.queryOne<{ status: string }>(
        `SELECT status FROM agent_webhook_events WHERE id = $1::uuid`,
        [delivery.guid],
      );
      if (local?.status === 'processed') continue;

      // Trigger redelivery.
      const trigger = await fetcher(
        `${host}/app/hook/deliveries/${delivery.id}/attempts`,
        {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${jwt}`,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': apiVersion,
            'User-Agent': 'agent-auth/0.1 webhook-replay',
          },
        },
      );
      if (trigger.ok) redelivered++;
    }
    if (stop) {
      stoppedEarly = true;
      break;
    }
    if (page.length < 100) {
      stoppedEarly = true;
      break;
    }
    cursor = page[page.length - 1]!.guid;
  }
  const capHit = !stoppedEarly;
  if (capHit) {
    deps.onAlert?.('agent_auth.webhook_replay.cap_hit', {
      max_pages: state.config_max_pages,
    });
  }

  // Update cursor to first delivery of the most recent page.
  await deps.postgres.query(
    `UPDATE agent_webhook_replay_state
        SET last_seen_delivery_id = COALESCE($2, last_seen_delivery_id),
            last_run_at = $1,
            last_run_status = $3,
            catch_up_pages = catch_up_pages + $4,
            total_redelivered = total_redelivered + $5
      WHERE provider = 'github_app'`,
    [now, firstDeliveryThisPage, capHit ? 'cap_hit' : 'ok', pageCount, redelivered],
  );

  return {
    inspected_pages: pageCount,
    redelivered,
    cap_hit: capHit,
    status: capHit ? 'cap_hit' : 'ok',
  };
}

async function markRunStatus(
  pg: PostgresAdapter,
  status: 'ok' | 'partial' | 'failed' | 'cap_hit',
  extra: { redelivered: number },
): Promise<void> {
  await pg.query(
    `UPDATE agent_webhook_replay_state
        SET last_run_at = now(),
            last_run_status = $1,
            total_redelivered = total_redelivered + $2
      WHERE provider = 'github_app'`,
    [status, extra.redelivered],
  );
}
