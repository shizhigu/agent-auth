/**
 * Express type augmentation: adds `req.agent: AgentContext | undefined`.
 *
 * Lives in its own module so the declare-merge applies before any handler
 * file is loaded. Per SPEC §6.3 we use `req.agent`, NOT `req.user` — the
 * latter belongs to your existing human auth lib and confusing them is a
 * confused-deputy footgun (RT-9).
 */
import type { AgentContext } from '@vouch/server';

declare module 'express-serve-static-core' {
  interface Request {
    agent?: AgentContext;
  }
}

export {};
