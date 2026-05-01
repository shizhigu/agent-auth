/**
 * Express type augmentation: makes `req.agent: AgentContext | undefined`
 * available on every handler. Per Vouch SPEC §6.3 we use `req.agent`,
 * NOT `req.user` — confusing the two creates a confused-deputy bug.
 */
import type { AgentContext } from '@vouch/server';

declare module 'express-serve-static-core' {
  interface Request {
    agent?: AgentContext;
  }
}

export {};
