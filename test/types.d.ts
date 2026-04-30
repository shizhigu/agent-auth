import type { AgentContext } from '../src/types.js';

declare module 'express' {
  interface Request {
    agent?: AgentContext;
  }
}

declare module 'hono' {
  interface ContextVariableMap {
    agent: AgentContext;
  }
}

export {};
