/**
 * Structured JSON logger that runs every record through the scrubber
 * before emitting. SPEC §7.2 + §6.6.
 *
 * The lib does NOT bring in pino / winston — the SaaS may already use one.
 * Instead we provide a small `Logger` interface and a default impl that
 * prints to stdout. SaaS apps can replace it via the `logger` config field
 * (added when M5 wires observability into the rest of the lib).
 */

import { defaultScrubber, type CompiledScrubber } from './scrubber.js';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'alert';

export interface LogRecord {
  readonly level: LogLevel;
  readonly msg: string;
  readonly ts: string;
  readonly [key: string]: unknown;
}

export interface Logger {
  debug(msg: string, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
  alert(msg: string, meta?: Record<string, unknown>): void;
}

export interface LoggerConfig {
  readonly scrubber?: CompiledScrubber;
  readonly minLevel?: LogLevel;
  readonly emit?: (record: LogRecord) => void;
  readonly clock?: () => Date;
}

const LEVEL_RANK: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  alert: 50,
};

export function createLogger(cfg: LoggerConfig = {}): Logger {
  const scrubber = cfg.scrubber ?? defaultScrubber;
  const min = LEVEL_RANK[cfg.minLevel ?? 'info'];
  const emit = cfg.emit ?? defaultEmit;
  const now = cfg.clock ?? (() => new Date());
  function log(level: LogLevel, msg: string, meta?: Record<string, unknown>): void {
    if (LEVEL_RANK[level] < min) return;
    const scrubbed = (meta ? (scrubber.scrub(meta) as Record<string, unknown>) : {});
    const rec: LogRecord = {
      level,
      msg: scrubber.scrubLine(msg),
      ts: now().toISOString(),
      ...scrubbed,
    };
    emit(rec);
  }
  return {
    debug: (m, meta) => log('debug', m, meta),
    info: (m, meta) => log('info', m, meta),
    warn: (m, meta) => log('warn', m, meta),
    error: (m, meta) => log('error', m, meta),
    alert: (m, meta) => log('alert', m, meta),
  };
}

function defaultEmit(rec: LogRecord): void {
  process.stdout.write(JSON.stringify(rec) + '\n');
}

/** Test-only: collects emitted records into an array. */
export function makeArrayLogger(): { logger: Logger; records: LogRecord[] } {
  const records: LogRecord[] = [];
  const logger = createLogger({
    minLevel: 'debug',
    emit: (rec) => records.push(rec),
  });
  return { logger, records };
}
