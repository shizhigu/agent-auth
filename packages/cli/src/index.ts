/**
 * Programmatic entry for `@vouch/cli`. The shipped binary is `dist/cli.js`
 * but library consumers can import the migrate runner directly:
 *
 *   import { createMigrateRunner } from '@vouch/cli/migrate';
 */

export {
  createMigrateRunner,
  resolveBundledSchemaDir,
  type Migration,
  type MigrationResult,
  type MigrationStatus,
  type MigrateRunner,
  type MigrateRunnerConfig,
} from './migrate.js';
