import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';

// libsodium-wrappers ESM build references a sibling module that isn't shipped;
// the unit config aliases this away — integration + chaos need the same fix.
const require_ = createRequire(import.meta.url);
const libsodiumCjs = require_.resolve('libsodium-wrappers/dist/modules/libsodium-wrappers.js');

export default defineConfig({
  resolve: {
    alias: { 'libsodium-wrappers': libsodiumCjs },
  },
  test: {
    include: ['test/integration/**/*.int.test.ts'],
    environment: 'node',
    globals: false,
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } }, // share Postgres/Redis containers across files
    testTimeout: 60000,
    hookTimeout: 60000,
    server: {
      deps: { inline: ['libsodium-wrappers'] },
    },
  },
});
