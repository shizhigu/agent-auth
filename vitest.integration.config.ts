import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

// libsodium-wrappers ESM build references a sibling module that isn't shipped;
// the unit config aliases this away — integration + chaos need the same fix.
const libsodiumCjs = fileURLToPath(
  new URL(
    './node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js',
    import.meta.url,
  ),
);

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
