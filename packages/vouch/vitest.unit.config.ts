import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';

// libsodium-wrappers ships a broken ESM build (its .mjs imports a sibling
// libsodium.mjs that isn't published). Resolve to the CJS file directly so
// vitest never touches the package's `exports` map. createRequire follows
// node_modules resolution so this works regardless of where npm hoisted
// the dep (root in workspace setups, package-local otherwise).
const require_ = createRequire(import.meta.url);
const libsodiumCjs = require_.resolve('libsodium-wrappers/dist/modules/libsodium-wrappers.js');

export default defineConfig({
  resolve: {
    alias: {
      'libsodium-wrappers': libsodiumCjs,
    },
  },
  test: {
    include: ['test/unit/**/*.test.ts'],
    environment: 'node',
    globals: false,
    reporters: ['default'],
    pool: 'forks',
    poolOptions: { forks: { singleFork: false } },
    testTimeout: 10000,
    server: {
      deps: {
        inline: ['libsodium-wrappers'],
      },
    },
  },
});
