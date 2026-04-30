import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

// libsodium-wrappers ships a broken ESM build (its .mjs imports a sibling
// libsodium.mjs that isn't published). Resolve to the CJS file via an absolute
// path — this bypasses the package's `exports` map entirely.
const libsodiumCjs = fileURLToPath(
  new URL(
    './node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js',
    import.meta.url,
  ),
);

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
