import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

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
    include: ['test/chaos/**/*.chaos.test.ts'],
    environment: 'node',
    globals: false,
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    testTimeout: 240000,
    hookTimeout: 240000,
    server: {
      deps: { inline: ['libsodium-wrappers'] },
    },
  },
});
