import { defineConfig } from 'vitest/config';
import { createRequire } from 'node:module';

const require_ = createRequire(import.meta.url);
const libsodiumCjs = require_.resolve('libsodium-wrappers/dist/modules/libsodium-wrappers.js');

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
