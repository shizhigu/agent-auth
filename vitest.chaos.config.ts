import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/chaos/**/*.test.ts'],
    environment: 'node',
    globals: false,
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    testTimeout: 120000,
    hookTimeout: 120000,
  },
});
