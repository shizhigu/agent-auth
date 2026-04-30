import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/unit/**/*.test.ts'],
    environment: 'node',
    globals: false,
    reporters: ['default'],
    pool: 'forks',
    poolOptions: { forks: { singleFork: false } },
    testTimeout: 10000,
  },
});
