import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/integration/**/*.int.test.ts'],
    environment: 'node',
    globals: false,
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } }, // share Postgres/Redis containers across files
    testTimeout: 60000,
    hookTimeout: 60000,
  },
});
