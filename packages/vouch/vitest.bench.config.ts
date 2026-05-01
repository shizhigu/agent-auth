import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['bench/**/*.bench.ts'],
    environment: 'node',
    globals: false,
    benchmark: { include: ['bench/**/*.bench.ts'] },
  },
});
