import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    testTimeout: 15000,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'text-summary', 'json-summary'],
      include: ['src/**/*.ts'],
      exclude: [
        'src/index.ts',
        // src/version.ts re-exports package.json's version. The v8 remapper
        // cannot attribute any statement to it: the SSR transform turns
        // `pkg.version` into `__vite_ssr_import_0__.default.version`, which
        // the coverage provider ignores as import plumbing, and the export
        // getter machinery carries no source mappings. The file is executed
        // and asserted on every run (tests/version.test.ts, transport wire
        // batches), but the metric cannot see it, so it is excluded rather
        // than left as a permanent, unfixable hole in the 100% gate.
        'src/version.ts',
      ],
      thresholds: {
        statements: 100,
        branches: 100,
        functions: 100,
        lines: 100,
      },
    },
  },
});
