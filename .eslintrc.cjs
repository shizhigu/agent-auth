/* ESLint config — enforces no `any` in security paths and warns on req.user usage in agent-protected routes (per SPEC §6.3). */
module.exports = {
  root: true,
  parser: '@typescript-eslint/parser',
  parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
  plugins: ['@typescript-eslint'],
  env: { node: true, es2022: true },
  ignorePatterns: ['dist/', 'node_modules/', 'coverage/'],
  rules: {
    '@typescript-eslint/no-explicit-any': 'error',
    '@typescript-eslint/no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    'no-restricted-syntax': [
      'warn',
      {
        selector: "MemberExpression[object.name='req'][property.name='user']",
        message: "agent-auth routes must use req.agent (see SPEC §6.3 confused-deputy prevention).",
      },
    ],
  },
};
