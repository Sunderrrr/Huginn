module.exports = {
  root: true,
  env: { browser: true, es2021: true },
  extends: [
    "eslint:recommended",
    "plugin:@typescript-eslint/recommended",
    "plugin:react-hooks/recommended",
  ],
  parser: "@typescript-eslint/parser",
  plugins: ["react-refresh"],
  ignorePatterns: ["dist", ".eslintrc.cjs"],
  rules: {
    // Co-locating a context hook with its provider is intentional here.
    "react-refresh/only-export-components": "off",
    "@typescript-eslint/no-explicit-any": "off",
  },
};
