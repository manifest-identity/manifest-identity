// The page's lint (D-086): one rule that matters, the one SonarCloud
// turned main red on after a rule set change. typescript-eslint reads
// the plain script through the TypeScript checker so it can tell a
// promise from a value; no TypeScript is written here.
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    files: ["frontend/app.js"],
    languageOptions: {
      parser: tseslint.parser,
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        window: "readonly", document: "readonly", fetch: "readonly",
        FormData: "readonly", URLSearchParams: "readonly", Blob: "readonly",
        URL: "readonly", console: "readonly", setTimeout: "readonly",
        clearTimeout: "readonly", navigator: "readonly", matchMedia: "readonly",
        localStorage: "readonly", Event: "readonly", Node: "readonly",
        requestAnimationFrame: "readonly", HTMLElement: "readonly",
      },
    },
    plugins: { "@typescript-eslint": tseslint.plugin },
    rules: {
      "@typescript-eslint/no-floating-promises": "error",
    },
  },
);
