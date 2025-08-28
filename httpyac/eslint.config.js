const globals = require("globals");
const eslintJs = require("@eslint/js");
const nodePlugin = require("eslint-plugin-n");
const prettierPlugin = require("eslint-plugin-prettier");
const prettierConfig = require("eslint-plugin-prettier/recommended");

/** @type {import("eslint").Linter.Config[]} */
module.exports = [
  {
    plugins: {
      node: nodePlugin,
      prettier: prettierPlugin,
    },
    languageOptions: {
      ecmaVersion: 2021,
      sourceType: "commonjs",
      globals: {
        ...globals.node,
      },
    },
  },
  eslintJs.configs.recommended,
  prettierConfig,
  {
    rules: {
      "dot-notation": ["off"],
      "no-console": ["off"],
      "no-await-in-loop": ["off"],
    },
  },
];
