# Contributing

## Getting Started

Fork the repository, clone your fork over HTTPS, and create a branch for your change.
Run `npm ci` to install the locked dependencies.

## Development

- `npm run watch` compiles while you work.
- `npm run build` compiles TypeScript.
- `node dist/index.js` starts the MCP server over stdio.
- `npm test` builds and runs the mocked API and MCP startup regressions.

Use test keys and mocked responses for tests. Never commit credentials.

## Adding New Tools

Add the tool definition and handler in `src/index.ts`. Keep optional services
behind their existing configuration checks. Add a regression test in `tests/`,
and update the Available Tools table in README.md and CHANGELOG.md.

## Code Style

Follow the existing TypeScript conventions, use meaningful errors, and keep
stdout reserved for MCP messages. Write diagnostics to stderr.

## Submitting Changes

Run `npm test` and `npm audit --audit-level=high`, then open a pull request
with the problem, resulting behavior, and verification results. Releases use
the repository's mandatory publish-mcp pipeline.
