# Contributing to trawly

Thanks for your interest in trawly. The project is intentionally small in v0:
npm + OSV only. New ecosystems and outputs are tracked in the roadmap.

## Development

```bash
npm install
npm run build
npm test
npm run typecheck
```

The CLI can be run directly from source while iterating:

```bash
npm run scan -- ./path-to-some-project
```

## Project layout

```
src/
  cli.ts                    # commander-based CLI
  index.ts                  # public library API
  scanner.ts                # orchestrates extractors + sources
  types.ts                  # shared types
  extractors/
    npm-package-lock.ts     # parse package-lock.json v2/v3
  sources/
    osv.ts                  # OSV /v1/querybatch + /v1/vulns
  reporters/
    table.ts                # human-readable table
    json.ts                 # stable JSON schema
tests/
  *.test.ts                 # vitest unit tests
```

## Guidelines

- Prefer adding a new file in `extractors/` or `sources/` over branching inside
  existing files.
- The JSON output schema is a public contract. Changing it requires a major
  version bump.
- Don't add features that mutate the user's project (lockfile rewrites,
  installs, etc.) without explicit opt-in. v0 is read-only.
- Vulnerability data is noisy. When in doubt, label things as `risk-signal`
  rather than `vulnerability`.

## Issues and PRs

Use the issue templates. For PRs, include tests for any new parser or source
behavior.
