# trawly

A dependency sanity scanner for JavaScript projects. Reads exact installed
versions from your `package-lock.json` and queries the
[OSV](https://google.github.io/osv.dev/api/) advisory database for known
vulnerabilities.

> **Limitation:** trawly reports known advisories. It cannot prove a package is
> safe : absence of findings is not absence of risk.

## Install

```bash
npm install --save-dev trawly
# or run ad-hoc:
npx trawly scan
```

Requires Node.js >= 20.

## Quickstart

```bash
# log-only run (always exits 0) : best for interactive inspection
npx trawly inspect

# gating run : exits non-zero when findings meet --fail-on (default: high). Use this in CI.
npx trawly scan

# scan a specific lockfile
npx trawly scan --lockfile path/to/package-lock.json

# JSON output (stable schema, suitable for CI artefacts)
npx trawly scan --format json > trawly-report.json

# only production deps
npx trawly scan --prod

# show every advisory instead of grouping by package
npx trawly scan --details
```

## Two ways to run

trawly intentionally separates the gating and reporting concerns:

| Command          | Exit code on findings                       | When to use                                   |
| ---------------- | ------------------------------------------- | --------------------------------------------- |
| `trawly scan`    | non-zero (`--fail-on`, default `high`)      | CI, pre-commit, anywhere a build should fail  |
| `trawly inspect` | always 0 unless an operational error occurs | local exploration, dashboards, "just show me" |

Both produce identical output. Only the exit behaviour differs.

## CLI

```
trawly scan [path]      Gating run. Exits non-zero when --fail-on is met.
trawly inspect [path]   Log-only run. Always exits 0 on findings.

Common options (both commands):

  --lockfile <path>          Explicit path to package-lock.json
  --format table|json        Output format (default: table)
  --prod                     Skip dev dependencies
  --include-dev              Include dev dependencies (default)
  --no-cache                 Bypass any local cache
  -v, --details              Show one row per advisory instead of grouping
  -q, --summary              Print only the one-line severity summary

scan-only:
  --fail-on <level>          Severity gate
                             (critical|high|moderate|low|none, default: high)
```

### Exit codes

| Code | Meaning                                                                                       |
| ---- | --------------------------------------------------------------------------------------------- |
| 0    | `inspect`: any outcome with no operational error. `scan`: no finding at or above `--fail-on`. |
| 1    | `scan` only: at least one finding at or above `--fail-on`.                                    |
| 2    | Operational error (e.g. lockfile read failed, OSV unreachable).                               |
| 3    | Invalid CLI input.                                                                            |

## Library API

```ts
import { scanProject, scanLockfile } from "trawly";

const result = await scanProject({ cwd: process.cwd() });
for (const finding of result.findings) {
  console.log(finding.packageName, finding.severity, finding.id);
}
```

The result follows this shape:

```jsonc
{
  "scannedAt": "2026-05-03T12:34:56.000Z",
  "packagesScanned": 412,
  "findings": [
    {
      "id": "GHSA-...",
      "source": "osv",
      "type": "vulnerability",
      "severity": "high",
      "packageName": "lodash",
      "installedVersion": "4.17.20",
      "summary": "Prototype pollution in lodash",
      "url": "https://github.com/advisories/GHSA-...",
      "fixedVersions": ["4.17.21"],
      "affectedPaths": ["node_modules/lodash"],
    },
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "moderate": 0,
    "low": 0,
    "unknown": 0,
  },
  "errors": [],
}
```

## CI example (GitHub Actions)

```yaml
name: trawly
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20 }
      - run: npm ci
      - run: npx trawly scan --fail-on high --format json > trawly.json
      - uses: actions/upload-artifact@v4
        if: always()
        with: { name: trawly-report, path: trawly.json }
```

## Roadmap

trawly v0 covers npm + OSV. Planned next:

- pnpm and Yarn lockfile support
- SARIF + Markdown reporters and a GitHub Action
- Config file with ignore entries (with required expiry)
- Baseline mode (fail only on new findings)
- Risk signals: install scripts, unexpected registries, package age
- Multi-ecosystem scanning via SBOM (SPDX, CycloneDX)

