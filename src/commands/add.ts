import kleur from "kleur";
import { queryOsv } from "../sources/osv.js";
import { compareFindings, summarize } from "../scanner.js";
import { SEVERITY_RANK } from "../types.js";
import type { Finding, PackageInstance, Severity } from "../types.js";
import {
  buildAddCommand,
  detectPackageManager,
  type PackageManager,
} from "../installer/pm-detect.js";
import { runPackageManager } from "../installer/runner.js";
import {
  parseSpec,
  partitionArgs,
  type ParsedSpec,
  type UnsupportedReason,
} from "../installer/spec-parser.js";
import {
  resolveVersion,
  VersionResolveError,
  type ResolvedVersion,
} from "../installer/version-resolver.js";

export interface AddOptions {
  cwd?: string;
  pm?: PackageManager;
  failOn: Severity | "none";
  allowVulnerable?: boolean;
  fetchImpl?: typeof fetch;
  /** Test seam: replace the real spawn with a stub. */
  runner?: typeof runPackageManager;
}

export interface AddResult {
  /** Specs we sent to the package manager. */
  installed: ResolvedSpec[];
  /** Specs we refused to install. */
  blocked: BlockedSpec[];
  /** Specs we couldn't analyze (git, file, url, alias). */
  skipped: SkippedSpec[];
  /** Specs that failed registry resolution. */
  errored: ErroredSpec[];
  /** All findings collected, sorted. */
  findings: Finding[];
  /** Exit code from the PM, or undefined if we never ran it. */
  pmExitCode?: number;
}

interface ResolvedSpec {
  spec: ParsedSpec;
  resolved: ResolvedVersion;
  findings: Finding[];
}

interface BlockedSpec extends ResolvedSpec {
  reason: "vulnerable";
}

interface SkippedSpec {
  spec: ParsedSpec;
  reason: UnsupportedReason;
}

interface ErroredSpec {
  spec: ParsedSpec;
  message: string;
}

export async function runAdd(
  args: string[],
  options: AddOptions,
): Promise<AddResult> {
  const { specs, flags } = partitionArgs(args);

  const skipped: SkippedSpec[] = [];
  const resolvable: ParsedSpec[] = [];
  for (const spec of specs) {
    if (spec.unsupported) {
      skipped.push({ spec, reason: spec.unsupported });
    } else {
      resolvable.push(spec);
    }
  }

  const resolved: ResolvedSpec[] = [];
  const errored: ErroredSpec[] = [];
  await Promise.all(
    resolvable.map(async (spec) => {
      try {
        const r = await resolveVersion(spec.name, spec.requested, {
          fetchImpl: options.fetchImpl,
        });
        resolved.push({ spec, resolved: r, findings: [] });
      } catch (err) {
        const message =
          err instanceof VersionResolveError
            ? err.message
            : `Registry error: ${(err as Error).message}`;
        errored.push({ spec, message });
      }
    }),
  );

  let findings: Finding[] = [];
  if (resolved.length > 0) {
    const instances: PackageInstance[] = resolved.map((r) => ({
      name: r.spec.name,
      version: r.resolved.version,
      ecosystem: "npm",
      path: r.spec.raw,
      direct: true,
      dev: false,
      optional: false,
    }));
    try {
      findings = await queryOsv(instances, { fetchImpl: options.fetchImpl });
    } catch (err) {
      // If OSV is unreachable we cannot make a safe call; treat as a hard error
      // for every resolvable spec rather than silently letting installs through.
      const message = `OSV query failed: ${(err as Error).message}`;
      for (const r of resolved) errored.push({ spec: r.spec, message });
      resolved.length = 0;
    }
  }

  for (const f of findings) {
    const owner = resolved.find(
      (r) => r.spec.name === f.packageName && r.resolved.version === f.installedVersion,
    );
    if (owner) owner.findings.push(f);
  }

  const blocked: BlockedSpec[] = [];
  const installed: ResolvedSpec[] = [];
  for (const r of resolved) {
    if (shouldBlock(r.findings, options)) {
      blocked.push({ ...r, reason: "vulnerable" });
    } else {
      installed.push(r);
    }
  }

  findings.sort(compareFindings);

  let pmExitCode: number | undefined;
  if (installed.length > 0) {
    const pm = detectPackageManager({ override: options.pm, cwd: options.cwd });
    const cmd = buildAddCommand(
      pm,
      installed.map((r) => r.spec.raw),
      flags,
    );
    process.stdout.write(
      kleur.gray(`> ${cmd.bin} ${cmd.args.join(" ")}\n`),
    );
    const runner = options.runner ?? runPackageManager;
    pmExitCode = await runner(cmd, { cwd: options.cwd });
  }

  return { installed, blocked, skipped, errored, findings, pmExitCode };
}

export function reportAdd(result: AddResult): string {
  const lines: string[] = [];

  if (result.skipped.length > 0) {
    for (const s of result.skipped) {
      lines.push(
        kleur.yellow(
          `~ Skipped ${s.spec.raw}: ${describeUnsupported(s.reason)} (cannot scan; not forwarded to install)`,
        ),
      );
    }
  }

  if (result.errored.length > 0) {
    for (const e of result.errored) {
      lines.push(kleur.red(`! ${e.spec.raw}: ${e.message}`));
    }
  }

  if (result.blocked.length > 0) {
    for (const b of result.blocked) {
      const sev = summarize(b.findings);
      const counts = describeSeverityCounts(sev);
      lines.push(
        kleur.red(
          `✗ Blocked ${b.spec.name}@${b.resolved.version}: ${counts}`,
        ),
      );
      if (b.resolved.source === "fallback-latest") {
        lines.push(
          kleur.gray(
            `  (scanned latest because we don't resolve semver ranges yet; you asked for "${b.resolved.requested}")`,
          ),
        );
      }
      for (const f of b.findings) {
        lines.push(
          `  - [${colorSeverity(f.severity)}] ${f.id} : ${f.summary}`,
        );
        if (f.fixedVersions.length > 0) {
          lines.push(kleur.gray(`    fixed in: ${f.fixedVersions.join(", ")}`));
        }
        if (f.url) lines.push(kleur.gray(`    ${f.url}`));
      }
    }
  }

  if (result.installed.length > 0) {
    const names = result.installed
      .map((r) => `${r.spec.name}@${r.resolved.version}`)
      .join(", ");
    lines.push(kleur.green(`✓ Installing: ${names}`));
  } else if (result.blocked.length > 0) {
    lines.push(
      kleur.red("Nothing installed : all requested packages were blocked."),
    );
  }

  return `${lines.join("\n")}\n`;
}

function shouldBlock(findings: Finding[], options: AddOptions): boolean {
  if (options.allowVulnerable) return false;
  if (options.failOn === "none") return false;
  const threshold = SEVERITY_RANK[options.failOn];
  return findings.some((f) => SEVERITY_RANK[f.severity] >= threshold);
}

function describeUnsupported(reason: UnsupportedReason): string {
  switch (reason) {
    case "git":
      return "git specs cannot be scanned against OSV";
    case "url":
      return "URL specs cannot be scanned against OSV";
    case "file":
      return "local file specs cannot be scanned against OSV";
    case "alias":
      return "npm aliases are not supported in v1";
    case "workspace":
      return "workspace protocol specs are not scanned";
    case "invalid":
      return "could not parse spec";
  }
}

function describeSeverityCounts(summary: Record<Severity, number>): string {
  const parts: string[] = [];
  for (const sev of ["critical", "high", "moderate", "low", "unknown"] as Severity[]) {
    if (summary[sev] > 0) parts.push(`${summary[sev]} ${sev}`);
  }
  return parts.length === 0 ? "no advisories" : `${parts.join(", ")} advisor${total(summary) === 1 ? "y" : "ies"}`;
}

function total(summary: Record<Severity, number>): number {
  return Object.values(summary).reduce((a, b) => a + b, 0);
}

function colorSeverity(sev: Severity): string {
  switch (sev) {
    case "critical":
      return kleur.bold().red(sev);
    case "high":
      return kleur.red(sev);
    case "moderate":
      return kleur.yellow(sev);
    case "low":
      return kleur.cyan(sev);
    case "unknown":
      return kleur.gray(sev);
  }
}

// Re-exports so tests can poke at the parsed spec type.
export { parseSpec };
