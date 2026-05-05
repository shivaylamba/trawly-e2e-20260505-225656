export type Severity = "critical" | "high" | "moderate" | "low" | "unknown";

export type Ecosystem = "npm";

export type FindingType =
  | "vulnerability"
  | "malware"
  | "risk-signal"
  | "integrity";

export const SEVERITY_RANK: Record<Severity, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
  unknown: 0,
};

export interface PackageInstance {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  /** Path within the lockfile's `packages` map (e.g. "node_modules/foo"). */
  path: string;
  direct: boolean;
  dev: boolean;
  optional: boolean;
  resolved?: string;
  integrity?: string;
}

export interface Finding {
  id: string;
  source: "osv";
  type: FindingType;
  severity: Severity;
  packageName: string;
  installedVersion: string;
  summary: string;
  url?: string;
  fixedVersions: string[];
  affectedPaths: string[];
}

export interface ScanError {
  message: string;
  cause?: string;
}

export interface ScanResult {
  scannedAt: string;
  packagesScanned: number;
  findings: Finding[];
  summary: Record<Severity, number>;
  errors: ScanError[];
}

export interface ScanProjectOptions {
  cwd?: string;
  lockfile?: string;
  includeDev?: boolean;
  prodOnly?: boolean;
  cache?: boolean;
  fetchImpl?: typeof fetch;
}

export interface ScanLockfileOptions {
  lockfilePath: string;
  includeDev?: boolean;
  prodOnly?: boolean;
  fetchImpl?: typeof fetch;
}

export type FailOnLevel = Severity | "none";
