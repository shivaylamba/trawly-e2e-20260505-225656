export {
  scanProject,
  scanLockfile,
  meetsThreshold,
  summarize,
  compareFindings,
  ScanInputError,
} from "./scanner.js";

export { parseNpmPackageLock } from "./extractors/npm-package-lock.js";
export { queryOsv, dedupeForQuery } from "./sources/osv.js";
export { SEVERITY_RANK } from "./types.js";
export type {
  Severity,
  Ecosystem,
  FindingType,
  PackageInstance,
  Finding,
  ScanError,
  ScanResult,
  ScanProjectOptions,
  ScanLockfileOptions,
  FailOnLevel,
} from "./types.js";
