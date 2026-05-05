import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

export type PackageManager = "npm" | "pnpm" | "yarn" | "bun";

export interface PmCommand {
  /** Binary to spawn, e.g. "pnpm". */
  bin: string;
  /** Argv to spawn it with. */
  args: string[];
}

export interface DetectOptions {
  /** Override detection. */
  override?: PackageManager;
  /** Project directory. Defaults to cwd. */
  cwd?: string;
}

const LOCKFILES: Array<{ file: string; pm: PackageManager }> = [
  { file: "pnpm-lock.yaml", pm: "pnpm" },
  { file: "yarn.lock", pm: "yarn" },
  { file: "bun.lockb", pm: "bun" },
  { file: "bun.lock", pm: "bun" },
  { file: "package-lock.json", pm: "npm" },
  { file: "npm-shrinkwrap.json", pm: "npm" },
];

export function detectPackageManager(opts: DetectOptions = {}): PackageManager {
  if (opts.override) return opts.override;
  const cwd = opts.cwd ?? process.cwd();

  const fromField = readPackageManagerField(cwd);
  if (fromField) return fromField;

  for (const { file, pm } of LOCKFILES) {
    if (existsSync(join(cwd, file))) return pm;
  }
  return "npm";
}

function readPackageManagerField(cwd: string): PackageManager | undefined {
  const pkgPath = join(cwd, "package.json");
  if (!existsSync(pkgPath)) return undefined;
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as {
      packageManager?: string;
    };
    if (typeof pkg.packageManager !== "string") return undefined;
    const name = pkg.packageManager.split("@")[0];
    if (name === "npm" || name === "pnpm" || name === "yarn" || name === "bun") {
      return name;
    }
  } catch {
    // Malformed package.json : fall back to lockfile detection.
  }
  return undefined;
}

/**
 * Build the argv to add packages with the chosen package manager.
 * `flags` are user-supplied PM flags (e.g. -D, --save-exact) preserved as-is.
 */
export function buildAddCommand(
  pm: PackageManager,
  packages: string[],
  flags: string[],
): PmCommand {
  switch (pm) {
    case "npm":
      return { bin: "npm", args: ["install", ...flags, ...packages] };
    case "pnpm":
      return { bin: "pnpm", args: ["add", ...flags, ...packages] };
    case "yarn":
      return { bin: "yarn", args: ["add", ...flags, ...packages] };
    case "bun":
      return { bin: "bun", args: ["add", ...flags, ...packages] };
  }
}

export function buildInstallCommand(
  pm: PackageManager,
  flags: string[],
): PmCommand {
  return { bin: pm, args: ["install", ...flags] };
}

export function buildRemoveCommand(
  pm: PackageManager,
  packages: string[],
  flags: string[],
): PmCommand {
  switch (pm) {
    case "npm":
      return { bin: "npm", args: ["uninstall", ...flags, ...packages] };
    case "pnpm":
      return { bin: "pnpm", args: ["remove", ...flags, ...packages] };
    case "yarn":
      return { bin: "yarn", args: ["remove", ...flags, ...packages] };
    case "bun":
      return { bin: "bun", args: ["remove", ...flags, ...packages] };
  }
}
