import { spawn } from "node:child_process";
import type { PmCommand } from "./pm-detect.js";

export interface RunOptions {
  cwd?: string;
}

/**
 * Spawn the package manager with stdio inherited so the user sees the live
 * install output. Resolves with the PM's exit code.
 */
export function runPackageManager(
  cmd: PmCommand,
  opts: RunOptions = {},
): Promise<number> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd.bin, cmd.args, {
      cwd: opts.cwd,
      stdio: "inherit",
      shell: process.platform === "win32",
    });
    child.on("error", reject);
    child.on("close", (code) => resolve(code ?? 0));
  });
}
