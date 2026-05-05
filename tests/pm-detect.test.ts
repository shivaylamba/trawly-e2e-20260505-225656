import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  buildAddCommand,
  buildInstallCommand,
  buildRemoveCommand,
  detectPackageManager,
} from "../src/installer/pm-detect.js";

function makeProject(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "trawly-pm-"));
  for (const [name, contents] of Object.entries(files)) {
    writeFileSync(join(dir, name), contents);
  }
  return dir;
}

describe("detectPackageManager", () => {
  it("respects override", () => {
    expect(detectPackageManager({ override: "pnpm" })).toBe("pnpm");
  });

  it("reads packageManager field", () => {
    const dir = makeProject({
      "package.json": JSON.stringify({ packageManager: "pnpm@8.6.0" }),
    });
    expect(detectPackageManager({ cwd: dir })).toBe("pnpm");
  });

  it("falls back to lockfile detection", () => {
    const dir = makeProject({
      "package.json": "{}",
      "yarn.lock": "",
    });
    expect(detectPackageManager({ cwd: dir })).toBe("yarn");
  });

  it("prefers pnpm-lock over package-lock when both exist", () => {
    const dir = makeProject({
      "package.json": "{}",
      "pnpm-lock.yaml": "",
      "package-lock.json": "{}",
    });
    expect(detectPackageManager({ cwd: dir })).toBe("pnpm");
  });

  it("defaults to npm with no signals", () => {
    const dir = makeProject({ "package.json": "{}" });
    expect(detectPackageManager({ cwd: dir })).toBe("npm");
  });
});

describe("command builders", () => {
  it("npm add uses install verb", () => {
    expect(buildAddCommand("npm", ["next"], ["-D"])).toEqual({
      bin: "npm",
      args: ["install", "-D", "next"],
    });
  });

  it("pnpm add uses add verb", () => {
    expect(buildAddCommand("pnpm", ["next"], [])).toEqual({
      bin: "pnpm",
      args: ["add", "next"],
    });
  });

  it("npm remove uses uninstall verb", () => {
    expect(buildRemoveCommand("npm", ["lodash"], [])).toEqual({
      bin: "npm",
      args: ["uninstall", "lodash"],
    });
  });

  it("install builds pm install with flags", () => {
    expect(buildInstallCommand("yarn", ["--frozen-lockfile"])).toEqual({
      bin: "yarn",
      args: ["install", "--frozen-lockfile"],
    });
  });
});
