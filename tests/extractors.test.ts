import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  packagePathToName,
  parseNpmPackageLock,
} from "../src/extractors/npm-package-lock.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURE = join(here, "fixtures", "package-lock.json");

describe("packagePathToName", () => {
  it("extracts unscoped name", () => {
    expect(packagePathToName("node_modules/foo")).toBe("foo");
  });

  it("extracts scoped name", () => {
    expect(packagePathToName("node_modules/@scope/bar")).toBe("@scope/bar");
  });

  it("uses the deepest node_modules segment for nested installs", () => {
    expect(
      packagePathToName("node_modules/foo/node_modules/bar"),
    ).toBe("bar");
    expect(
      packagePathToName("node_modules/foo/node_modules/@scope/bar"),
    ).toBe("@scope/bar");
  });

  it("returns null for paths without node_modules", () => {
    expect(packagePathToName("packages/foo")).toBeNull();
  });
});

describe("parseNpmPackageLock", () => {
  it("extracts package instances and skips workspace links", () => {
    const instances = parseNpmPackageLock(FIXTURE);
    const names = instances.map((i) => i.name).sort();
    expect(names).toEqual([
      "@scope/sub",
      "lodash",
      "minimist",
      "safe-buffer",
    ]);
  });

  it("marks dev and direct flags correctly", () => {
    const instances = parseNpmPackageLock(FIXTURE);
    const lodash = instances.find((i) => i.name === "lodash")!;
    const minimist = instances.find((i) => i.name === "minimist")!;
    const nested = instances.find((i) => i.name === "safe-buffer")!;
    const scoped = instances.find((i) => i.name === "@scope/sub")!;

    expect(lodash.direct).toBe(true);
    expect(lodash.dev).toBe(false);
    expect(lodash.version).toBe("4.17.20");

    expect(minimist.direct).toBe(true);
    expect(minimist.dev).toBe(true);

    expect(nested.direct).toBe(false);
    expect(scoped.direct).toBe(false);
    expect(scoped.path).toBe("node_modules/@scope/sub");
  });
});
