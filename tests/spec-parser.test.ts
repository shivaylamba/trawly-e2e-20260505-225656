import { describe, expect, it } from "vitest";
import { parseSpec, partitionArgs } from "../src/installer/spec-parser.js";

describe("parseSpec", () => {
  it("parses bare package name", () => {
    const r = parseSpec("next");
    expect(r.name).toBe("next");
    expect(r.requested).toBeUndefined();
  });

  it("parses name@version", () => {
    expect(parseSpec("next@14.2.3")).toMatchObject({
      name: "next",
      requested: "14.2.3",
    });
  });

  it("parses scoped name without version", () => {
    const r = parseSpec("@types/node");
    expect(r.name).toBe("@types/node");
    expect(r.requested).toBeUndefined();
  });

  it("parses scoped name@range", () => {
    expect(parseSpec("@types/node@^20")).toMatchObject({
      name: "@types/node",
      requested: "^20",
    });
  });

  it("flags git specs as unsupported", () => {
    expect(parseSpec("git+https://github.com/foo/bar")).toMatchObject({
      unsupported: "git",
    });
  });

  it("flags file specs as unsupported", () => {
    expect(parseSpec("file:../local-pkg")).toMatchObject({ unsupported: "file" });
  });

  it("flags npm aliases as unsupported", () => {
    expect(parseSpec("alias@npm:real-pkg@1.0")).toMatchObject({
      unsupported: "alias",
    });
  });

  it("flags scoped npm aliases as unsupported", () => {
    expect(parseSpec("@my/alias@npm:real-pkg@1.0")).toMatchObject({
      unsupported: "alias",
    });
  });

  it("flags workspace protocol as unsupported", () => {
    expect(parseSpec("workspace:*")).toMatchObject({ unsupported: "workspace" });
  });
});

describe("partitionArgs", () => {
  it("separates flags from specs", () => {
    const { specs, flags } = partitionArgs(["-D", "vitest", "--save-exact", "react"]);
    expect(flags).toEqual(["-D", "--save-exact"]);
    expect(specs.map((s) => s.name)).toEqual(["vitest", "react"]);
  });
});
