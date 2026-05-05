import { describe, expect, it } from "vitest";
import {
  resolveVersion,
  VersionResolveError,
} from "../src/installer/version-resolver.js";

function fakeFetch(packuments: Record<string, unknown>): typeof fetch {
  return (async (url: string | URL | Request) => {
    const u = typeof url === "string" ? url : url.toString();
    const name = decodePackageName(u);
    if (!(name in packuments)) {
      return new Response("not found", { status: 404 });
    }
    return new Response(JSON.stringify(packuments[name]), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
}

function decodePackageName(url: string): string {
  // Strip the registry prefix and decode the path.
  const path = url.replace(/^https?:\/\/[^/]+\//, "");
  return decodeURIComponent(path.replace("%2F", "/"));
}

describe("resolveVersion", () => {
  it("resolves to latest when no version requested", async () => {
    const r = await resolveVersion("next", undefined, {
      fetchImpl: fakeFetch({
        next: { "dist-tags": { latest: "14.2.3" } },
      }),
    });
    expect(r).toEqual({ version: "14.2.3", source: "dist-tag", requested: "latest" });
  });

  it("uses an exact version when present", async () => {
    const r = await resolveVersion("react", "18.2.0", {
      fetchImpl: fakeFetch({
        react: {
          "dist-tags": { latest: "18.3.0" },
          versions: { "18.2.0": {}, "18.3.0": {} },
        },
      }),
    });
    expect(r).toEqual({ version: "18.2.0", source: "exact" });
  });

  it("rejects an exact version that doesn't exist", async () => {
    await expect(
      resolveVersion("react", "99.0.0", {
        fetchImpl: fakeFetch({
          react: {
            "dist-tags": { latest: "18.3.0" },
            versions: { "18.3.0": {} },
          },
        }),
      }),
    ).rejects.toBeInstanceOf(VersionResolveError);
  });

  it("resolves a known dist-tag", async () => {
    const r = await resolveVersion("next", "canary", {
      fetchImpl: fakeFetch({
        next: { "dist-tags": { latest: "14.2.3", canary: "15.0.0-canary.1" } },
      }),
    });
    expect(r).toEqual({
      version: "15.0.0-canary.1",
      source: "dist-tag",
      requested: "canary",
    });
  });

  it("falls back to latest for semver ranges", async () => {
    const r = await resolveVersion("react", "^18", {
      fetchImpl: fakeFetch({
        react: { "dist-tags": { latest: "18.3.0" } },
      }),
    });
    expect(r).toEqual({
      version: "18.3.0",
      source: "fallback-latest",
      requested: "^18",
    });
  });

  it("throws on 404", async () => {
    await expect(
      resolveVersion("does-not-exist", undefined, {
        fetchImpl: fakeFetch({}),
      }),
    ).rejects.toBeInstanceOf(VersionResolveError);
  });
});
