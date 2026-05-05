import { describe, expect, it, vi } from "vitest";
import { runAdd } from "../src/commands/add.js";

const REGISTRY = "https://registry.npmjs.org";
const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN = "https://api.osv.dev/v1/vulns";

interface FakeResponses {
  packuments?: Record<string, unknown>;
  /** Map of "name@version" → array of OSV vuln IDs. */
  vulns?: Record<string, string[]>;
  /** Map of OSV id → detail record. */
  details?: Record<string, unknown>;
}

function makeFetch(r: FakeResponses): typeof fetch {
  return (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();

    if (url.startsWith(REGISTRY)) {
      const path = decodeURIComponent(
        url.replace(`${REGISTRY}/`, "").replace("%2F", "/"),
      );
      const data = r.packuments?.[path];
      if (!data) return new Response("not found", { status: 404 });
      return new Response(JSON.stringify(data), { status: 200 });
    }

    if (url === OSV_BATCH) {
      const body = JSON.parse(init?.body as string) as {
        queries: Array<{ package: { name: string }; version: string }>;
      };
      const results = body.queries.map((q) => {
        const key = `${q.package.name}@${q.version}`;
        const ids = r.vulns?.[key];
        if (!ids || ids.length === 0) return {};
        return { vulns: ids.map((id) => ({ id })) };
      });
      return new Response(JSON.stringify({ results }), { status: 200 });
    }

    if (url.startsWith(`${OSV_VULN}/`)) {
      const id = decodeURIComponent(url.slice(`${OSV_VULN}/`.length));
      const detail = r.details?.[id];
      if (!detail) return new Response("not found", { status: 404 });
      return new Response(JSON.stringify(detail), { status: 200 });
    }

    return new Response("unexpected url", { status: 500 });
  }) as typeof fetch;
}

describe("runAdd", () => {
  it("partitions vulnerable from clean packages", async () => {
    const runner = vi.fn().mockResolvedValue(0);
    const result = await runAdd(["next", "vitest"], {
      failOn: "high",
      runner,
      fetchImpl: makeFetch({
        packuments: {
          next: { "dist-tags": { latest: "14.2.3" } },
          vitest: { "dist-tags": { latest: "1.0.0" } },
        },
        vulns: { "next@14.2.3": ["GHSA-xxxx"] },
        details: {
          "GHSA-xxxx": {
            id: "GHSA-xxxx",
            summary: "next is bad",
            database_specific: { severity: "HIGH" },
          },
        },
      }),
    });

    expect(result.blocked.map((b) => b.spec.name)).toEqual(["next"]);
    expect(result.installed.map((i) => i.spec.name)).toEqual(["vitest"]);
    expect(runner).toHaveBeenCalledOnce();
    const cmd = runner.mock.calls[0]?.[0] as { args: string[] };
    expect(cmd.args).toContain("vitest");
    expect(cmd.args).not.toContain("next");
  });

  it("does not invoke the runner when everything is blocked", async () => {
    const runner = vi.fn().mockResolvedValue(0);
    const result = await runAdd(["next"], {
      failOn: "high",
      runner,
      fetchImpl: makeFetch({
        packuments: { next: { "dist-tags": { latest: "14.2.3" } } },
        vulns: { "next@14.2.3": ["GHSA-xxxx"] },
        details: {
          "GHSA-xxxx": {
            id: "GHSA-xxxx",
            summary: "boom",
            database_specific: { severity: "CRITICAL" },
          },
        },
      }),
    });

    expect(result.installed).toHaveLength(0);
    expect(result.blocked).toHaveLength(1);
    expect(runner).not.toHaveBeenCalled();
  });

  it("respects --allow-vulnerable", async () => {
    const runner = vi.fn().mockResolvedValue(0);
    const result = await runAdd(["next"], {
      failOn: "high",
      allowVulnerable: true,
      runner,
      fetchImpl: makeFetch({
        packuments: { next: { "dist-tags": { latest: "14.2.3" } } },
        vulns: { "next@14.2.3": ["GHSA-xxxx"] },
        details: {
          "GHSA-xxxx": {
            id: "GHSA-xxxx",
            database_specific: { severity: "CRITICAL" },
          },
        },
      }),
    });

    expect(result.blocked).toHaveLength(0);
    expect(result.installed).toHaveLength(1);
    expect(result.findings).toHaveLength(1);
    expect(runner).toHaveBeenCalledOnce();
  });

  it("respects --fail-on threshold", async () => {
    const runner = vi.fn().mockResolvedValue(0);
    const result = await runAdd(["foo"], {
      failOn: "critical",
      runner,
      fetchImpl: makeFetch({
        packuments: { foo: { "dist-tags": { latest: "1.0.0" } } },
        vulns: { "foo@1.0.0": ["GHSA-yyy"] },
        details: {
          "GHSA-yyy": {
            id: "GHSA-yyy",
            database_specific: { severity: "HIGH" },
          },
        },
      }),
    });

    // High doesn't meet critical threshold → installs.
    expect(result.installed).toHaveLength(1);
    expect(result.blocked).toHaveLength(0);
    expect(runner).toHaveBeenCalled();
  });

  it("skips git/file/url specs without scanning or installing them", async () => {
    const runner = vi.fn().mockResolvedValue(0);
    const result = await runAdd(
      ["git+https://github.com/foo/bar", "vitest"],
      {
        failOn: "high",
        runner,
        fetchImpl: makeFetch({
          packuments: { vitest: { "dist-tags": { latest: "1.0.0" } } },
        }),
      },
    );

    expect(result.skipped).toHaveLength(1);
    expect(result.skipped[0]?.reason).toBe("git");
    expect(result.installed.map((i) => i.spec.name)).toEqual(["vitest"]);
  });

  it("forwards passthrough flags to the runner", async () => {
    const runner = vi.fn().mockResolvedValue(0);
    await runAdd(["-D", "vitest"], {
      failOn: "high",
      runner,
      fetchImpl: makeFetch({
        packuments: { vitest: { "dist-tags": { latest: "1.0.0" } } },
      }),
    });
    const cmd = runner.mock.calls[0]?.[0] as { args: string[] };
    expect(cmd.args).toContain("-D");
    expect(cmd.args).toContain("vitest");
  });

  it("treats OSV failure as an error for all resolved specs", async () => {
    const runner = vi.fn().mockResolvedValue(0);
    const failingFetch: typeof fetch = (async (input: string | URL | Request, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input.toString();
      if (url.startsWith(REGISTRY)) {
        return new Response(
          JSON.stringify({ "dist-tags": { latest: "1.0.0" } }),
          { status: 200 },
        );
      }
      if (url === OSV_BATCH) return new Response("nope", { status: 503 });
      return new Response("unexpected", { status: 500 });
    }) as typeof fetch;

    const result = await runAdd(["foo"], {
      failOn: "high",
      runner,
      fetchImpl: failingFetch,
    });
    expect(result.errored).toHaveLength(1);
    expect(result.installed).toHaveLength(0);
    expect(runner).not.toHaveBeenCalled();
  });
});
