const REGISTRY_URL = "https://registry.npmjs.org";
const REQUEST_TIMEOUT_MS = 15_000;

export interface ResolveDeps {
  fetchImpl?: typeof fetch;
  registryUrl?: string;
}

export interface ResolvedVersion {
  /** Concrete version we'll hand to OSV. */
  version: string;
  /**
   * How we picked it: "exact" (user pinned), "dist-tag" (latest/next/etc),
   * or "fallback-latest" (we couldn't resolve a range so we scanned latest).
   */
  source: "exact" | "dist-tag" | "fallback-latest";
  /** Set when source !== "exact" : what the user asked for. */
  requested?: string;
}

interface PackumentDistTags {
  latest?: string;
  [tag: string]: string | undefined;
}

interface Packument {
  name?: string;
  "dist-tags"?: PackumentDistTags;
  versions?: Record<string, unknown>;
}

const EXACT_VERSION_RE = /^\d+\.\d+\.\d+(?:[-+][\w.+-]+)?$/;
const RANGE_CHARS_RE = /[\^~><=|\s*x]/i;

/**
 * Resolve a user-supplied spec to a concrete version we can query OSV with.
 *
 * Strategy (v1):
 *   - no version requested        → dist-tags.latest
 *   - exact version (1.2.3)       → use as-is, verified to exist
 *   - dist-tag (latest/next/beta) → dist-tags[tag], or fall back to latest
 *   - semver range (^1, >=2)      → dist-tags.latest with source="fallback-latest"
 *
 * The fallback case is a known limitation: the installed version may differ
 * from what we scanned. The orchestrator surfaces this in its report.
 */
export async function resolveVersion(
  name: string,
  requested: string | undefined,
  deps: ResolveDeps = {},
): Promise<ResolvedVersion> {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const registry = deps.registryUrl ?? REGISTRY_URL;
  const packument = await fetchPackument(fetchImpl, registry, name);

  const distTags = packument["dist-tags"] ?? {};
  const latest = distTags.latest;

  if (!requested) {
    if (!latest) {
      throw new VersionResolveError(
        `Package ${name} has no "latest" dist-tag in the registry.`,
      );
    }
    return { version: latest, source: "dist-tag", requested: "latest" };
  }

  if (EXACT_VERSION_RE.test(requested)) {
    if (packument.versions && !packument.versions[requested]) {
      throw new VersionResolveError(
        `Version ${requested} of ${name} is not published.`,
      );
    }
    return { version: requested, source: "exact" };
  }

  if (!RANGE_CHARS_RE.test(requested) && distTags[requested]) {
    return {
      version: distTags[requested] as string,
      source: "dist-tag",
      requested,
    };
  }

  if (!latest) {
    throw new VersionResolveError(
      `Cannot resolve ${name}@${requested}: no "latest" dist-tag available to fall back on.`,
    );
  }
  return { version: latest, source: "fallback-latest", requested };
}

export class VersionResolveError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "VersionResolveError";
  }
}

async function fetchPackument(
  fetchImpl: typeof fetch,
  registry: string,
  name: string,
): Promise<Packument> {
  const url = `${registry.replace(/\/$/, "")}/${encodePackageName(name)}`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const res = await fetchImpl(url, {
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (res.status === 404) {
      throw new VersionResolveError(`Package ${name} not found in registry.`);
    }
    if (!res.ok) {
      throw new VersionResolveError(
        `Registry ${res.status} for ${name}: ${res.statusText}`,
      );
    }
    return (await res.json()) as Packument;
  } finally {
    clearTimeout(timer);
  }
}

function encodePackageName(name: string): string {
  // Scoped names: "@scope/name" → "@scope%2Fname"
  if (name.startsWith("@")) {
    const slash = name.indexOf("/");
    if (slash !== -1) {
      return `${encodeURIComponent(name.slice(0, slash))}%2F${encodeURIComponent(name.slice(slash + 1))}`;
    }
  }
  return encodeURIComponent(name);
}
