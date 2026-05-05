export interface ParsedSpec {
  /** Original argv token, preserved so we can hand it back to the package manager. */
  raw: string;
  /** Bare package name, e.g. "next" or "@types/node". */
  name: string;
  /**
   * Whatever followed the "@" separator: an exact version, a semver range,
   * or a dist-tag like "latest" / "next". Undefined when the user passed only
   * the package name.
   */
  requested?: string;
  /** Specs we cannot meaningfully scan (git, tarball, file, url, alias). */
  unsupported?: UnsupportedReason;
}

export type UnsupportedReason =
  | "git"
  | "url"
  | "file"
  | "alias"
  | "workspace"
  | "invalid";

const URL_PROTOCOLS = ["http:", "https:", "git:", "git+ssh:", "git+https:", "git+http:"];

export function parseSpec(raw: string): ParsedSpec {
  const trimmed = raw.trim();
  if (trimmed === "") {
    return { raw, name: "", unsupported: "invalid" };
  }

  if (trimmed.startsWith("file:")) return { raw, name: trimmed, unsupported: "file" };
  if (trimmed.startsWith("workspace:")) {
    return { raw, name: trimmed, unsupported: "workspace" };
  }
  if (URL_PROTOCOLS.some((p) => trimmed.startsWith(p))) {
    const reason = trimmed.includes("git") ? "git" : "url";
    return { raw, name: trimmed, unsupported: reason };
  }
  // npm aliases: "alias@npm:real-pkg@1.0". We can't reliably gate these in v1.
  if (/^[^@/].*@npm:/.test(trimmed) || /^@[^/]+\/[^@]+@npm:/.test(trimmed)) {
    return { raw, name: trimmed, unsupported: "alias" };
  }

  // Scoped: "@scope/name" or "@scope/name@version".
  if (trimmed.startsWith("@")) {
    const slash = trimmed.indexOf("/");
    if (slash === -1) return { raw, name: trimmed, unsupported: "invalid" };
    const rest = trimmed.slice(slash + 1);
    const at = rest.indexOf("@");
    if (at === -1) {
      return { raw, name: trimmed };
    }
    const subname = rest.slice(0, at);
    const requested = rest.slice(at + 1);
    if (subname === "" || requested === "") {
      return { raw, name: trimmed, unsupported: "invalid" };
    }
    return { raw, name: `${trimmed.slice(0, slash)}/${subname}`, requested };
  }

  const at = trimmed.indexOf("@");
  if (at === -1) return { raw, name: trimmed };
  const name = trimmed.slice(0, at);
  const requested = trimmed.slice(at + 1);
  if (name === "" || requested === "") {
    return { raw, name: trimmed, unsupported: "invalid" };
  }
  return { raw, name, requested };
}

/**
 * Splits an argv list into recognized package specs and forwarded flags.
 * Anything starting with "-" is treated as a flag and preserved untouched.
 */
export function partitionArgs(args: string[]): {
  specs: ParsedSpec[];
  flags: string[];
} {
  const specs: ParsedSpec[] = [];
  const flags: string[] = [];
  for (const arg of args) {
    if (arg.startsWith("-")) {
      flags.push(arg);
      continue;
    }
    specs.push(parseSpec(arg));
  }
  return { specs, flags };
}
