import type { ScanResult } from "../types.js";

export function reportJson(result: ScanResult): string {
  return JSON.stringify(result, null, 2);
}
