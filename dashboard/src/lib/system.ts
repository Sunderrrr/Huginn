/** Format the worker's optional OS details without guessing missing versions. */
export function formatSystemLabel(os: string | null | undefined, system: string | null | undefined): string {
  const detailed = system?.trim();
  if (detailed) return detailed;

  switch (os?.toLowerCase()) {
    case "windows":
      return "Windows · details unavailable";
    case "linux":
      return "Linux · details unavailable";
    default:
      return os ? `${os} · details unavailable` : "Unknown";
  }
}
