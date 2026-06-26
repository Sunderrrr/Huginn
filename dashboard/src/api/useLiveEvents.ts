import { useEffect } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, getToken } from "./client";

// Map a server hint to the query-key prefixes to invalidate (prefix match, so
// ["vm"] refreshes every ["vm", id]).
const INVALIDATE: Record<string, string[][]> = {
  tasks: [["audit"], ["vms"], ["vm"]],
  vms: [["vms"], ["vm"]],
};

/**
 * Subscribe to the hub's SSE stream and refresh the matching React Query caches
 * the instant something changes server-side (a worker reports a result, a VM
 * goes offline…), instead of waiting for the next poll.
 *
 * Uses fetch streaming (not EventSource) so the JWT travels in the
 * Authorization header — never in the URL or an access log. Reconnects with
 * backoff; the existing polling stays as a fallback if the stream drops.
 */
export function useLiveEvents(): void {
  const qc = useQueryClient();
  useEffect(() => {
    const controller = new AbortController();
    let stopped = false;

    const handle = (data: string) => {
      try {
        const { type } = JSON.parse(data) as { type?: string };
        for (const key of INVALIDATE[type ?? ""] ?? []) {
          qc.invalidateQueries({ queryKey: key });
        }
      } catch {
        /* ignore malformed events */
      }
    };

    async function run() {
      let backoff = 1000;
      while (!stopped) {
        try {
          const token = getToken();
          if (!token) return;
          const resp = await fetch(`${api.hubUrl}/api/events`, {
            headers: { Authorization: `Bearer ${token}`, Accept: "text/event-stream" },
            signal: controller.signal,
          });
          if (!resp.ok || !resp.body) throw new Error(`sse ${resp.status}`);
          backoff = 1000; // healthy connection — reset backoff

          const reader = resp.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";
          while (!stopped) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            // SSE frames are separated by a blank line.
            let sep: number;
            while ((sep = buffer.indexOf("\n\n")) !== -1) {
              const frame = buffer.slice(0, sep);
              buffer = buffer.slice(sep + 2);
              for (const line of frame.split("\n")) {
                if (line.startsWith("data:")) handle(line.slice(5).trim());
              }
            }
          }
        } catch {
          if (stopped) return;
        }
        // Reconnect with capped exponential backoff.
        await new Promise((r) => setTimeout(r, backoff));
        backoff = Math.min(backoff * 2, 15000);
      }
    }

    void run();
    return () => {
      stopped = true;
      controller.abort();
    };
  }, [qc]);
}
