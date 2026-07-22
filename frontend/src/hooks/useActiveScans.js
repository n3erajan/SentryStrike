import { useCallback, useEffect, useState } from "react";
import { listScans } from "../services/scan.js";

const ACTIVE_STATUSES = new Set(["queued", "running"]);

// Loads GET /scans once when the consuming page mounts and exposes only scans
// that are still in flight. `refresh()` is available for an explicit reload
// without creating background traffic while the user is elsewhere in the app.
export function useActiveScans() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshToken, setRefreshToken] = useState(0);

  const refresh = useCallback(() => {
    setRefreshToken((value) => value + 1);
  }, []);

  useEffect(() => {
    let stopped = false;
    const controller = new AbortController();

    async function load() {
      setLoading(true);
      try {
        const data = await listScans({ limit: 100, signal: controller.signal });
        if (stopped) return;
        const items = Array.isArray(data?.items) ? data.items : [];
        setScans(items.filter((s) => ACTIVE_STATUSES.has(s.status)));
        setError("");
      } catch (err) {
        if (stopped || err.name === "AbortError") return;
        setError(err.message || "Could not load active scans.");
      } finally {
        if (!stopped) setLoading(false);
      }
    }

    load();
    return () => {
      stopped = true;
      controller.abort();
    };
  }, [refreshToken]);

  return { scans, loading, error, count: scans.length, refresh };
}

export { useActiveScans as default };
