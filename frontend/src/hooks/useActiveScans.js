import { useCallback, useEffect, useState } from "react";
import { listScans } from "../services/scan.js";

const POLL_INTERVAL_MS = 5000;
const ACTIVE_STATUSES = new Set(["queued", "running"]);
const ANALYSIS_ACTIVE = new Set(["queued", "running"]);

export function isAnalysisPending(scan) {
  return (
    scan.status === "completed" &&
    ANALYSIS_ACTIVE.has(scan.analysis?.status)
  );
}

export function isActive(scan) {
  if (ACTIVE_STATUSES.has(scan.status)) return true;
  return isAnalysisPending(scan);
}

// Polls GET /scans on an interval and exposes the scans that are still in
// flight (queued or running) or completed but still running AI analysis.
// Backs both the Active dashboard and the sidebar count badge, so the user
// can watch every concurrent scan. `refresh()` forces an immediate re-fetch
// (e.g. right after starting a new scan).
export function useActiveScans({ intervalMs = POLL_INTERVAL_MS } = {}) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [refreshToken, setRefreshToken] = useState(0);

  const refresh = useCallback(() => {
    setRefreshToken((value) => value + 1);
  }, []);

  useEffect(() => {
    let stopped = false;
    let timer = null;
    const controller = new AbortController();

    async function poll() {
      try {
        const data = await listScans({ limit: 25, signal: controller.signal });
        if (stopped) return;
        const items = Array.isArray(data?.items) ? data.items : [];
        const active = items.filter(isActive);
        setScans(active);
        setError("");
        if (!active.length && timer) {
          clearInterval(timer);
          timer = null;
        }
      } catch (err) {
        if (stopped || err.name === "AbortError") return;
        setError(err.message || "Could not load active scans.");
      } finally {
        if (!stopped) setLoading(false);
      }
    }

    poll();
    timer = setInterval(poll, intervalMs);
    return () => {
      stopped = true;
      controller.abort();
      if (timer) clearInterval(timer);
    };
  }, [intervalMs, refreshToken]);

  return { scans, loading, error, count: scans.length, refresh };
}

export { useActiveScans as default };
