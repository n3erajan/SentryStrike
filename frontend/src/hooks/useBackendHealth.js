import { useEffect, useState } from "react";
import { getHealth } from "../services/health.js";

const POLL_INTERVAL_MS = 15000;

export function useBackendHealth({ intervalMs = POLL_INTERVAL_MS } = {}) {
  const [health, setHealth] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    let stopped = false;
    let polling = false;
    const controller = new AbortController();

    async function poll() {
      if (stopped || polling) return;
      polling = true;
      try {
        const data = await getHealth(controller.signal);
        if (stopped) return;
        setHealth(data);
        setError("");
      } catch (err) {
        if (stopped || err.name === "AbortError") return;
        setError(err.message || "Could not read scanner health.");
      } finally {
        polling = false;
        if (!stopped) setLoading(false);
      }
    }

    const id = setInterval(poll, intervalMs);
    poll();
    return () => {
      stopped = true;
      controller.abort();
      clearInterval(id);
    };
  }, [intervalMs]);

  return { health, loading, error };
}

export default useBackendHealth;
