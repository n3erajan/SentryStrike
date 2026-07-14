import { useState, useEffect, useRef, useCallback } from "react";
import { SCAN_STAGES } from "../data/constants.js";
import { getScanStatus, cancelScan } from "../services/scan.js";

const POLL_INTERVAL_MS = 4000;

// The backend reports numeric progress + a status string; it does not stream
// per-stage labels. We derive a stage from progress so the UI stays in step
// with real work instead of a fake timer.
function stageForProgress(progress, status) {
  if (status === "completed") return SCAN_STAGES.length - 1;
  if (status === "queued" || !status) return 0;
  const idx = Math.floor((progress / 100) * (SCAN_STAGES.length - 1));
  return Math.max(0, Math.min(SCAN_STAGES.length - 2, idx));
}

// Polls GET /scans/{id}/status for a single scan and derives a live view:
// progress, stage, ETA, and a running log of stage transitions. Terminal
// statuses stop the poll. Extracted from the old useScan so the active-scan
// page can own the lifecycle of one scan independently of the submit form.
function useScanStatus(scanId) {
  const [status, setStatus] = useState(null);
  const [progress, setProgress] = useState(0);
  const [eta, setEta] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");

  const logRef = useRef(null);
  const startRef = useRef(Date.now());
  const lastStageRef = useRef(-1);
  const doneRef = useRef(false);

  const stageIdx = stageForProgress(progress, status);
  const active = status === "queued" || status === "running" || status === null;

  const pushLog = useCallback((kind, text) => {
    setLogs((prev) => [...prev, { kind, text }]);
  }, []);

  const cancel = useCallback(async () => {
    if (!scanId) return;
    pushLog("warn", "[!] Cancelling scan…");
    try {
      await cancelScan(scanId);
    } catch {
      // Best-effort — polling will reflect the real terminal state.
    }
  }, [scanId, pushLog]);

  useEffect(() => {
    if (!scanId) return undefined;

    let stopped = false;
    const controller = new AbortController();
    startRef.current = Date.now();
    lastStageRef.current = -1;
    doneRef.current = false;

    async function poll() {
      try {
        const s = await getScanStatus(scanId, controller.signal);
        if (stopped) return;

        const p = typeof s.progress === "number" ? s.progress : 0;
        setProgress(p);
        setStatus(s.status);

        const stage = stageForProgress(p, s.status);
        if (stage !== lastStageRef.current && s.status === "running") {
          lastStageRef.current = stage;
          pushLog("ok", `[✓] ${SCAN_STAGES[stage]}`);
        }

        const elapsed = (Date.now() - startRef.current) / 1000;
        if (p > 3 && p < 100 && elapsed > 0) {
          setEta(Math.max(1, Math.ceil((elapsed / p) * (100 - p))));
        }

        if (s.status === "completed" && !doneRef.current) {
          doneRef.current = true;
          setProgress(100);
          setEta(0);
          pushLog("ok", "[✓] Scan complete — report ready");
          stopPolling();
        } else if (s.status === "failed") {
          setError(s.error || "The scan failed. Please try again.");
          pushLog("warn", `[!] ${s.error || "Scan failed"}`);
          stopPolling();
        } else if (s.status === "cancelled") {
          pushLog("warn", "[!] Scan cancelled");
          stopPolling();
        }
      } catch (err) {
        if (stopped || err.name === "AbortError") return;
        setError(err.message || "Lost connection to the scan.");
        pushLog("warn", `[!] ${err.message || "Lost connection to the scan."}`);
        stopPolling();
      }
    }

    let id = null;
    function stopPolling() {
      if (id) clearInterval(id);
      id = null;
    }

    poll();
    id = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      stopped = true;
      controller.abort();
      if (id) clearInterval(id);
    };
  }, [scanId, pushLog]);

  // Keep the live log scrolled to the newest line.
  useEffect(() => {
    logRef.current?.scrollTo({
      top: logRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [logs]);

  return { status, progress, stageIdx, eta, logs, logRef, error, active, cancel };
}

export { useScanStatus, stageForProgress };
export default useScanStatus;
