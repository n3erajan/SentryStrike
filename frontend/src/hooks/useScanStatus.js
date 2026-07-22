import { useState, useEffect, useRef, useCallback } from "react";
import { SCAN_PHASES } from "../data/constants.js";
import { getScanStatus, cancelScan } from "../services/scan.js";

const POLL_INTERVAL_MS = 4000;

// Prefer the worker's named phase. The progress fallback keeps the view usable
// with older scan records that predate current_phase.
function stageForProgress(progress, status, currentPhase) {
  if (status === "completed") return SCAN_PHASES.length;
  if (status === "queued" || !status) return 0;
  const phaseIdx = SCAN_PHASES.findIndex(({ key }) => key === currentPhase);
  if (phaseIdx >= 0) return phaseIdx;
  const idx = Math.floor((progress / 100) * SCAN_PHASES.length);
  return Math.max(1, Math.min(SCAN_PHASES.length - 1, idx));
}

// Polls one scan's backend-owned lifecycle. Terminal statuses stop polling;
// cancellation remains pending until the scanner worker acknowledges it.
function useScanStatus(scanId) {
  const [status, setStatus] = useState(null);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("queued");
  const [phaseMessage, setPhaseMessage] = useState("Scan queued");
  const [eta, setEta] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");
  const [cancelling, setCancelling] = useState(false);

  const logRef = useRef(null);
  const lastPhaseRef = useRef("");
  const doneRef = useRef(false);

  const stageIdx = stageForProgress(progress, status, phase);
  const active = status === "queued" || status === "running" || status === null;

  const pushLog = useCallback((kind, text) => {
    setLogs((prev) => [...prev, { kind, text }]);
  }, []);

  const cancel = useCallback(async () => {
    if (!scanId || cancelling) return;
    setCancelling(true);
    setError("");
    pushLog("warn", "[pending] Cancellation requested");
    try {
      const result = await cancelScan(scanId);
      if (!result?.cancelled) {
        setCancelling(false);
        pushLog("warn", "[info] This scan can no longer be cancelled");
      }
    } catch (err) {
      setCancelling(false);
      setError(err.message || "Could not request cancellation.");
    }
  }, [scanId, cancelling, pushLog]);

  useEffect(() => {
    if (!scanId) return undefined;

    let stopped = false;
    let polling = false;
    let id = null;
    const controller = new AbortController();
    lastPhaseRef.current = "";
    doneRef.current = false;

    function stopPolling() {
      if (id) clearInterval(id);
      id = null;
    }

    async function poll() {
      if (stopped || polling) return;
      polling = true;
      try {
        const scan = await getScanStatus(scanId, controller.signal);
        if (stopped) return;

        const nextProgress =
          typeof scan.progress === "number" ? scan.progress : 0;
        const nextPhase = scan.current_phase || "queued";
        const nextMessage = scan.phase_message || "Scan in progress";

        setProgress(nextProgress);
        setStatus(scan.status);
        setPhase(nextPhase);
        setPhaseMessage(nextMessage);
        setEta(
          typeof scan.eta_seconds === "number" && scan.eta_seconds >= 0
            ? scan.eta_seconds
            : null,
        );

        if (
          nextPhase !== lastPhaseRef.current &&
          scan.status === "running"
        ) {
          lastPhaseRef.current = nextPhase;
          pushLog("ok", `[phase] ${nextMessage}`);
        }

        if (scan.status === "completed" && !doneRef.current) {
          doneRef.current = true;
          setProgress(100);
          setEta(0);
          setCancelling(false);
          pushLog("ok", "[complete] Report ready");
          stopPolling();
        } else if (scan.status === "failed") {
          const failureMessage =
            scan.error ||
            scan.error_message ||
            "The scan failed. Please try again.";
          setError(failureMessage);
          pushLog("warn", `[!] ${failureMessage}`);
          setCancelling(false);
          stopPolling();
        } else if (scan.status === "cancelled") {
          pushLog("warn", "[!] Scan cancelled");
          setCancelling(false);
          stopPolling();
        }
      } catch (err) {
        if (stopped || err.name === "AbortError") return;
        setError(err.message || "Lost connection to the scan.");
        pushLog("warn", `[!] ${err.message || "Lost connection to the scan."}`);
        stopPolling();
      } finally {
        polling = false;
      }
    }

    id = setInterval(poll, POLL_INTERVAL_MS);
    poll();
    return () => {
      stopped = true;
      controller.abort();
      stopPolling();
    };
  }, [scanId, pushLog]);

  useEffect(() => {
    logRef.current?.scrollTo({
      top: logRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [logs]);

  return {
    status,
    progress,
    phase,
    phaseMessage,
    stageIdx,
    eta,
    logs,
    logRef,
    error,
    active,
    cancelling,
    cancel,
  };
}

export { useScanStatus, stageForProgress };
export default useScanStatus;
