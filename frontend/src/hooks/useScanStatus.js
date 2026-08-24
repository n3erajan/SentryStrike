import { useState, useEffect, useRef, useCallback } from "react";
import { SCAN_PHASES } from "../data/constants.js";
import { getScanStatus, cancelScan } from "../services/scan.js";

const POLL_INTERVAL_MS = 4000;
// Once the scan itself is complete we keep polling for the analyzer's result,
// but only for this many ticks (~10 min) so a stalled or disabled analyzer
// doesn't leave the page polling indefinitely.
const MAX_ANALYSIS_POLLS = 150;

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

// The worker reports several distinct messages under one phase key - detector
// progress alone walks from "Running 12 active detectors" to "Detectors 7/12
// complete". Deduping on the phase key would freeze the log at each phase's
// first message, so key on the phase and message together. Returns the key to
// record, or null when this poll adds nothing new.
function nextPhaseLogKey(status, phase, message, lastKey) {
  if (status !== "running" || !message) return null;
  const key = `${phase}|${message}`;
  return key === lastKey ? null : key;
}

// Polls one scan's backend-owned lifecycle. Terminal statuses stop polling;
// cancellation remains pending until the scanner worker acknowledges it.
//
// AI enrichment runs in a separate analyzer worker after the scan itself
// completes, so `analysis` keeps updating past the scan's terminal status -
// polling continues until that reaches a terminal state too.
function useScanStatus(scanId) {
  const [status, setStatus] = useState(null);
  const [progress, setProgress] = useState(0);
  const [phase, setPhase] = useState("queued");
  const [eta, setEta] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");
  const [cancelling, setCancelling] = useState(false);
  const [siteTitle, setSiteTitle] = useState("");
  const [applicationName, setApplicationName] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [statistics, setStatistics] = useState(null);
  const [crawlMode, setCrawlMode] = useState("");
  const [applicationId, setApplicationId] = useState("");

  const logRef = useRef(null);
  const lastPhaseRef = useRef("");
  const lastAnalysisRef = useRef("");
  const analysisPollsRef = useRef(0);
  const doneRef = useRef(false);

  const stageIdx = stageForProgress(progress, status, phase);
  const active = status === "queued" || status === "running" || status === null;

  const pushLog = useCallback((kind, text) => {
    setLogs((prev) => [...prev, { kind, text, time: Date.now() }]);
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
      setError(err);
    }
  }, [scanId, cancelling, pushLog]);

  useEffect(() => {
    if (!scanId) return undefined;

    let stopped = false;
    let polling = false;
    let id = null;
    const controller = new AbortController();
    lastPhaseRef.current = "";
    lastAnalysisRef.current = "";
    analysisPollsRef.current = 0;
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
        const nextAnalysis = scan.analysis || null;

        setProgress(nextProgress);
        setStatus(scan.status);
        setPhase(nextPhase);
        setAnalysis(nextAnalysis);
        setEta(
          typeof scan.eta_seconds === "number" && scan.eta_seconds >= 0
            ? scan.eta_seconds
            : null,
        );
        if (scan.site_title) setSiteTitle(scan.site_title);
        if (scan.application_name) setApplicationName(scan.application_name);
        if (scan.target_url) setTargetUrl(scan.target_url);
        if (scan.statistics) setStatistics(scan.statistics);
        if (scan.crawl_mode) setCrawlMode(scan.crawl_mode);
        if (scan.application_id) setApplicationId(scan.application_id);

        const phaseLogKey = nextPhaseLogKey(
          scan.status,
          nextPhase,
          nextMessage,
          lastPhaseRef.current,
        );
        if (phaseLogKey) {
          lastPhaseRef.current = phaseLogKey;
          pushLog("ok", `[phase] ${nextMessage}`);
        }

        // The analyzer keeps working after the scan itself finishes, so log its
        // transitions too rather than leaving the view apparently frozen.
        const analysisStatus = nextAnalysis?.status || "";
        if (analysisStatus && analysisStatus !== lastAnalysisRef.current) {
          lastAnalysisRef.current = analysisStatus;
          const analysisDone = analysisStatus === "completed";
          const analysisFailed = analysisStatus === "failed";
          if (analysisDone || analysisFailed || analysisStatus === "running") {
            pushLog(
              analysisFailed ? "warn" : "ok",
              `[analysis] ${
                nextAnalysis.message ||
                nextAnalysis.error_message ||
                `AI analysis ${analysisStatus}`
              }`,
            );
          }
        }
        // Enrichment is still in flight; keep polling even once the scan is
        // done. `not_requested` also counts as pending, because the analyzer
        // handoff lands a moment after the scan flips to completed - but the
        // post-completion polling is capped so a job that never gets enqueued
        // (AI analysis disabled, analyzer down) doesn't poll forever.
        const analysisTerminal = ["completed", "failed", "cancelled"].includes(
          analysisStatus,
        );

        if (scan.status === "completed" && !doneRef.current) {
          doneRef.current = true;
          setProgress(100);
          setEta(0);
          setCancelling(false);
          pushLog("ok", "[complete] Report ready");
        }
        if (scan.status === "completed") {
          if (analysisTerminal) stopPolling();
          else if (++analysisPollsRef.current > MAX_ANALYSIS_POLLS)
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
        setError(err);
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
    stageIdx,
    eta,
    analysis,
    siteTitle,
    applicationName,
    targetUrl,
    statistics,
    crawlMode,
    applicationId,
    logs,
    logRef,
    error,
    active,
    cancelling,
    cancel,
  };
}

export { useScanStatus, stageForProgress, nextPhaseLogKey };
export default useScanStatus;
