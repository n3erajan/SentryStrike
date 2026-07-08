import { useState, useEffect, useRef, useCallback } from "react";
import { isValidUrl } from "../utils/helpers.js";
import { SCAN_STAGES } from "../data/constants.js";
import { createScan, getScanStatus, cancelScan } from "../services/scan.js";

const POLL_INTERVAL_MS = 5000;

// The backend reports numeric progress + a status string; it does not stream
// per-stage labels. We derive a stage from progress so the UI stays in step
// with real work instead of a fake timer.
function stageForProgress(progress, status) {
  if (status === "completed") return SCAN_STAGES.length - 1;
  if (status === "queued" || !status) return 0;
  const idx = Math.floor((progress / 100) * (SCAN_STAGES.length - 1));
  return Math.max(0, Math.min(SCAN_STAGES.length - 2, idx));
}

function useScan(onComplete) {
  // Inputs required by the backend CreateScanRequest.
  const [url, setUrl] = useState("");
  const [crawlMode, setCrawlMode] = useState("full"); // full | single
  const [authText, setAuthText] = useState("");
  const [consent, setConsent] = useState(false);
  const [touched, setTouched] = useState(false);

  // Optional per-scan ScanConfig overrides. Keyed by the backend field name;
  // any key left blank/absent falls back to the backend default. `scan_mode`
  // is just another config key here.
  const [config, setConfig] = useState({});
  const setConfigField = useCallback((key, value) => {
    setConfig((prev) => {
      if (value === "" || value === undefined || value === null) {
        const next = { ...prev };
        delete next[key];
        return next;
      }
      return { ...prev, [key]: value };
    });
  }, []);

  // Optional test-account credentials for authenticated / IDOR testing. Shape:
  // { main: {username, password, ...}, second: {...}, admin: {...} }.
  const [credentials, setCredentials] = useState({});
  const setCredentialField = useCallback((role, key, value) => {
    setCredentials((prev) => {
      const account = { ...(prev[role] || {}) };
      if (value === "" || value === undefined || value === null) {
        delete account[key];
      } else {
        account[key] = value;
      }
      const next = { ...prev };
      if (Object.keys(account).length) next[role] = account;
      else delete next[role];
      return next;
    });
  }, []);

  // Live scan state.
  const [scanning, setScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [status, setStatus] = useState(null);
  const [progress, setProgress] = useState(0);
  const [eta, setEta] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState("");

  const logRef = useRef(null);
  const startRef = useRef(0);
  const doneRef = useRef(false);
  const lastStageRef = useRef(-1);

  const valid = isValidUrl(url);
  const canStart = valid && consent && !scanning;
  const stageIdx = stageForProgress(progress, status);

  const pushLog = useCallback((kind, text) => {
    setLogs((prev) => [...prev, { kind, text }]);
  }, []);

  const startScan = useCallback(async () => {
    setTouched(true);
    if (!valid || !consent || scanning) return;

    setError("");
    setLogs([]);
    setProgress(0);
    setEta(null);
    setStatus("queued");
    setScanId(null);
    doneRef.current = false;
    lastStageRef.current = -1;
    startRef.current = Date.now();
    setScanning(true);
    pushLog("ok", `[✓] Requesting authorized scan of ${url}`);

    try {
      const res = await createScan({
        targetUrl: url,
        crawlMode,
        authorizationConfirmed: consent,
        authorizationText: authText,
        config,
        credentials,
      });
      setScanId(res.scan_id);
      setStatus(res.status || "queued");
      setProgress(typeof res.progress === "number" ? res.progress : 0);
      pushLog("ok", `[✓] Scan queued · id ${res.scan_id}`);
    } catch (err) {
      setError(err.message || "Could not start the scan.");
      pushLog("warn", `[!] ${err.message || "Could not start the scan."}`);
      setScanning(false);
      setStatus("failed");
    }
  }, [
    valid,
    consent,
    scanning,
    url,
    crawlMode,
    authText,
    config,
    credentials,
    pushLog,
  ]);

  const cancel = useCallback(async () => {
    if (!scanId) {
      setScanning(false);
      setStatus(null);
      return;
    }
    pushLog("warn", "[!] Cancelling scan…");
    try {
      await cancelScan(scanId);
    } catch {
      // Best-effort — we stop polling locally regardless.
    }
    setStatus("cancelled");
    setScanning(false);
  }, [scanId, pushLog]);

  // Poll the backend for real status/progress once a scan is queued.
  useEffect(() => {
    if (!scanning || !scanId) return undefined;

    let stopped = false;
    const controller = new AbortController();

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
          pushLog("ok", "[✓] Scan complete — compiling report");
          setScanning(false);
          setTimeout(() => onComplete({ scanId, target: url }), 800);
        } else if (s.status === "failed") {
          setError(s.error || "The scan failed. Please try again.");
          pushLog("warn", `[!] ${s.error || "Scan failed"}`);
          setScanning(false);
        } else if (s.status === "cancelled") {
          pushLog("warn", "[!] Scan cancelled");
          setScanning(false);
        }
      } catch (err) {
        if (stopped || err.name === "AbortError") return;
        setError(err.message || "Lost connection to the scan.");
        pushLog("warn", `[!] ${err.message || "Lost connection to the scan."}`);
        setScanning(false);
      }
    }

    poll();
    const id = setInterval(poll, POLL_INTERVAL_MS);
    return () => {
      stopped = true;
      controller.abort();
      clearInterval(id);
    };
  }, [scanning, scanId, url, onComplete, pushLog]);

  // Keep the live log scrolled to the newest line.
  useEffect(() => {
    logRef.current?.scrollTo({
      top: logRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [logs]);

  return {
    // inputs
    url,
    setUrl,
    crawlMode,
    setCrawlMode,
    authText,
    setAuthText,
    consent,
    setConsent,
    touched,
    setTouched,
    // advanced overrides
    config,
    setConfigField,
    credentials,
    setCredentialField,
    // live state
    scanning,
    status,
    progress,
    stageIdx,
    eta,
    logs,
    logRef,
    error,
    scanId,
    // derived + actions
    valid,
    canStart,
    startScan,
    cancel,
  };
}

export { useScan };
