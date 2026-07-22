import { useState, useCallback, useEffect } from "react";
import { isValidUrl } from "../utils/helpers.js";
import { createScan } from "../services/scan.js";
import { getDefaultConfig } from "../services/workspace.js";

// Form state + submission for a new scan. Polling and progress no longer live
// here — once a scan is created the caller navigates to its own active-scan
// page (see ActiveScanPage / useScanStatus). `startScan` resolves to the new
// scan_id (or null on failure), leaving the form intact so the user can queue
// another scan immediately while the first one runs.
function useScanForm() {
  // Inputs required by the backend CreateScanRequest.
  const [url, setUrl] = useState("");
  const [crawlMode, setCrawlMode] = useState("full"); // full | single
  const [consent, setConsent] = useState(false);
  const [touched, setTouched] = useState(false);

  // Optional per-scan ScanConfig overrides. Keyed by the backend field name;
  // any key left blank/absent falls back to the backend default. `scan_mode`
  // is just another config key here.
  const [config, setConfig] = useState({});
  const [defaultsLoading, setDefaultsLoading] = useState(true);
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

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    getDefaultConfig(controller.signal)
      .then((data) => setConfig(data.config || {}))
      .catch((err) => {
        if (err.name !== "AbortError") setError(err.message || "Could not load workspace scan defaults.");
      })
      .finally(() => {
        if (!controller.signal.aborted) setDefaultsLoading(false);
      });
    return () => controller.abort();
  }, []);

  const valid = isValidUrl(url);
  const canStart = valid && consent && !submitting && !defaultsLoading;

  // Creates the scan and returns its id. Returns null (and sets `error`) on
  // failure. Does NOT poll — the caller routes to the active-scan view.
  const startScan = useCallback(async () => {
    setTouched(true);
    if (!valid || !consent || submitting) return null;

    setError("");
    setSubmitting(true);
    try {
      const res = await createScan({
        targetUrl: url,
        crawlMode,
        authorizationConfirmed: consent,
        config,
        credentials,
      });
      return { scanId: res.scan_id, target: url };
    } catch (err) {
      setError(err.message || "Could not start the scan.");
      return null;
    } finally {
      setSubmitting(false);
    }
  }, [valid, consent, submitting, url, crawlMode, config, credentials]);

  return {
    // inputs
    url,
    setUrl,
    crawlMode,
    setCrawlMode,
    consent,
    setConsent,
    touched,
    setTouched,
    // advanced overrides
    config,
    defaultsLoading,
    setConfigField,
    credentials,
    setCredentialField,
    // submission
    submitting,
    error,
    valid,
    canStart,
    startScan,
  };
}

export { useScanForm };
export default useScanForm;
