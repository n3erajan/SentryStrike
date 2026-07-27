import { useState, useCallback, useEffect } from "react";
import { isValidUrl } from "../utils/helpers.js";
import { createScan } from "../services/scan.js";
import { getApplication } from "../services/applications.js";

// Form state + submission for a new scan. Polling and progress no longer live
// here — once a scan is created the caller navigates to its own active-scan
// page (see ActiveScanPage / useScanStatus). `startScan` resolves to the new
// scan_id (or null on failure), leaving the form intact so the user can queue
// another scan immediately while the first one runs.
//
// `applicationId` is optional. When set, the target URL and config are seeded
// from that application's stored defaults — the workspace-level default config
// no longer exists; defaults live on the Application entity now.
function useScanForm({ applicationId } = {}) {
  // Inputs required by the backend CreateScanRequest.
  const [url, setUrl] = useState("");
  const [crawlMode, setCrawlMode] = useState("full"); // full | single
  const [consent, setConsent] = useState(false);
  const [touched, setTouched] = useState(false);

  // Optional per-scan ScanConfig overrides. Keyed by the backend field name;
  // any key left blank/absent falls back to the backend default. `scan_mode`
  // is just another config key here. Seeded from the selected application.
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

  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");
  // True when the last submit failed because a scan for this target is already
  // in flight (HTTP 409), so the view can render it as guidance not a failure.
  const [conflict, setConflict] = useState(false);

  // Seed the form from the chosen application. Clearing the selection leaves
  // whatever the user has already typed alone — only an explicit pick rewrites
  // the URL and config. `loadedApp` tracks which id the form currently
  // reflects, so the loading flag is derived rather than set synchronously.
  const [loadedApp, setLoadedApp] = useState("");
  useEffect(() => {
    if (!applicationId) return undefined;
    const controller = new AbortController();
    getApplication(applicationId, controller.signal)
      .then((app) => {
        setUrl(app.target_url || "");
        setConfig(app.default_scan_config || {});
      })
      .catch((err) => {
        if (err.name !== "AbortError")
          setError(err);
      })
      .finally(() => {
        if (!controller.signal.aborted) setLoadedApp(applicationId);
      });
    return () => controller.abort();
  }, [applicationId]);

  const defaultsLoading = Boolean(applicationId) && loadedApp !== applicationId;
  const valid = isValidUrl(url);
  const canStart = valid && consent && !submitting && !defaultsLoading;

  // Creates the scan and returns its id. Returns null (and sets `error`) on
  // failure. Does NOT poll — the caller routes to the active-scan view.
  const startScan = useCallback(async () => {
    setTouched(true);
    if (!valid || !consent || submitting) return null;

    setError("");
    setConflict(false);
    setSubmitting(true);
    try {
      const res = await createScan({
        targetUrl: url,
        applicationId,
        crawlMode,
        authorizationConfirmed: consent,
        config,
        credentials,
      });
      return { scanId: res.scan_id, target: url };
    } catch (err) {
      // 409 means a scan for this same target is already queued or running;
      // the backend's message names it, so surface that verbatim.
      setError(err);
      setConflict(err.status === 409);
      return null;
    } finally {
      setSubmitting(false);
    }
  }, [valid, consent, submitting, url, applicationId, crawlMode, config, credentials]);

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
    conflict,
    valid,
    canStart,
    startScan,
  };
}

export { useScanForm };
export default useScanForm;
