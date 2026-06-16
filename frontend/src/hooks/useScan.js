import React, { useState, useEffect, useRef } from "react";
import { isValidUrl } from "../utils/helpers.js";
import { SCAN_STAGES, LOG_LINES } from "../data/constants.js";

function useScan(onComplete) {
  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [touched, setTouched] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stageIdx, setStageIdx] = useState(0);
  const [logs, setLogs] = useState([]);
  const logRef = useRef(null);

  const valid = isValidUrl(url);
  const canStart = valid && consent && !scanning;
  const eta = Math.max(0, Math.ceil((100 - progress) / 14));

  useEffect(() => {
    if (!scanning) return;
    const start = Date.now(),
      total = 7000;
    const pi = setInterval(() => {
      const p = Math.min(100, ((Date.now() - start) / total) * 100);
      setProgress(p);
      setStageIdx(
        Math.min(
          SCAN_STAGES.length - 1,
          Math.floor((p / 100) * SCAN_STAGES.length),
        ),
      );
      if (p >= 100) {
        clearInterval(pi);
        setTimeout(() => onComplete(url), 700);
      }
    }, 80);
    let i = 0;
    const li = setInterval(() => {
      if (i >= LOG_LINES.length) return clearInterval(li);
      setLogs((l) => [...l, LOG_LINES[i++]]);
    }, 600);
    return () => {
      clearInterval(pi);
      clearInterval(li);
    };
  }, [scanning]); // eslint-disable-line

  useEffect(() => {
    logRef.current?.scrollTo({
      top: logRef.current.scrollHeight,
      behavior: "smooth",
    });
  }, [logs]);

  return {
    url,
    setUrl,
    consent,
    setConsent,
    touched,
    setTouched,
    scanning,
    setScanning,
    progress,
    stageIdx,
    logs,
    logRef,
    valid,
    canStart,
    eta,
  };
}

export { useScan };
