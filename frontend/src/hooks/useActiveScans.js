import { useCallback, useEffect, useMemo } from "react";
import { listScans } from "../services/scan.js";
import useQuery from "./useQuery.js";
import {
  invalidateQueries,
  retainQueryPolling,
} from "../services/queryCache.js";

const POLL_INTERVAL_MS = 5000;
export const ACTIVE_SCANS_QUERY_KEY = "scans:list:25";
const ACTIVE_STATUSES = new Set(["queued", "running"]);
const ANALYSIS_ACTIVE = new Set(["queued", "running"]);
const TERMINAL_STATUSES = new Set(["completed", "failed", "cancelled"]);
const ANALYSIS_TERMINAL = new Set(["completed", "failed", "cancelled"]);

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

export function findFinishedScans(previousItems, nextItems) {
  const previousById = new Map(
    (previousItems || []).map((scan) => [scan.id, scan]),
  );

  return (nextItems || []).filter((scan) => {
    const previous = previousById.get(scan.id);
    if (!previous) return false;

    const scanFinished =
      !TERMINAL_STATUSES.has(previous.status) &&
      TERMINAL_STATUSES.has(scan.status);
    const analysisFinished =
      scan.status === "completed" &&
      ANALYSIS_ACTIVE.has(previous.analysis?.status) &&
      ANALYSIS_TERMINAL.has(scan.analysis?.status);

    return scanFinished || analysisFinished;
  });
}

// Overlays freshly-polled records onto a list that isn't polled itself.
//
// The scans table reads `scans:list:all`, which is only refetched when a scan
// reaches a terminal status — so an in-flight scan's progress and phase columns
// would sit frozen at their mount-time values. `scans:list:25` is already being
// polled every few seconds for the active count, so reuse those records rather
// than issuing a second request.
//
// Only *active* scans are overlaid. Once a scan finishes it drops out of the
// polled set at the same moment `scans:list:all` is invalidated, so the base
// list is authoritative again and a stale poll result can't overwrite it.
export function mergeLiveScans(baseItems, polledItems) {
  const base = baseItems || [];
  const live = new Map();
  for (const scan of polledItems || []) {
    if (isActive(scan)) live.set(scan.id, scan);
  }
  if (live.size === 0) return base;
  return base.map((scan) => live.get(scan.id) || scan);
}

export async function invalidateFinishedScanQueries(finishedScans) {  if (finishedScans.length === 0) return;

  const invalidations = [
    invalidateQueries("scans:list:all"),
    invalidateQueries("applications:scans"),
  ];
  finishedScans.forEach((scan) => {
    if (scan.status === "completed") {
      invalidations.push(invalidateQueries(`reports:detail:${scan.id}`));
    }
  });
  await Promise.all(invalidations);
}

// Polls GET /scans on an interval and exposes the scans that are still in
// flight (queued or running) or completed but still running AI analysis.
// Backs both the Active dashboard and the sidebar count badge, so the user
// can watch every concurrent scan. `refresh()` forces an immediate re-fetch
// (e.g. right after starting a new scan).
export function useActiveScans({ intervalMs = POLL_INTERVAL_MS } = {}) {
  const {
    data,
    error,
    contentEntered,
    isLoading: loading,
    refetch,
  } = useQuery({
    queryKey: ACTIVE_SCANS_QUERY_KEY,
    queryFn: () => listScans({ limit: 25 }),
    staleTime: POLL_INTERVAL_MS,
  });
  const items = useMemo(
    () => (Array.isArray(data?.items) ? data.items : []),
    [data],
  );
  const scans = items.filter(isActive);
  const hasActiveScans = scans.length > 0;

  const refresh = useCallback(() => {
    invalidateQueries("applications:scans");
    return invalidateQueries("scans");
  }, []);

  const poll = useCallback(async () => {
    const nextData = await refetch();
    const nextItems = Array.isArray(nextData?.items) ? nextData.items : [];
    const finishedScans = findFinishedScans(items, nextItems);
    await invalidateFinishedScanQueries(finishedScans);
    return nextData;
  }, [items, refetch]);

  useEffect(() => {
    if (!hasActiveScans) return;
    return retainQueryPolling(ACTIVE_SCANS_QUERY_KEY, intervalMs, poll);
  }, [hasActiveScans, intervalMs, poll]);

  return {
    scans,
    allScans: items,
    loading,
    error,
    count: scans.length,
    contentEntered,
    refresh,
  };
}

export { useActiveScans as default };
