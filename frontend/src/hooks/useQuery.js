import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useSyncExternalStore,
} from "react";
import {
  DEFAULT_STALE_TIME_MS,
  fetchQuery,
  getQuerySnapshot,
  subscribeToQuery,
} from "../services/queryCache.js";

export default function useQuery({
  queryKey,
  queryFn,
  staleTime = DEFAULT_STALE_TIME_MS,
  enabled = true,
}) {
  const key = String(queryKey);
  const queryFnRef = useRef(queryFn);
  const hadDataAtMount = useMemo(
    () => getQuerySnapshot(key).hasData,
    [key],
  );

  useEffect(() => {
    queryFnRef.current = queryFn;
  }, [queryFn]);

  const subscribe = useCallback(
    (listener) => subscribeToQuery(key, listener),
    [key],
  );
  const getSnapshot = useCallback(() => getQuerySnapshot(key), [key]);
  const snapshot = useSyncExternalStore(subscribe, getSnapshot, getSnapshot);

  useEffect(() => {
    if (!enabled) return;
    fetchQuery({
      queryKey: key,
      queryFn: () => queryFnRef.current(),
      staleTime,
    }).catch(() => {});
  }, [enabled, key, staleTime]);

  const refetch = useCallback(
    () =>
      fetchQuery({
        queryKey: key,
        queryFn: () => queryFnRef.current(),
        staleTime,
        force: true,
      }),
    [key, staleTime],
  );

  return {
    ...snapshot,
    isLoading:
      enabled && !snapshot.hasData && snapshot.status !== "error",
    isRefreshing: snapshot.hasData && snapshot.isFetching,
    isFetchedAfterMount: !hadDataAtMount && snapshot.hasData,
    refetch,
  };
}
