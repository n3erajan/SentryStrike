const DEFAULT_STALE_TIME_MS = 60_000;

const EMPTY_SNAPSHOT = Object.freeze({
  data: undefined,
  error: null,
  hasData: false,
  isFetching: false,
  status: "idle",
  updatedAt: 0,
});

const queries = new Map();
const pollers = new Map();

function normalizeKey(queryKey) {
  const key = String(queryKey || "").trim();
  if (!key) throw new Error("queryKey must be a non-empty string");
  return key;
}

function createEntry(key) {
  return {
    key,
    listeners: new Set(),
    promise: null,
    queryFn: null,
    staleTime: DEFAULT_STALE_TIME_MS,
    invalidatedWhileFetching: false,
    writeVersion: 0,
    snapshot: EMPTY_SNAPSHOT,
  };
}

function getEntry(queryKey) {
  const key = normalizeKey(queryKey);
  let entry = queries.get(key);
  if (!entry) {
    entry = createEntry(key);
    queries.set(key, entry);
  }
  return entry;
}

function publish(entry, nextSnapshot) {
  entry.snapshot = nextSnapshot;
  entry.listeners.forEach((listener) => listener());
}

function isFresh(snapshot, staleTime) {
  return (
    snapshot.hasData &&
    !snapshot.error &&
    snapshot.updatedAt > 0 &&
    Date.now() - snapshot.updatedAt < staleTime
  );
}

export function getQuerySnapshot(queryKey) {
  return queries.get(normalizeKey(queryKey))?.snapshot || EMPTY_SNAPSHOT;
}

export function getQueryData(queryKey) {
  const snapshot = getQuerySnapshot(queryKey);
  return snapshot.hasData ? snapshot.data : undefined;
}

export function subscribeToQuery(queryKey, listener) {
  const entry = getEntry(queryKey);
  entry.listeners.add(listener);
  return () => entry.listeners.delete(listener);
}

export function fetchQuery({
  queryKey,
  queryFn,
  staleTime = DEFAULT_STALE_TIME_MS,
  force = false,
}) {
  if (typeof queryFn !== "function") {
    throw new TypeError("queryFn must be a function");
  }

  const entry = getEntry(queryKey);
  entry.queryFn = queryFn;
  entry.staleTime = staleTime;

  if (entry.promise) return entry.promise;
  if (!force && isFresh(entry.snapshot, staleTime)) {
    return Promise.resolve(entry.snapshot.data);
  }

  const requestWriteVersion = entry.writeVersion;
  entry.invalidatedWhileFetching = false;
  publish(entry, {
    ...entry.snapshot,
    error: null,
    isFetching: true,
    status: entry.snapshot.hasData ? "success" : "pending",
  });

  entry.promise = Promise.resolve()
    .then(queryFn)
    .then(
      (data) => {
        if (requestWriteVersion !== entry.writeVersion) {
          return entry.snapshot.data;
        }
        publish(entry, {
          data,
          error: null,
          hasData: true,
          isFetching: false,
          status: "success",
          updatedAt: entry.invalidatedWhileFetching ? 0 : Date.now(),
        });
        return data;
      },
      (error) => {
        publish(entry, {
          ...entry.snapshot,
          error,
          isFetching: false,
          status: "error",
        });
        throw error;
      },
    )
    .finally(() => {
      entry.promise = null;
      if (
        entry.invalidatedWhileFetching &&
        entry.listeners.size > 0 &&
        entry.queryFn
      ) {
        fetchQuery({
          queryKey: entry.key,
          queryFn: entry.queryFn,
          staleTime: entry.staleTime,
          force: true,
        }).catch(() => {});
      }
    });

  return entry.promise;
}

export function setQueryData(queryKey, value) {
  const entry = getEntry(queryKey);
  const data = typeof value === "function" ? value(entry.snapshot.data) : value;
  entry.writeVersion += 1;
  publish(entry, {
    data,
    error: null,
    hasData: true,
    isFetching: false,
    status: "success",
    updatedAt: Date.now(),
  });
  return data;
}

export function invalidateQueries(prefix, { refetchActive = true } = {}) {
  const normalizedPrefix = normalizeKey(prefix);
  const refetches = [];

  for (const entry of queries.values()) {
    if (
      entry.key !== normalizedPrefix &&
      !entry.key.startsWith(`${normalizedPrefix}:`)
    ) {
      continue;
    }

    publish(entry, { ...entry.snapshot, updatedAt: 0 });
    if (!refetchActive || entry.listeners.size === 0 || !entry.queryFn) continue;

    if (entry.promise) {
      entry.invalidatedWhileFetching = true;
      refetches.push(entry.promise);
      continue;
    }

    refetches.push(
      fetchQuery({
        queryKey: entry.key,
        queryFn: entry.queryFn,
        staleTime: entry.staleTime,
        force: true,
      }),
    );
  }

  return Promise.allSettled(refetches);
}

function restartPoller(poller) {
  if (poller.timer) clearInterval(poller.timer);
  if (poller.subscribers.size === 0) return;

  const intervalMs = Math.min(
    ...Array.from(poller.subscribers.values(), ({ intervalMs: value }) => value),
  );
  poller.timer = setInterval(() => {
    const subscriber = poller.subscribers.values().next().value;
    Promise.resolve(subscriber?.callback()).catch(() => {});
  }, intervalMs);
}

export function retainQueryPolling(queryKey, intervalMs, callback) {
  const key = normalizeKey(queryKey);
  const token = Symbol(key);
  let poller = pollers.get(key);
  if (!poller) {
    poller = { subscribers: new Map(), timer: null };
    pollers.set(key, poller);
  }
  poller.subscribers.set(token, { intervalMs, callback });
  restartPoller(poller);

  return () => {
    poller.subscribers.delete(token);
    if (poller.subscribers.size === 0) {
      if (poller.timer) clearInterval(poller.timer);
      pollers.delete(key);
    } else {
      restartPoller(poller);
    }
  };
}

export function clearQueryCache() {
  const listeners = new Set();
  queries.forEach((entry) => entry.listeners.forEach((listener) => listeners.add(listener)));
  queries.clear();

  pollers.forEach((poller) => {
    if (poller.timer) clearInterval(poller.timer);
  });
  pollers.clear();
  listeners.forEach((listener) => listener());
}

export { DEFAULT_STALE_TIME_MS };
