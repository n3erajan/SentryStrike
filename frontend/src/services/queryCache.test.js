import test from "node:test";
import assert from "node:assert/strict";

import {
  clearQueryCache,
  fetchQuery,
  getQueryData,
  getQuerySnapshot,
  invalidateQueries,
  setQueryData,
  subscribeToQuery,
} from "./queryCache.js";

test.beforeEach(() => clearQueryCache());

test("serves fresh cached data without repeating the request", async () => {
  let calls = 0;
  const queryFn = async () => ({ value: ++calls });

  const first = await fetchQuery({ queryKey: "apps:list", queryFn });
  const second = await fetchQuery({ queryKey: "apps:list", queryFn });

  assert.deepEqual(first, { value: 1 });
  assert.strictEqual(second, first);
  assert.equal(calls, 1);
});

test("deduplicates callers while a request is in flight", async () => {
  let resolveRequest;
  let calls = 0;
  const queryFn = () => {
    calls += 1;
    return new Promise((resolve) => {
      resolveRequest = resolve;
    });
  };

  const first = fetchQuery({ queryKey: "workspace", queryFn });
  const second = fetchQuery({ queryKey: "workspace", queryFn });
  await Promise.resolve();
  resolveRequest({ name: "Acme" });

  assert.strictEqual(first, second);
  assert.deepEqual(await first, { name: "Acme" });
  assert.equal(calls, 1);
});

test("keeps a first-load placeholder mounted through a fast response", async () => {
  const request = fetchQuery({
    queryKey: "fast-local-request",
    queryFn: async () => ({ ready: true }),
  });

  await Promise.resolve();
  await Promise.resolve();
  assert.equal(getQuerySnapshot("fast-local-request").hasData, false);
  assert.equal(getQuerySnapshot("fast-local-request").status, "pending");

  await request;
  assert.deepEqual(getQueryData("fast-local-request"), { ready: true });
});

test("keeps cached data visible when a background refresh fails", async () => {
  setQueryData("reports:list", ["cached"]);

  await assert.rejects(
    fetchQuery({
      queryKey: "reports:list",
      queryFn: async () => {
        throw new Error("offline");
      },
      force: true,
    }),
    /offline/,
  );

  const snapshot = getQuerySnapshot("reports:list");
  assert.deepEqual(snapshot.data, ["cached"]);
  assert.equal(snapshot.hasData, true);
  assert.equal(snapshot.error.message, "offline");
});

test("retries an errored cache entry even inside its stale window", async () => {
  setQueryData("reports:retry", ["cached"]);
  await assert.rejects(
    fetchQuery({
      queryKey: "reports:retry",
      queryFn: async () => {
        throw new Error("offline");
      },
      force: true,
    }),
  );

  const data = await fetchQuery({
    queryKey: "reports:retry",
    queryFn: async () => ["fresh"],
  });

  assert.deepEqual(data, ["fresh"]);
  assert.equal(getQuerySnapshot("reports:retry").error, null);
});

test("does not let an older request overwrite mutation data", async () => {
  let resolveRequest;
  const request = fetchQuery({
    queryKey: "workspace",
    queryFn: () =>
      new Promise((resolve) => {
        resolveRequest = resolve;
      }),
  });
  await Promise.resolve();

  setQueryData("workspace", { name: "Updated" });
  resolveRequest({ name: "Old response" });
  await request;

  assert.deepEqual(getQueryData("workspace"), { name: "Updated" });
});

test("invalidating a prefix refreshes active matching queries", async () => {
  let calls = 0;
  const queryFn = async () => ++calls;
  const unsubscribe = subscribeToQuery("applications:list", () => {});
  await fetchQuery({ queryKey: "applications:list", queryFn });

  await invalidateQueries("applications");

  assert.equal(getQueryData("applications:list"), 2);
  assert.equal(calls, 2);
  unsubscribe();
});

test("clearing the cache removes session-scoped data", () => {
  setQueryData("workspace", { name: "Private workspace" });
  clearQueryCache();

  assert.equal(getQueryData("workspace"), undefined);
  assert.equal(getQuerySnapshot("workspace").hasData, false);
});
