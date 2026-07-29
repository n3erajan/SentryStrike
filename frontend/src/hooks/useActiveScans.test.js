import test from "node:test";
import assert from "node:assert/strict";

import {
  findFinishedScans,
  invalidateFinishedScanQueries,
} from "./useActiveScans.js";
import {
  clearQueryCache,
  getQuerySnapshot,
  setQueryData,
} from "../services/queryCache.js";

test.beforeEach(() => clearQueryCache());

test("detects a scan becoming terminal", () => {
  const previous = [{ id: "scan-1", status: "running" }];
  const next = [{ id: "scan-1", status: "completed" }];

  assert.deepEqual(findFinishedScans(previous, next), next);
});

test("detects analysis completion after the scan finishes", () => {
  const previous = [
    { id: "scan-1", status: "completed", analysis: { status: "running" } },
  ];
  const next = [
    { id: "scan-1", status: "completed", analysis: { status: "completed" } },
  ];

  assert.deepEqual(findFinishedScans(previous, next), next);
});

test("ignores unchanged and newly observed terminal scans", () => {
  const previous = [{ id: "scan-1", status: "completed" }];
  const next = [
    { id: "scan-1", status: "completed" },
    { id: "scan-2", status: "completed" },
  ];

  assert.deepEqual(findFinishedScans(previous, next), []);
});

test("marks report and application caches stale when a scan finishes", async () => {
  setQueryData("scans:list:all", { items: [{ id: "old-scan" }] });
  setQueryData("applications:scans:app-1", { items: [] });
  setQueryData("reports:detail:scan-1", { analysis: { status: "running" } });

  await invalidateFinishedScanQueries([
    { id: "scan-1", status: "completed" },
  ]);

  assert.equal(getQuerySnapshot("scans:list:all").updatedAt, 0);
  assert.equal(getQuerySnapshot("applications:scans:app-1").updatedAt, 0);
  assert.equal(getQuerySnapshot("reports:detail:scan-1").updatedAt, 0);
});
