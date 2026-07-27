import test from "node:test";
import assert from "node:assert/strict";

import { apiErrorFromPayload } from "./apiClient.js";

test("formats structured validation errors as concise field guidance", () => {
  const error = apiErrorFromPayload(
    {
      error_code: "VALIDATION_ERROR",
      request_id: "abc123",
      field_errors: [{ field: "email", message: "Enter a valid email address." }],
    },
    422,
  );

  assert.equal(error.message, "Email: Enter a valid email address.");
  assert.equal(error.code, "VALIDATION_ERROR");
  assert.equal(error.requestId, "abc123");
});

test("cleans legacy FastAPI validation messages", () => {
  const error = apiErrorFromPayload(
    {
      detail: [
        {
          type: "value_error",
          loc: ["body", "email"],
          msg: "Value error, Enter a valid email address.",
        },
      ],
    },
    422,
  );

  assert.equal(error.message, "Email: Enter a valid email address.");
  assert.doesNotMatch(error.message, /value error/i);
});

test("does not expose technical or server-side messages", () => {
  const technical = apiErrorFromPayload(
    { message: "Redis ConnectionError at /app/worker.py:44", request_id: "ref500" },
    500,
  );

  assert.equal(technical.message, "We couldn't complete your request. Please try again.");
  assert.equal(technical.requestId, "ref500");
});

test("uses professional status copy for empty responses", () => {
  assert.equal(
    apiErrorFromPayload(null, 404).message,
    "We couldn't find the requested resource.",
  );
});
