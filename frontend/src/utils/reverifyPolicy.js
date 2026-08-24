// Client-side mirror of `shared/reverification/policy.py`.
//
// The backend rejects re-verification requests it cannot honour with a 409
// (see `assert_reverify_allowed`). This module reproduces that classification
// so the UI can disable the button and explain why, instead of letting the
// user click into a dead end. The backend remains the authority - a 409 is
// still handled - but the two must be kept in sync by hand when the policy
// changes.
//
// The three ENFORCE_* feature flags are all enabled on the backend, so the
// gates they guard are unconditional here.

export const ReverifyClass = {
  reverifiable: "reverifiable",
  requiresFullScan: "requires_full_scan",
  requiresSecondaryIdentity: "requires_secondary_identity",
  insufficientReplayMetadata: "insufficient_replay_metadata",
};

export const ReverifyFamily = {
  securityHeaders: "security_headers",
  cryptoFailures: "crypto_failures",
  supplyChain: "supply_chain",
  sensitivePaths: "sensitive_paths",
  exceptionHandling: "exception_handling",
  csrf: "csrf",
  openRedirect: "open_redirect",
  sqlInjection: "sql_injection",
  nosqlInjection: "nosql_injection",
  commandInjection: "command_injection",
  fileInclusion: "file_inclusion",
  xss: "xss",
  ssrf: "ssrf",
  fileUpload: "file_upload",
  accessControl: "access_control",
  authentication: "authentication",
  unknown: "unknown",
};

// Detector-name / detector_id tokens → family.
const DETECTOR_ID_ALIASES = [
  ["security_headers", ReverifyFamily.securityHeaders],
  ["crypto_failures", ReverifyFamily.cryptoFailures],
  ["supply_chain", ReverifyFamily.supplyChain],
  ["sensitive_paths", ReverifyFamily.sensitivePaths],
  ["exception_handling", ReverifyFamily.exceptionHandling],
  ["csrf", ReverifyFamily.csrf],
  ["open_redirect", ReverifyFamily.openRedirect],
  ["injection_sql_command", ReverifyFamily.sqlInjection],
  ["sql_injection", ReverifyFamily.sqlInjection],
  ["sqli", ReverifyFamily.sqlInjection],
  ["nosql_injection", ReverifyFamily.nosqlInjection],
  ["command_injection", ReverifyFamily.commandInjection],
  ["file_inclusion", ReverifyFamily.fileInclusion],
  ["xss", ReverifyFamily.xss],
  ["xss_detector", ReverifyFamily.xss],
  ["ssrf", ReverifyFamily.ssrf],
  ["file_upload", ReverifyFamily.fileUpload],
  ["access_control", ReverifyFamily.accessControl],
  ["idor", ReverifyFamily.accessControl],
  ["idor_detector", ReverifyFamily.accessControl],
  ["authentication_failures", ReverifyFamily.authentication],
  ["auth", ReverifyFamily.authentication],
];

const VULN_TYPE_HINTS = [
  [
    [
      "missing security header",
      "content security policy",
      "cors misconfiguration",
      "information disclosure in header",
    ],
    ReverifyFamily.securityHeaders,
  ],
  [
    [
      "insecure transport",
      "mixed content",
      "session cookie",
      "cookie without secure",
      "sensitive data in url",
    ],
    ReverifyFamily.cryptoFailures,
  ],
  [["vulnerable component"], ReverifyFamily.supplyChain],
  [
    ["sensitive path", "exposed", ".git", "backup file"],
    ReverifyFamily.sensitivePaths,
  ],
  [
    ["stack trace", "verbose error", "exception", "error disclosure"],
    ReverifyFamily.exceptionHandling,
  ],
  [["csrf", "cross-site request forgery"], ReverifyFamily.csrf],
  [["open redirect"], ReverifyFamily.openRedirect],
  [["sql injection", "sqli"], ReverifyFamily.sqlInjection],
  [["nosql", "mongodb"], ReverifyFamily.nosqlInjection],
  [
    ["command injection", "os command", "rce"],
    ReverifyFamily.commandInjection,
  ],
  [
    ["file inclusion", "path traversal", "lfi", "rfi", "directory traversal"],
    ReverifyFamily.fileInclusion,
  ],
  [["xss", "cross-site scripting", "dom-based"], ReverifyFamily.xss],
  [["ssrf", "server-side request"], ReverifyFamily.ssrf],
  [["file upload", "unrestricted upload"], ReverifyFamily.fileUpload],
  [
    [
      "idor",
      "bola",
      "broken access",
      "forced browsing",
      "mass assignment",
      "authorization",
    ],
    ReverifyFamily.accessControl,
  ],
  [
    [
      "authentication",
      "session fixation",
      "jwt",
      "brute force",
      "credential",
      "password over get",
    ],
    ReverifyFamily.authentication,
  ],
];

// Auth sub-kinds that need crawl-wide context and cannot be re-verified alone.
const AUTH_FULL_SCAN_MARKERS = [
  "brute",
  "credential stuffing",
  "default credential",
  "lockout",
  "api workflow",
  "login recipe",
  "password spraying",
];

// Passive/structural auth findings that ARE self-contained enough to replay.
const AUTH_SELF_CONTAINED_MARKERS = [
  "password",
  "get method",
  "token in url",
  "token in query",
  "admin path",
  "session cookie",
  "jwt",
  "csrf",
];

// Injection families that need AttackTarget structural metadata for replay.
const INJECTION_FAMILIES = new Set([
  ReverifyFamily.sqlInjection,
  ReverifyFamily.nosqlInjection,
  ReverifyFamily.commandInjection,
  ReverifyFamily.fileInclusion,
  ReverifyFamily.xss,
  ReverifyFamily.ssrf,
  ReverifyFamily.fileUpload,
]);

// Access-control findings that need a second (or admin) identity to re-prove.
const ACCESS_CONTROL_SECONDARY_MARKERS = [
  "idor",
  "bola",
  "authorization matrix",
  "horizontal",
  "vertical",
  "privilege",
  "mass assignment",
  "mutating authorization",
];

// Body-ish parameter locations whose replay needs a captured request template.
const BODY_LOCATIONS = new Set([
  "form",
  "form_body",
  "body",
  "data",
  "json",
  "json_body",
  "body_json",
  "graphql_variable",
]);

/** Map stored finding metadata onto a stable reverify family. */
export function resolveFamily({
  detectorId = "",
  vulnType = "",
  category = "",
  proofType = "",
} = {}) {
  const detector = (detectorId || "").trim().toLowerCase().replaceAll(" ", "_");
  const exact = DETECTOR_ID_ALIASES.find(([alias]) => alias === detector);
  if (exact) return exact[1];
  const partial = DETECTOR_ID_ALIASES.find(
    ([alias]) => detector && detector.includes(alias),
  );
  if (partial) return partial[1];

  const haystack = [vulnType, proofType]
    .filter(Boolean)
    .map((part) => part.toLowerCase())
    .join(" ");
  for (const [markers, family] of VULN_TYPE_HINTS) {
    if (markers.some((marker) => haystack.includes(marker))) return family;
  }

  const cat = (category || "").toString().toLowerCase();
  if (cat.includes("a03") || cat.includes("supply chain"))
    return ReverifyFamily.supplyChain;
  if (cat.includes("a04") || cat.includes("cryptographic"))
    return ReverifyFamily.cryptoFailures;
  if (cat.includes("a01") || cat.includes("access control"))
    return ReverifyFamily.accessControl;
  if (cat.includes("a07") || cat.includes("authentication"))
    return ReverifyFamily.authentication;
  if (cat.includes("a10") || cat.includes("exception"))
    return ReverifyFamily.exceptionHandling;
  // Ambiguous injection without a clearer detector/vuln_type hint.
  return ReverifyFamily.unknown;
}

function authRequiresFullScan(vulnType, proofType) {
  const haystack = `${vulnType || ""} ${proofType || ""}`.toLowerCase();
  return AUTH_FULL_SCAN_MARKERS.some((marker) => haystack.includes(marker));
}

function accessControlNeedsSecondary(vulnType, proofType) {
  const haystack = `${vulnType || ""} ${proofType || ""}`.toLowerCase();
  // Conservative: an access_control finding with no subtype still needs a
  // second identity for the differential check.
  if (!haystack.trim()) return true;
  if (haystack.includes("forced browsing")) return false;
  return ACCESS_CONTROL_SECONDARY_MARKERS.some((marker) =>
    haystack.includes(marker),
  );
}

function hasReplayTemplate(target) {
  const template = target.request_template;
  if (!template || typeof template !== "object") return false;
  return (
    template.form_inputs != null ||
    template.json_template != null ||
    template.json_body != null ||
    template.form_body != null ||
    template.replay_exact === true
  );
}

/** Classify a VerificationTarget plus the owning finding's fields. */
export function classifyTarget(target, { vulnType, category } = {}) {
  const effectiveVulnType = vulnType || target.vuln_type;
  const family = resolveFamily({
    detectorId: target.detector_id,
    vulnType: effectiveVulnType,
    category,
    proofType: target.proof_type,
  });

  if (family === ReverifyFamily.supplyChain)
    return { family, classification: ReverifyClass.requiresFullScan };
  if (family === ReverifyFamily.unknown)
    return { family, classification: ReverifyClass.requiresFullScan };

  if (family === ReverifyFamily.authentication) {
    if (authRequiresFullScan(effectiveVulnType, target.proof_type))
      return { family, classification: ReverifyClass.requiresFullScan };
    const haystack =
      `${effectiveVulnType || ""} ${target.proof_type || ""}`.toLowerCase();
    const selfContained = AUTH_SELF_CONTAINED_MARKERS.some((marker) =>
      haystack.includes(marker),
    );
    if (!selfContained)
      return { family, classification: ReverifyClass.requiresFullScan };
  }

  if (
    family === ReverifyFamily.accessControl &&
    accessControlNeedsSecondary(effectiveVulnType, target.proof_type)
  )
    return { family, classification: ReverifyClass.requiresSecondaryIdentity };

  if (INJECTION_FAMILIES.has(family)) {
    const location = (target.parameter_location || "").toLowerCase();
    if (BODY_LOCATIONS.has(location) && !hasReplayTemplate(target))
      return {
        family,
        classification: ReverifyClass.insufficientReplayMetadata,
      };
  }

  return { family, classification: ReverifyClass.reverifiable };
}

/** Classify a persisted finding. Returns null classification when unreplayable. */
export function classifyFinding(finding) {
  const target = finding?.verification_target;
  if (!target)
    return {
      family: ReverifyFamily.unknown,
      classification: ReverifyClass.requiresFullScan,
    };
  return classifyTarget(target, {
    vulnType: finding.vuln_type,
    category: finding.category,
  });
}

// Reasons mirror the CannotReverify messages the backend raises, so the
// disabled-button tooltip reads the same as the 409 would.
const REASONS = {
  [ReverifyClass.requiresFullScan]:
    "This finding depends on crawl-wide context and cannot be re-verified in isolation. Run a full scan instead.",
  [ReverifyClass.insufficientReplayMetadata]:
    "This finding lacks the replay metadata needed for focused re-verification. Run a new scan to capture it.",
  [ReverifyClass.requiresSecondaryIdentity]:
    "Access-control re-verification needs a second or admin test account to prove the difference.",
};

const SUPPLY_CHAIN_REASON =
  "Component/CVE findings require a full rescan to re-fingerprint the target.";

/**
 * Decide how the Re-verify control should behave for one finding.
 * Returns { allowed, needsCredentials, reason, family, classification }.
 */
export function reverifyAffordance(finding) {
  if (!finding?.verification_target) {
    return {
      allowed: false,
      needsCredentials: false,
      reason: "This finding does not contain a replayable verification target.",
      family: ReverifyFamily.unknown,
      classification: ReverifyClass.requiresFullScan,
    };
  }
  const { family, classification } = classifyFinding(finding);
  if (classification === ReverifyClass.reverifiable)
    return {
      allowed: true,
      needsCredentials: false,
      reason: "",
      family,
      classification,
    };
  if (classification === ReverifyClass.requiresSecondaryIdentity)
    return {
      allowed: true,
      needsCredentials: true,
      reason: REASONS[classification],
      family,
      classification,
    };
  return {
    allowed: false,
    needsCredentials: false,
    reason:
      family === ReverifyFamily.supplyChain
        ? SUPPLY_CHAIN_REASON
        : REASONS[classification],
    family,
    classification,
  };
}
