import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlunparse

from app.core.detectors.attack_surface import PreparedAttackRequest


@dataclass(frozen=True)
class _AuthMaterial:
    label: str
    cookies: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def configured(self) -> bool:
        return bool(self.cookies or self.headers)


@dataclass(frozen=True)
class _MatrixTarget:
    request: PreparedAttackRequest
    source: str
    parameter: str | None = None
    parameter_location: str | None = None
    has_object_reference: bool = False
    admin_like: bool = False


@dataclass(frozen=True)
class _ResponseProfile:
    status_code: int
    content_type: str
    success: bool
    is_json: bool
    json_shape: frozenset[str] = field(default_factory=frozenset)
    identifiers: frozenset[str] = field(default_factory=frozenset)
    sensitive_fields: frozenset[str] = field(default_factory=frozenset)
    # Narrow subset of sensitive_fields that carry genuinely secret material
    # (credentials, tokens, keys, crypto seeds). Unlike broad PII field names
    # (email/username/role), a secret field in an anonymous response is an
    # unambiguous leak regardless of whether the endpoint is otherwise public.
    secret_fields: frozenset[str] = field(default_factory=frozenset)
    item_count: int = 0
    body_length: int = 0

# State-changing HTTP methods whose authorization is tested non-destructively
# (synthetic non-existent id + status differential), never via the read-oriented
# IDOR baseline. POST is excluded: it targets a collection (no owner id to
# destroy) and is already exercised by the auth matrix / create paths.
_MUTATING_AUTHZ_METHODS = frozenset({"PUT", "PATCH", "DELETE"})

# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------
_NUMERIC_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
# Long hex identifiers (Mongo ObjectId = 24, SHA-1 = 40, etc.).
_LONG_HEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.IGNORECASE)
# Opaque base64url/token identifiers: long, mixed, and containing a digit so
# ordinary path words ("changelog", "dashboard") are not treated as ids.
_OPAQUE_ID_SEGMENT_RE = re.compile(r"^(?=.*\d)[A-Za-z0-9_\-]{12,}$")


def _looks_like_path_id_segment(segment: str) -> bool:
    """True when a REST path segment looks like an object id.

    Covers pure integers, UUIDs, long hex strings (ObjectId/SHA), and opaque
    base64url-style tokens that mix letters and digits. Purely alphabetic
    segments are never treated as ids so route words are not fuzzed.
    """
    if not segment:
        return False
    if _NUMERIC_RE.match(segment) or _UUID_RE.match(segment):
        return True
    if _LONG_HEX_RE.match(segment):
        return True
    return bool(_OPAQUE_ID_SEGMENT_RE.match(segment))


# ---------------------------------------------------------------------------
# IDOR value classification
#
# A genuine object-reference ID is one of:
#   1. A pure integer  (e.g. 42, 1000)
#   2. A UUID          (e.g. 550e8400-e29b-41d4-a716-446655440000)
#   3. A short opaque token that contains at least one digit AND is not a
#      common English word / semantic slug.  This prevents "changelog",
#      "about", "home", "admin" etc. from being treated as IDs.
#
# The old IDOR_VALUE_PATTERN matched any [a-zA-Z0-9_-]{1,32}, which was far
# too broad and was the primary root cause of semantic-slug false positives.
# ---------------------------------------------------------------------------

# Pattern 3: opaque token — must have digits mixed in (e.g. "abc123", "user_42")
# Pure alpha strings like "changelog" do NOT match.
_OPAQUE_TOKEN_RE = re.compile(r"^(?=.*\d)[a-zA-Z0-9_\-]{2,32}$")

# Well-known semantic slug words that should never be treated as IDs even if
# they happen to pass a regex.  This list is intentionally generic — it covers
# routing / navigation tokens that appear across many frameworks and apps.
_SEMANTIC_SLUGS: frozenset[str] = frozenset({
    # Navigation / document-type words
    "home", "about", "index", "main", "default", "start", "welcome",
    "help", "faq", "docs", "documentation", "manual", "guide", "tutorial",
    "changelog", "changes", "history", "readme", "license", "terms", "privacy",
    "contact", "support", "feedback", "blog", "news", "events", "updates",
    # Status / action words
    "new", "edit", "create", "delete", "update", "view", "show", "list",
    "search", "filter", "sort", "export", "import", "upload", "download",
    "login", "logout", "register", "signup", "signin", "signout", "reset",
    # Common CMS / framework page names
    "page", "post", "article", "category", "tag", "section", "chapter",
    "dashboard", "overview", "summary", "report", "analytics", "stats",
    # Misc tokens that appear as param values in real apps
    "all", "any", "none", "latest", "recent", "popular", "featured",
    "active", "inactive", "enabled", "disabled", "pending", "done", "open",
    "public", "private", "draft", "published", "archived",
})


def _is_valid_id_value(val: str) -> bool:
    """
    Return True only when *val* looks like a genuine object-reference
    identifier — not a semantic slug or human-readable keyword.

    Accepts:
      - Pure integers: "1", "42", "10000"
      - UUIDs: "550e8400-e29b-41d4-a716-446655440000"
      - Opaque tokens that contain at least one digit mixed with letters
        (e.g. "abc123", "user_42", "t9k3m") and are NOT in the semantic
        slug blocklist.

    Rejects:
      - Empty strings
      - Boolean/null literals ("true", "false", "null", …)
      - Pure alphabetic strings of any length ("changelog", "home", …)
      - Values in the semantic slug blocklist
    """
    if not val:
        return False
    lower = val.lower()
    # Hard blocklist first — quick exit
    if lower in _NON_ID_VALUES or lower in _SEMANTIC_SLUGS:
        return False
    # Pure integers are always valid IDs
    if _NUMERIC_RE.match(val):
        return True
    # UUIDs are always valid IDs
    if _UUID_RE.match(val):
        return True
    # Opaque token: must contain at least one digit
    if _OPAQUE_TOKEN_RE.match(val):
        return True
    # Everything else (pure alpha strings, etc.) is rejected
    return False


# Tokens that signal "this looks like a login page body"
_LOGIN_SIGNALS = frozenset(["login", "sign in", "signin"])
_LOGIN_CREDENTIAL_SIGNALS = frozenset(["password", "username", "email"])

# Signals inside a soft-200 body that indicate "resource not found"
_SOFT_NOTFOUND_SIGNALS: tuple[str, ...] = (
    "not found", "no such", "does not exist", "invalid id",
    "no record", "resource not found", "page not found",
    "404", "error", "invalid", "unknown",
)

# Non-ID literal values that should never be treated as object references
_NON_ID_VALUES: frozenset[str] = frozenset({
    "on", "off", "true", "false", "yes", "no", "null", "none", "undefined",
})


def _looks_like_login_page(body: str) -> bool:
    """Return True when the response body appears to be a login/auth wall.

    A login wall is an HTML document. A structured JSON/data payload is an API
    response and is NEVER a login page — even when it contains field names such
    as ``email``, ``username`` or ``lastLoginIp`` (whose substring "login"
    otherwise trips the word heuristic). Guarding on JSON first prevents a data
    collection (e.g. a user listing) from being misread as a login wall, which
    would suppress genuine authorization findings against it.
    """
    stripped = body.lstrip()
    if stripped[:1] in ("{", "["):
        try:
            json.loads(stripped)
            return False
        except ValueError:
            pass
    b = body.lower()
    has_login_word = any(s in b for s in _LOGIN_SIGNALS)
    has_credential_field = any(s in b for s in _LOGIN_CREDENTIAL_SIGNALS)
    return has_login_word and has_credential_field


def _looks_like_error_page(body: str) -> bool:
    """
    Return True when the body looks like a generic error / not-found page
    rather than a real resource.  Used to filter soft-200 responses.
    """
    b = body.lower()
    return any(s in b for s in _SOFT_NOTFOUND_SIGNALS)


def _mutate_id(val: str) -> list[str]:
    """
    Return a list of candidate mutated IDs for the given value.

    Covers numeric, UUID, and opaque/hash-style identifiers so that the
    detector doesn't silently skip non-integer IDs.
    """
    candidates: list[str] = []

    # Numeric: try +1 and -1 (guard against negative IDs)
    if _NUMERIC_RE.match(val):
        n = int(val)
        candidates.append(str(n + 1))
        if n > 1:
            candidates.append(str(n - 1))
        return candidates

    # UUID v4: flip the last hex digit to produce a plausibly different UUID
    if _UUID_RE.match(val):
        parts = val.split("-")
        last = parts[-1]
        flipped = last[:-1] + ("0" if last[-1] != "0" else "1")
        candidates.append("-".join(parts[:-1] + [flipped]))
        return candidates

    # Opaque short token: swap last digit(s) to produce a different-looking ID
    # E.g. "user42" → "user43"; "abc123" → "abc124"
    m = re.search(r"(\d+)$", val)
    if m:
        prefix = val[: m.start()]
        n = int(m.group(1))
        candidates.append(prefix + str(n + 1))
        if n > 1:
            candidates.append(prefix + str(n - 1))
        return candidates

    # Fallback for fully opaque tokens without trailing digits:
    # try appending "1" / "2" to generate distinct candidates
    candidates.append(val + "1")
    candidates.append(val + "2")
    return candidates


def _strip_query(url: str) -> str:
    """Return the URL with the query-string removed."""
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, "", p.fragment))


# ---------------------------------------------------------------------------
# Burp-Suite-inspired differential analysis helpers
#
# Burp Suite's IDOR detection (Collaborator + active scanning) works by:
#   1. Making a baseline request with the authenticated session.
#   2. Making the same request *without* credentials → if it already returns
#      200, the resource is public and IDOR is not applicable.
#   3. Mutating the ID and requesting with credentials.
#   4. Comparing the mutated response against:
#      a. The unauthenticated mutated response  — if unauth also gets 200,
#         the mutated resource is public, not an access-control bypass.
#      b. The authenticated own-resource response — the content should be
#         *meaningfully different* (a different object was returned) but not
#         so different that it looks like a generic error page.
#   5. Only flagging when the authenticated mutated response is clearly a
#      real resource that differs from the authenticated session's own data.
#
# We implement the same multi-signal differential below.
# ---------------------------------------------------------------------------

def _json_structural_analysis(a: str, b: str) -> tuple[float, float] | None:
    import json
    try:
        ja = json.loads(a)
        jb = json.loads(b)
    except Exception:
        return None
        
    def flatten(obj: object, prefix: str = "") -> dict[str, object]:
        items: dict[str, object] = {}
        if isinstance(obj, dict):
            for k, v in obj.items():
                items.update(flatten(v, f"{prefix}.{k}"))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                items.update(flatten(v, f"{prefix}[{i}]"))
        else:
            items[prefix] = obj
        return items
        
    fa = flatten(ja)
    fb = flatten(jb)
    if not fa and not fb:
        return 1.0, 1.0
        
    keys_union = set(fa.keys()) | set(fb.keys())
    if not keys_union:
        return 1.0, 1.0
        
    key_matches = sum(1 for k in keys_union if k in fa and k in fb)
    val_matches = sum(1 for k in keys_union if fa.get(k) == fb.get(k))
    return key_matches / len(keys_union), val_matches / len(keys_union)

# Response fields that reference the owner or authorization scope of a record,
# rather than the record's own primary key. An unchanged owner/container scope
# means the mutation stayed inside the same authorization boundary. Bare ``id``
# is excluded because it normally names the record itself.
_OWNER_REFERENCE_KEYS: frozenset[str] = frozenset(
    {
        "userid", "user_id", "uid",
        "owner", "ownerid", "owner_id",
        "accountid", "account_id",
        "customerid", "customer_id",
        "createdby", "created_by",
        "authorid", "author_id",
        "tenantid", "tenant_id",
        "organizationid", "organization_id", "orgid", "org_id",
        "workspaceid", "workspace_id",
        "projectid", "project_id",
        "teamid", "team_id", "groupid", "group_id",
        "parentid", "parent_id",
        "basketid", "basket_id", "cartid", "cart_id",
        "orderid", "order_id",
    }
)
_NORMALIZED_OWNER_REFERENCE_KEYS = frozenset(
    re.sub(r"[^a-z0-9]", "", key.lower()) for key in _OWNER_REFERENCE_KEYS
)


def _owner_references(body: str) -> dict[str, object]:
    """Extract owner-reference field values from a JSON body.

    Keys are matched case-insensitively on the LAST path segment of a flattened
    JSON body, so ``data.UserId`` and ``UserId`` both count. Returns a mapping of
    ``normalized_owner_key -> value`` for non-empty values only. Framework- and
    target-agnostic: no specific field name or path is assumed.
    """
    import json

    try:
        parsed = json.loads(body)
    except Exception:
        return {}

    owners: dict[str, object] = {}

    def walk(obj: object) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                norm = re.sub(r"[^a-z0-9]", "", str(key).lower())
                if (
                    norm in _NORMALIZED_OWNER_REFERENCE_KEYS
                    and isinstance(value, (str, int))
                    and str(value).strip()
                ):
                    owners.setdefault(norm, str(value).strip())
                walk(value)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)

    walk(parsed)
    return owners


def _is_same_owner(own_body: str, mutated_body: str) -> bool:
    """True when both bodies reference the same owner or authorization scope.

    Requires at least one owner-reference key present in BOTH bodies with an
    equal value. When they match, the "victim" object is actually owned by the
    reading identity (e.g. a scanner-provisioned second identity reading its own
    resource), so a successful read is not a cross-user authorization bypass.
    """
    own_owners = _owner_references(own_body)
    mutated_owners = _owner_references(mutated_body)
    shared = set(own_owners) & set(mutated_owners)
    if not shared:
        return False
    return all(own_owners[key] == mutated_owners[key] for key in shared)


def _differential_idor_verdict(
    *,
    own_body: str,
    mutated_authed_body: str,
    mutated_unauthed_body: str | None,
) -> tuple[bool, float, str]:
    """
    Apply Burp-Suite-style differential analysis to decide whether a response
    to a mutated ID represents a genuine IDOR or a false positive.
    """
    if _looks_like_error_page(mutated_authed_body):
        return False, 0.0, "mutated response resembles an error/not-found page"

    # Same-owner guard: if the own and mutated objects reference the same owner
    # (UserId/owner/account/…), the reading identity already owns the mutated
    # record, so a 200 is a self-read, not a cross-user IDOR. This kills the
    # false positive where two resources provisioned under the SAME identity are
    # mutated between one another.
    if _is_same_owner(own_body, mutated_authed_body):
        return False, 0.0, "mutated object shares the same owner reference as the own object (same-user read)"

    # Semantic JSON Differential
    json_sims = _json_structural_analysis(own_body, mutated_authed_body)
    if json_sims is not None:
        key_sim, val_sim = json_sims
        if key_sim < 0.50:
            return False, key_sim, "mutated JSON structure differs too much (likely an error object)"
        if val_sim == 1.0:
            return False, 1.0, "mutated JSON has identical values (generic template or same object)"
            
        if mutated_unauthed_body is not None:
            unauth_json_sims = _json_structural_analysis(mutated_authed_body, mutated_unauthed_body)
            if unauth_json_sims is not None:
                _, unauth_val_sim = unauth_json_sims
                if unauth_val_sim > 0.99:
                    return False, 0.0, "mutated JSON is identical to unauthed JSON (publicly accessible)"
                    
        return True, val_sim, "JSON differential analysis passed"

    # Fallback to Text-Based Differential
    if mutated_unauthed_body is not None:
        unauth_sim = _body_similarity(mutated_authed_body, mutated_unauthed_body)
        if unauth_sim > 0.85:
            return False, 0.0, f"mutated resource is publicly accessible (authed vs unauthed similarity: {unauth_sim:.0%})"

    own_sim = _body_similarity(own_body, mutated_authed_body)
    if own_sim > 0.95:
        return False, own_sim, "mutated response is virtually identical to own resource (generic template)"
    if own_sim < 0.10:
        return False, own_sim, "mutated response is too dissimilar from own resource — likely an error page"

    return True, own_sim, "differential analysis passed"


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _body_similarity(a: str, b: str) -> float:
    """
    Rough Jaccard similarity between two response bodies using character
    4-grams.  Returns a float in [0, 1].  1 = identical content.

    Used in two places:
      - "too similar" guard: if own and mutated responses are >95% similar
        they are probably the same generic template.
      - "too different" guard: if own and mutated are <10% similar the
        mutated response is probably a generic error page.
      - Public-resource guard: if authed and unauthed mutated responses are
        >85% similar, the mutated resource is publicly accessible.
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    def ngrams(text: str, n: int = 4) -> set[str]:
        t = text.lower()
        return {t[i : i + n] for i in range(len(t) - n + 1)}

    sa, sb = ngrams(a), ngrams(b)
    if not sa and not sb:
        return 1.0
    intersection = len(sa & sb)
    union = len(sa | sb)
    return intersection / union if union else 0.0
