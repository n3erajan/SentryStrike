"""Broken-access-control detector.

This package is the split form of the former single-module
``access_control.py`` monolith. The public surface is unchanged: importers
still ``from app.core.detectors.access_control import AccessControlDetector``
(and the module-level helpers/constants re-exported below), and the class name,
attributes, and ``detect()`` signature are identical.

The detector logic is composed from focused mixins, each owning one concern:

* ``RuntimeMixin`` — the ``detect()`` orchestration entry point, per-scan auth
  material construction, and the small structural classification helpers.
* ``ForcedBrowsingMixin`` — unauthenticated sensitive-path exposure.
* ``IdorMixin`` — horizontal/vertical IDOR via id-mutation differential.
* ``AuthorizationMatrixMixin`` — the unauth/low/second/privileged response
  matrix and the response-profile comparison helpers it relies on.
* ``MutatingAuthorizationMixin`` — non-destructive authz checks on
  state-changing methods (synthetic non-existent id + status differential).
* ``MassAssignmentMixin`` — privilege-field injection on create/update bodies.
* ``TargetingMixin`` — attack-surface/target construction, request building,
  header sanitization, and id/collection extraction shared by every check.

``common.py`` holds the module-level dataclasses, constants, regexes, and pure
functions (no ``self``) shared across the mixins.
"""

import logging

from app.core.detectors.base_detector import BaseDetector

from app.core.detectors.access_control.common import (
    _AuthMaterial,
    _MatrixTarget,
    _ResponseProfile,
    _MUTATING_AUTHZ_METHODS,
    _NUMERIC_RE,
    _UUID_RE,
    _LONG_HEX_RE,
    _OPAQUE_ID_SEGMENT_RE,
    _OPAQUE_TOKEN_RE,
    _SEMANTIC_SLUGS,
    _NON_ID_VALUES,
    _LOGIN_SIGNALS,
    _LOGIN_CREDENTIAL_SIGNALS,
    _SOFT_NOTFOUND_SIGNALS,
    _OWNER_REFERENCE_KEYS,
    _looks_like_path_id_segment,
    _is_valid_id_value,
    _looks_like_login_page,
    _looks_like_error_page,
    _mutate_id,
    _strip_query,
    _json_structural_analysis,
    _owner_references,
    _is_same_owner,
    _differential_idor_verdict,
    _body_similarity,
)
from app.core.detectors.access_control.forced_browsing import ForcedBrowsingMixin
from app.core.detectors.access_control.idor import IdorMixin
from app.core.detectors.access_control.authorization_matrix import AuthorizationMatrixMixin
from app.core.detectors.access_control.mutating_authorization import MutatingAuthorizationMixin
from app.core.detectors.access_control.mass_assignment import MassAssignmentMixin
from app.core.detectors.access_control.targeting import TargetingMixin
from app.core.detectors.access_control.runtime import RuntimeMixin

logger = logging.getLogger("app.core.detectors.access_control")


class AccessControlDetector(
    RuntimeMixin,
    ForcedBrowsingMixin,
    IdorMixin,
    AuthorizationMatrixMixin,
    MutatingAuthorizationMixin,
    MassAssignmentMixin,
    TargetingMixin,
    BaseDetector,
):
    name = "access_control"

    # Tokens that name GATED FUNCTIONALITY — resources that are supposed to
    # require authorization, so reaching them unauthenticated (with a working
    # authenticated baseline) is a genuine A01 Broken Access Control finding and
    # the auth-vs-unauth differential IS the proof.
    #
    # Accidental FILE / VCS / dotfile exposure (``.git``, ``.env``,
    # ``.htaccess`` …) is deliberately NOT here: such a file should never be
    # web-served at all, there is no meaningful "authorized version" to diff
    # against, and it is A02 Security Misconfiguration — owned by the
    # ``sensitive_paths`` detector, which probes those exact paths and confirms
    # by content. Keeping them here made forced browsing do sensitive_paths'
    # job and emit the same exposure twice under two different OWASP categories.
    sensitive_path_tokens: frozenset[str] = frozenset({
        "admin", "manage", "management", "manager",
        "internal", "debug", "private", "config", "configuration", "settings",
        "backup", "console", "panel", "restricted", "staff",
        "db", "database", "phpmyadmin", "adminer",
        "actuator",                          # Spring Boot actuator endpoints
        "api/internal", "api/admin",         # Common API prefixes
        "graphql", "graphiql",               # GraphQL explorers left open
        "swagger", "swagger-ui", "api-docs", # API docs sometimes left public
        "wp-admin", "wp-login",              # WordPress
        "cpanel", "whm",                     # Hosting panels
    })

    idor_param_tokens: frozenset[str] = frozenset({
        "id", "user", "user_id", "userid",
        "account", "account_id", "accountid",
        "order", "order_id", "orderid",
        "record", "record_id", "recordid",
        "profile", "uid", "uuid",
        "customer", "customer_id", "customerid",
        "invoice", "invoice_id", "invoiceid",
        "ticket", "ticket_id", "ticketid",
        "document", "doc", "doc_id", "docid",
        "file", "file_id", "fileid",
        "message_id", "messageid", "msg_id", "msgid",
        "ref", "reference",
    })

    # Max parallel HTTP requests to avoid hammering the target
    _CONCURRENCY = 5


__all__ = [
    "AccessControlDetector",
    "_AuthMaterial",
    "_MatrixTarget",
    "_ResponseProfile",
    "_MUTATING_AUTHZ_METHODS",
    "_NUMERIC_RE",
    "_UUID_RE",
    "_LONG_HEX_RE",
    "_OPAQUE_ID_SEGMENT_RE",
    "_OPAQUE_TOKEN_RE",
    "_SEMANTIC_SLUGS",
    "_NON_ID_VALUES",
    "_LOGIN_SIGNALS",
    "_LOGIN_CREDENTIAL_SIGNALS",
    "_SOFT_NOTFOUND_SIGNALS",
    "_OWNER_REFERENCE_KEYS",
    "_looks_like_path_id_segment",
    "_is_valid_id_value",
    "_looks_like_login_page",
    "_looks_like_error_page",
    "_mutate_id",
    "_strip_query",
    "_json_structural_analysis",
    "_owner_references",
    "_is_same_owner",
    "_differential_idor_verdict",
    "_body_similarity",
]
