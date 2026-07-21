# SentryStrike — Workspace / Multi-Tenancy Feature Plan

**Status:** Awaiting sign-off
**Scope:** Backend only (no frontend work in this effort)
**Branch target:** TBD (feature branch off `scanner-upgrade` / `main`)

---

## 1. Goal

Turn SentryStrike from a flat single-user tool into an **invite-only, single-owner
workspace platform**. A business owner is onboarded by us (the vendor), runs an
organization, and invites their team (admins, analysts, developers, viewers) to
share one view of scans and findings across the sites they are authorized to test.

The whole platform is **invite-only at both tiers**:
- **Vendor → Owner:** we generate an owner invite via a management CLI (no UI).
- **Owner/Admin → Member:** invites are issued by email into their own org.

Registration is only reachable by consuming a valid, email-bound, role-pinned
invite token. There is no open sign-up.

---

## 2. Constraints (decided)

These are locked from the design discussion and drive every decision below:

1. **One user = one org = one role.** Because removing a member deletes their
   account, a user can never belong to more than one workspace. → **No
   `Membership` table.** `org_id` + `role` live directly on `User`.
2. **Single owner per org.** Admins assist but there is exactly one owner.
3. **Invite is email-bound + role-pinned.** The invited email is stored on the
   invite; registration rejects any other email for that token. Role is fixed at
   invite time; the registrant cannot choose it.
4. **Cancel = invalidate.** Owner/Admin cancels an invite → its state flips to
   `cancelled` and the token no longer accepts.
5. **No "leave workspace."** The only exit is owner/admin-initiated removal.
6. **Removal is a hard account delete.** Removing a member deletes their `User`
   doc and revokes all their sessions. Guards required (see §7).
7. **Greenfield.** Not deployed yet → **no data migration / backfill.**
8. **Owner onboarding is CLI-only.** No superadmin UI, no token-gated HTTP
   endpoint for now — access is shell access to the backend container.
9. **Email delivery is pluggable:** SMTP backend for production, console backend
   for dev.
10. **Scan creation = everyone except Viewer.**
11. **Record who started and who cancelled** each scan (`started_by` already
    exists via `owner_user_id`/`owner_email`; add `cancelled_by`).
12. **Workspace default scan config is a stored convenience blob only.** Frontend
    fetches it and pre-fills the create-scan form; the user submits a fully
    resolved config. **No backend merge, no server-side fallback** — the
    scanner's built-in `ScanConfig` defaults remain the safety net.

---

## 3. Roles

Single shared enum `UserRole`, matching how `ScanStatus` / `ReviewStatus` are
already modelled in the codebase.

| Role | Create/cancel scan | Triage findings | Manage members & invites | Workspace config (default config, retention) | Delete workspace |
|------|:--:|:--:|:--:|:--:|:--:|
| **owner**     | ✓ | ✓ | ✓ | ✓ | ✓ |
| **admin**     | ✓ | ✓ | ✓ | ✓ | — |
| **analyst**   | ✓ | ✓ | — | — | — |
| **developer** | ✓ (view + comment + mark-remediated) | limited | — | — | — |
| **viewer**    | — (read-only) | — | — | — | — |

> `analyst` replaces the earlier `security` label (avoids "security guard"
> connotation). All org members can **see** all scans/findings in their org — the
> shared-view goal. Role gates **actions**, not visibility.

---

## 4. Authorization model

The entire current authorization model is a single predicate:
**"does this scan's `owner_user_id` equal the caller?"** — implemented as
`ScanRepository.get_owned_by_id(...)` / `list(owner_user_id=...)` and called in
**9 route handlers**.

Workspaces replace that predicate with:
**"is the caller a member of this resource's org, and does their role permit
this action?"**

- Visibility scoping: `org_id` on the resource == `current_user.org_id`.
- Action gating: new `require_role(*allowed: UserRole)` FastAPI dependency.

This is the **security-critical** part of the whole effort: a gap here is a
cross-tenant data leak. It ships behind dedicated isolation tests before
anything else is built on top.

---

## 5. Data model changes (Phase 0)

### New — `shared/models/organization.py`
```python
class Organization(Document):
    name: str
    owner_user_id: Indexed(str)
    retention_days: int = 90            # floor enforced on write: max(30, value)
    default_scan_config: dict = {}      # ScanConfig-shaped blob; frontend reads + prefills
    created_at: datetime
    updated_at: datetime
```

### Extend — `shared/models/user.py`
```python
    org_id: Indexed(str)
    role: UserRole                      # owner | admin | analyst | developer | viewer
```

### New — `shared/models/invite.py`
```python
class InviteState(str, Enum):
    pending = "pending"
    accepted = "accepted"
    cancelled = "cancelled"
    expired = "expired"

class Invite(Document):
    email: Indexed(str)
    org_id: str | None                  # None for owner-invites (org not yet created)
    org_name: str | None                # carried on owner-invites -> Organization.name
    role: UserRole
    token_hash: Indexed(str, unique=True)   # only the SHA-256 hash is stored (mirrors UserSession)
    state: InviteState = InviteState.pending
    expires_at: datetime
    invited_by_user_id: str | None      # None when issued by the vendor CLI
    created_at: datetime
```

### Extend — `shared/models/scan.py`
```python
    org_id: Indexed(str)
    cancelled_by_user_id: str | None = None
    cancelled_by_email: str | None = None
```
(“Who started it” is already captured by `owner_user_id` / `owner_email`.)

### New — `shared/models/user.py` (or shared enums module)
```python
class UserRole(str, Enum):
    owner = "owner"
    admin = "admin"
    analyst = "analyst"
    developer = "developer"
    viewer = "viewer"
```

---

## 6. Authorization layer changes (Phase 1)

### `backend/app/api/dependencies.py`
- Add `require_role(*allowed: UserRole)` → returns a dependency that resolves
  `get_current_user`, checks `user.role in allowed`, else raises 403.

### `shared/database/repositories/scan_repository.py`
- `create(..., org_id=...)`
- `list(org_id=...)`  (replaces `owner_user_id` scoping — returns **all** org scans)
- `get_in_org(scan_id, org_id)` (replaces `get_owned_by_id`; returns None for
  other orgs, preserving the "can't distinguish 404 from forbidden" property)

### The 9 handlers that change

| File | Handler | Today | Becomes |
|------|---------|-------|---------|
| `routes/scan.py` | `create_scan` | sets `owner_user_id` | + set `org_id`; gate `require_role(owner, admin, analyst, developer)` |
| `routes/scan.py` | `list_scans` | `list(owner_user_id=…)` | `list(org_id=…)` |
| `routes/scan.py` | `get_scan_details` | `get_owned_by_id` | `get_in_org` |
| `routes/scan.py` | `get_scan_status` | `get_owned_by_id` | `get_in_org` |
| `routes/scan.py` | `cancel_scan` | `get_owned_by_id` | `get_in_org` + record `cancelled_by`; gate `require_role(owner, admin, analyst, developer)` |
| `routes/reports.py` | `get_report_data` | `get_owned_by_id` | `get_in_org` |
| `routes/reports.py` | `generate_pdf_report` | `get_owned_by_id` | `get_in_org` |
| `routes/analysis.py` | `list_vulnerabilities` | `get_owned_by_id` | `get_in_org` |
| `routes/analysis.py` | `get_vulnerability_details` | `get_owned_by_id` | `get_in_org` |

### Tests — `backend/tests/unit/test_org_isolation.py` (new)
- A user in org B receives **404** on every one of the 9 handlers for an org-A scan.
- A **viewer** receives **403** on `create_scan` and `cancel_scan`.
- Non-viewer roles succeed on create/cancel.
- Extend/replace existing `test_scan_ownership.py`.

**Phases 0 and 1 land together, behind the isolation tests, before any other
feature is built.**

---

## 7. Member management (Phase 3 — API only)

Endpoints under a new `routes/members.py` (or `workspace.py`), all org-scoped:

- `GET  /workspace/members` — list members of caller's org.  *(any member)*
- `POST /workspace/invites` — invite email + role into caller's org.  *(owner/admin)*
- `GET  /workspace/invites` — list pending invites.  *(owner/admin)*
- `POST /workspace/invites/{id}/cancel` — invalidate a pending invite.  *(owner/admin)*
- `DELETE /workspace/members/{user_id}` — remove member = hard delete.  *(owner/admin)*

### Member-removal guards (all must hold)
1. Caller is **owner or admin**.
2. Target is in the **same org** as caller.
3. Target is **not the owner** (owner cannot be removed via this path).
4. Target is **not the caller** (no self-delete; no accidental lockout).

### Removal effect (irreversible, explicitly confirmed action)
- Delete the target `User` document.
- Revoke/delete all the target's `UserSession` documents.
- (Phase 4) Reassign or orphan the target's finding comments/assignments.

---

## 8. Email + invites (Phase 2)

### Email service — `backend/app/core/email/`
- Pluggable interface `EmailBackend.send(to, subject, body_text, body_html)`.
- `SmtpEmailBackend` (production, config-driven).
- `ConsoleEmailBackend` (dev — writes the message + invite link to logs/stdout).
- Backend chosen by config (e.g. `EMAIL_BACKEND=smtp|console`).

### Invite token
- Random token (`secrets.token_urlsafe`), only the **SHA-256 hash** persisted —
  mirrors the existing `UserSession` token pattern.
- Single-use, expiring, rate-limited on issue.
- The raw token appears only in the emailed link.

### Owner onboarding — management CLI (`python -m app.cli`)
```bash
docker compose exec backend python -m app.cli invite-owner \
    --email owner@acme.com --org "Acme Corp"
```
- Creates a pending owner `Invite` (`org_id=None`, `org_name="Acme Corp"`,
  `role=owner`).
- Prints the invite link; emails it if a real SMTP backend is configured.
- No HTTP surface — access is container shell access, which only the vendor has.

### Registration (token-gated) — replaces `allow_registration`
- `POST /auth/register` now **requires a valid invite token**.
- Server validates: token exists, state `pending`, not expired, and the
  submitted email **matches** the invite's pinned email.
- On accept:
  - **Owner invite:** create `Organization` (name = `org_name`) → create `User`
    as `owner` with that `org_id` → set `Organization.owner_user_id`.
  - **Member invite:** create `User` with the invite's `org_id` + pinned `role`.
  - Flip invite `state` → `accepted`.
- The global `settings.allow_registration` flag is retired in favour of token
  validation.

---

## 9. Workspace settings (Phase 3)

### Default scan config (stored blob, no merge)
- `GET  /workspace/default-config` — any member (frontend prefills create-scan form).
- `PUT  /workspace/default-config` — owner/admin only.
- Stored as a `ScanConfig`-shaped dict on `Organization.default_scan_config`.
- **No backend merge / fallback.** Frontend reads it, prefills, lets the user
  edit, and submits a fully resolved config. Scanner built-in defaults remain
  the safety net for any omitted fields.

### Retention
- `GET  /workspace/retention` — any member.
- `PUT  /workspace/retention` — owner/admin only; floor enforced `max(30, value)`.

---

## 10. Finding collaboration (Phase 4)

Makes it a shared *workspace* rather than shared read-only.
- Extend `Vulnerability` with `assignee_user_id`, comments, and a
  remediation-status field (alongside existing `ReviewStatus`).
- Developer can be assigned a finding, comment, and mark
  "fixed — needs re-verification"; analyst/admin confirms.
- Endpoints for assign / comment / update remediation state, org-scoped and
  role-gated.

---

## 11. Retention purge + audit log (Phase 5)

- **Retention purge:** background job (fits the existing worker pattern) deleting
  scan data older than each org's `retention_days`. Runs periodically; logs what
  it purged.
- **Audit log:** append-only record of invites issued/cancelled, members removed,
  role changes, and scan create/cancel/delete actions — needed the moment
  "compliance" is in scope.

---

## 12. Phase summary & sequencing

| Phase | Deliverable | Depends on |
|-------|-------------|-----------|
| **0** | Models: `Organization`, `Invite`, `UserRole`; extend `User` + `Scan`. No migration. | — |
| **1** | Authorization core: `require_role`, org-scoped `ScanRepository`, rewrite 9 handlers, `test_org_isolation.py`. | 0 |
| **2** | Email service (SMTP + console), invite tokens, owner-invite CLI, token-gated registration. | 0, 1 |
| **3** | Member management API + workspace settings (default config, retention). | 2 |
| **4** | Finding collaboration (assign, comment, remediation status). | 1 |
| **5** | Retention purge job + audit log. | 3 |

**Rules:**
- Phases **0 + 1 are a package** and land together behind isolation tests — this
  is the multi-tenancy core and the only part that can leak data across tenants.
- Phases 2–5 are then largely independent; recommended order 2 → 3 → 4 → 5, but
  4 (collaboration, the actual value prop) may be pulled ahead of 5 (compliance).

---

## 13. Open items / to confirm

- Role labels: `owner | admin | analyst | developer | viewer` — confirm `analyst`.
- Default `retention_days` value (plan assumes 90, floor 30).
- Invite token TTL (e.g. 7 days) — to set in Phase 2.
- Email config keys / provider specifics — to nail down at Phase 2.
