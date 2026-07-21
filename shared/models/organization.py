from datetime import datetime, timezone

from beanie import Document, Indexed
from pydantic import Field

# Compliance floor for scan-data retention. A workspace may keep data longer,
# but never less than this many days.
MIN_RETENTION_DAYS = 30
DEFAULT_MEMBER_LIMIT = 10


class Organization(Document):
    """A workspace tenant: one owner, a team of members, and its own settings.

    Every scan, finding, and invite is scoped to an organization. Members see
    all scans in their org; roles gate what they may do (see ``UserRole``).
    """

    name: str
    owner_user_id: Indexed(str)
    # Seats include the owner, active members, and pending unexpired member
    # invitations. Invitations reserve a seat until accepted, cancelled, or
    # expired so concurrent issuers cannot oversubscribe a workspace.
    member_limit: int = Field(default=DEFAULT_MEMBER_LIMIT, ge=1)
    occupied_seats: int = Field(default=1, ge=1)
    # Scan data older than this is eligible for the retention purge. Enforced to
    # never drop below ``MIN_RETENTION_DAYS`` on write for compliance.
    retention_days: int = 90
    # A stored, ScanConfig-shaped convenience blob. The frontend fetches it to
    # pre-fill the create-scan form; the submitter sends a fully resolved config.
    # There is intentionally no server-side merge or fallback here — the
    # scanner's built-in ScanConfig defaults remain the safety net.
    default_scan_config: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Settings:
        name = "organizations"
        indexes = ["owner_user_id", [("created_at", -1)]]
