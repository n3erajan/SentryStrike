from __future__ import annotations

from datetime import datetime, timezone

from beanie import PydanticObjectId

from shared.models.application import Application


class ApplicationRepository:
    """Persistence layer for Application documents.

    All query logic strictly enforces org_id to prevent cross-workspace access and IDOR.
    """

    async def create(
        self,
        name: str,
        target_url: str,
        *,
        org_id: str,
        default_scan_config: dict | None = None,
    ) -> Application:
        app = Application(
            name=name,
            target_url=target_url,
            org_id=org_id,
            default_scan_config=default_scan_config or {},
        )
        await app.insert()
        return app

    async def get_in_org(self, app_id: str, org_id: str) -> Application | None:
        """Fetch an application only if it belongs to the given organization."""
        try:
            oid = PydanticObjectId(app_id)
        except Exception:
            return None
        return await Application.find_one(Application.id == oid, Application.org_id == org_id)

    async def count_in_org(self, org_id: str) -> int:
        """Total number of applications for this org."""
        return await Application.find(Application.org_id == org_id).count()

    async def list_in_org(self, org_id: str, skip: int = 0, limit: int = 20) -> list[Application]:
        """List applications for an organization, newest first."""
        return (
            await Application.find(Application.org_id == org_id)
            .sort(-Application.created_at)
            .skip(skip)
            .limit(limit)
            .to_list()
        )

    async def update_in_org(
        self,
        app_id: str,
        org_id: str,
        *,
        name: str | None = None,
        target_url: str | None = None,
        default_scan_config: dict | None = None,
    ) -> Application | None:
        """Update an application only if it belongs to the given organization."""
        app = await self.get_in_org(app_id, org_id)
        if app is None:
            return None

        if name is not None:
            app.name = name
        if target_url is not None:
            app.target_url = target_url
        if default_scan_config is not None:
            app.default_scan_config = default_scan_config

        app.updated_at = datetime.now(timezone.utc)
        await app.save()
        return app

    async def delete_in_org(self, app_id: str, org_id: str) -> bool:
        """Delete an application only if it belongs to the given organization."""
        app = await self.get_in_org(app_id, org_id)
        if app is None:
            return False
        await app.delete()
        return True
