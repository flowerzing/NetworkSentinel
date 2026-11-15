"""Device inventory queries and export orchestration."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from netsentinel.domain.models import DeviceAsset
from netsentinel.reporting.inventory import write_assets_csv, write_assets_json


class InventoryRepository(Protocol):
    """Persistence contract required by the inventory use case."""

    def list_assets(self, search: str | None = None) -> tuple[DeviceAsset, ...]:
        """Return assets matching an optional user-provided search string."""


class InventoryService:
    """Query persisted assets and delegate safe, deterministic exports."""

    def __init__(self, repository: InventoryRepository) -> None:
        self._repository = repository

    def list_assets(self, search: str | None = None) -> tuple[DeviceAsset, ...]:
        """Return inventory records filtered by address, hostname, or MAC."""
        normalized = search.strip() if search is not None else None
        return self._repository.list_assets(normalized or None)

    def export_csv(self, path: Path, search: str | None = None) -> int:
        """Write the current filtered inventory as CSV and return its row count."""
        assets = self.list_assets(search)
        write_assets_csv(path, assets)
        return len(assets)

    def export_json(self, path: Path, search: str | None = None) -> int:
        """Write the current filtered inventory as JSON and return its row count."""
        assets = self.list_assets(search)
        write_assets_json(path, assets)
        return len(assets)
