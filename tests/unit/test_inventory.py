"""Tests for inventory queries and deterministic exports."""

import csv
import json
from datetime import UTC, datetime
from ipaddress import IPv4Address
from pathlib import Path
from uuid import uuid4

from netsentinel.application.inventory import InventoryService
from netsentinel.domain.models import DeviceAsset


class FakeInventoryRepository:
    def __init__(self, assets: tuple[DeviceAsset, ...]) -> None:
        self.assets = assets
        self.searches: list[str | None] = []

    def list_assets(self, search: str | None = None) -> tuple[DeviceAsset, ...]:
        self.searches.append(search)
        if not search:
            return self.assets
        return tuple(
            asset
            for asset in self.assets
            if search.lower() in str(asset.address).lower()
            or search.lower() in (asset.hostname or "").lower()
            or search.lower() in (asset.mac_address or "").lower()
        )


def _asset(address: str, hostname: str) -> DeviceAsset:
    timestamp = datetime(2026, 1, 1, 12, tzinfo=UTC)
    return DeviceAsset(
        asset_id=uuid4(),
        address=IPv4Address(address),
        first_seen=timestamp,
        last_seen=timestamp,
        mac_address="AA:BB:CC:DD:EE:FF",
        hostname=hostname,
        vendor="Example Vendor",
        response_time_ms=2.5,
        status="active",
    )


def test_inventory_normalizes_search_and_returns_assets() -> None:
    repository = FakeInventoryRepository((_asset("192.168.1.10", "lab-host"),))
    service = InventoryService(repository)

    assets = service.list_assets("  LAB-HOST  ")

    assert len(assets) == 1
    assert repository.searches == ["LAB-HOST"]


def test_inventory_exports_csv(tmp_path: Path) -> None:
    service = InventoryService(
        FakeInventoryRepository((_asset("192.168.1.10", "lab-host"),))
    )
    path = tmp_path / "inventory.csv"

    count = service.export_csv(path)

    assert count == 1
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert rows[0]["ip_address"] == "192.168.1.10"
    assert rows[0]["hostname"] == "lab-host"


def test_inventory_exports_versioned_json(tmp_path: Path) -> None:
    service = InventoryService(
        FakeInventoryRepository((_asset("192.168.1.10", "lab-host"),))
    )
    path = tmp_path / "inventory.json"

    count = service.export_json(path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert count == 1
    assert payload["schema_version"] == 1
    assert payload["assets"][0]["ip_address"] == "192.168.1.10"
    assert payload["generated_at"]
