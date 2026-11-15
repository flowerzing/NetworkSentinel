"""CSV and JSON serialization for persisted device inventory records."""

from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netsentinel.domain.models import DeviceAsset

_FIELDS = (
    "ip_address",
    "mac_address",
    "hostname",
    "vendor",
    "response_time_ms",
    "status",
    "first_seen",
    "last_seen",
)


def write_assets_csv(path: Path, assets: Iterable[DeviceAsset]) -> None:
    """Write one deterministic CSV row per inventory asset."""
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=_FIELDS)
        writer.writeheader()
        writer.writerows(_asset_record(asset) for asset in assets)


def write_assets_json(path: Path, assets: Iterable[DeviceAsset]) -> None:
    """Write a versioned JSON envelope containing inventory assets."""
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(UTC).isoformat(),
        "assets": [_asset_record(asset) for asset in assets],
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def _asset_record(asset: DeviceAsset) -> dict[str, Any]:
    return {
        "ip_address": str(asset.address),
        "mac_address": asset.mac_address or "",
        "hostname": asset.hostname or "",
        "vendor": asset.vendor or "",
        "response_time_ms": asset.response_time_ms,
        "status": asset.status,
        "first_seen": asset.first_seen.astimezone(UTC).isoformat(),
        "last_seen": asset.last_seen.astimezone(UTC).isoformat(),
    }
