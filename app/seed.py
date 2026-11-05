"""Load synthetic food-processing and cold-chain devices plus a sample SBOM."""
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from .main import app

DEVICES = [
    {
        "device_id": "COLD-CTRL-001",
        "manufacturer": "Northstar Demo Systems",
        "model": "Refrigeration Controller RC-4",
        "firmware_version": "2.4.1",
        "support_until": "2028-12-31",
        "security": {
            "unique_identity": True,
            "authentication": "device_certificate",
            "default_credentials": False,
            "open_interfaces": ["https", "mqtts"],
            "encryption_in_transit": True,
            "encryption_at_rest": None,
            "update_mechanism": "manual",
            "logging_enabled": True,
            "secure_boot": None,
            "firmware_signed": None,
        },
    },
    {
        "device_id": "TEMP-SENSOR-002",
        "manufacturer": "Northstar Demo Systems",
        "model": "Cold-Room Temperature Sensor TS-2",
        "firmware_version": "1.8.0",
        "support_until": "2027-06-30",
        "security": {
            "unique_identity": None,
            "authentication": None,
            "default_credentials": None,
            "open_interfaces": ["mqtts"],
            "encryption_in_transit": True,
            "encryption_at_rest": None,
            "update_mechanism": "manual",
            "logging_enabled": None,
            "secure_boot": None,
            "firmware_signed": None,
        },
    },
    {
        "device_id": "EDGE-GW-003",
        "manufacturer": "Northstar Demo Systems",
        "model": "Industrial Edge Gateway EG-8",
        "firmware_version": "3.1.0",
        "support_until": "2030-06-30",
        "security": {
            "unique_identity": True,
            "authentication": "device_certificate",
            "default_credentials": False,
            "open_interfaces": ["https"],
            "encryption_in_transit": True,
            "encryption_at_rest": True,
            "update_mechanism": "automatic_signed",
            "logging_enabled": True,
            "secure_boot": True,
            "firmware_signed": True,
        },
    },
]


def _require_status(response, expected: int, operation: str) -> None:
    if response.status_code != expected:
        raise SystemExit(
            f"{operation} failed: expected HTTP {expected}, "
            f"received HTTP {response.status_code}: {response.text[:500]}"
        )


if __name__ == "__main__":
    api_key = os.environ.get("DEVICETRUST_API_KEY")
    if not api_key:
        raise SystemExit("Set DEVICETRUST_API_KEY before running the demo seeder.")

    headers = {"X-API-Key": api_key}
    sample_path = Path(__file__).parent.parent / "samples" / "cold_chain_gateway_sbom.json"
    sample = json.loads(sample_path.read_text(encoding="utf-8"))

    with TestClient(app) as client:
        existing = client.get("/devices", headers=headers)
        _require_status(existing, 200, "Device inventory preflight")
        existing_ids = {item["device_id"] for item in existing.json()}
        requested_ids = {item["device_id"] for item in DEVICES}
        conflicts = sorted(existing_ids & requested_ids)
        if conflicts:
            raise SystemExit(
                "Demo seed aborted before writing: these device IDs already exist: "
                + ", ".join(conflicts)
                + ". Use a fresh disposable database."
            )

        for device in DEVICES:
            response = client.post("/devices", json=device, headers=headers)
            _require_status(response, 201, f"Create {device['device_id']}")
            print("Created", device["device_id"])

        response = client.post(
            "/devices/EDGE-GW-003/sbom",
            json=sample,
            headers=headers,
        )
        _require_status(response, 200, "Import cold-chain gateway SBOM")
        print("SBOM import:", response.json())
