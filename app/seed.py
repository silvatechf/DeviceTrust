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
            "authentication": "unknown",
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

if __name__ == "__main__":
    api_key = os.environ.get("DEVICETRUST_API_KEY")
    if not api_key:
        raise SystemExit("Set DEVICETRUST_API_KEY before running the demo seeder.")

    headers = {"X-API-Key": api_key}
    sample_path = Path(__file__).parent.parent / "samples" / "cold_chain_gateway_sbom.json"
    sample = json.loads(sample_path.read_text(encoding="utf-8"))

    with TestClient(app) as client:
        for device in DEVICES:
            response = client.post("/devices", json=device, headers=headers)
            print(device["device_id"], response.status_code, response.text[:300])
        response = client.post(
            "/devices/EDGE-GW-003/sbom",
            json=sample,
            headers=headers,
        )
        print("SBOM import", response.status_code, response.text[:500])
