"""Load simulated devices and a sample SBOM using the local API."""
import json
import os
from pathlib import Path

from fastapi.testclient import TestClient

from .main import app

DEVICES = [
    {
        "device_id": "TEMP-001",
        "manufacturer": "Example IoT",
        "model": "Temperature Sensor V1",
        "firmware_version": "1.0.2",
        "support_until": "2028-12-31",
        "security": {
            "unique_identity": True,
            "authentication": "device_certificate",
            "default_credentials": False,
            "open_interfaces": ["mqtts"],
            "encryption_in_transit": True,
            "encryption_at_rest": False,
            "update_mechanism": "manual",
            "logging_enabled": None,
            "secure_boot": None,
            "firmware_signed": None,
        },
    },
    {
        "device_id": "CAM-002",
        "manufacturer": "Example IoT",
        "model": "Camera X",
        "firmware_version": "0.9.0",
        "support_until": "2023-01-01",
        "security": {
            "unique_identity": False,
            "authentication": "password_default",
            "default_credentials": True,
            "open_interfaces": ["telnet", "http"],
            "encryption_in_transit": False,
            "encryption_at_rest": False,
            "update_mechanism": "none",
            "logging_enabled": False,
            "secure_boot": False,
            "firmware_signed": False,
        },
    },
    {
        "device_id": "GATE-003",
        "manufacturer": "Example IoT",
        "model": "Gateway G3",
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
    headers = {"X-API-Key": os.environ["DEVICETRUST_API_KEY"]}
    sample = json.loads((Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_text())
    with TestClient(app) as client:
        for device in DEVICES:
            print(device["device_id"], client.post("/devices", json=device, headers=headers).status_code)
        print("sbom", client.post("/devices/CAM-002/sbom", json=sample, headers=headers).json())
