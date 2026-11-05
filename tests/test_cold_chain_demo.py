import json
from pathlib import Path

from app.sbom import parse_cyclonedx, scan_local
from app.schemas import DeviceIn
from app.seed import COLD_CHAIN_DEVICES, DEVICES


def test_cold_chain_demo_devices_match_api_contract():
    validated = [DeviceIn.model_validate(device) for device in COLD_CHAIN_DEVICES]

    assert {device.device_id for device in validated} == {
        "COLD-CTRL-001",
        "TEMP-SENSOR-002",
        "EDGE-GW-003",
    }
    sensor = next(device for device in validated if device.device_id == "TEMP-SENSOR-002")
    assert sensor.security.unique_identity is None
    assert sensor.security.authentication is None


def test_legacy_test_fixtures_remain_available():
    assert DEVICES[0]["device_id"] == "TEMP-001"
    assert DEVICES[1]["device_id"] == "CAM-002"


def test_cold_chain_sample_sbom_uses_only_synthetic_demo_advisories():
    sample_path = Path(__file__).parent.parent / "samples" / "cold_chain_gateway_sbom.json"
    document = json.loads(sample_path.read_text(encoding="utf-8"))

    components = parse_cyclonedx(document)
    findings = scan_local(components)

    assert len(components) == 3
    assert {finding["vuln_id"] for finding in findings} == {
        "DT-DEMO-0001",
        "DT-DEMO-0002",
        "DT-DEMO-0003",
    }
    assert all(finding["source"] == "local-demo" for finding in findings)
