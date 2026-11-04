from .conftest import H


def test_report_audit_trail_uses_exact_device_identifier(client):
    target = {
        "device_id": "CAM_002",
        "manufacturer": "Target Manufacturer",
        "model": "Target Camera",
        "firmware_version": "1.0.0",
        "security": {},
    }
    similar = {
        **target,
        "device_id": "CAMX002",
        "manufacturer": "Unrelated Manufacturer",
        "model": "Unrelated Camera",
    }

    assert client.post("/devices", json=target, headers=H).status_code == 201
    assert client.post("/devices", json=similar, headers=H).status_code == 201

    response = client.get("/devices/CAM_002/report", headers=H)

    assert response.status_code == 200
    trail = response.json()["evidence_trail"]
    assert len(trail) == 1
    assert trail[0]["payload"]["manufacturer"] == "Target Manufacturer"
