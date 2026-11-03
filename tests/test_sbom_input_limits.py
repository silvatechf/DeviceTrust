from .conftest import H


def _create_device(client, device_id):
    response = client.post(
        "/devices",
        json={
            "device_id": device_id,
            "manufacturer": "Example IoT",
            "model": "Test Sensor",
            "firmware_version": "1.0.0",
            "security": {},
        },
        headers=H,
    )
    assert response.status_code == 201


def test_malformed_sbom_json_returns_422(client):
    device_id = "SBOM-BAD-JSON"
    _create_device(client, device_id)
    response = client.post(
        f"/devices/{device_id}/sbom",
        content=b"{",
        headers={**H, "Content-Type": "application/json"},
    )
    assert response.status_code == 422


def test_non_object_sbom_json_returns_422(client):
    device_id = "SBOM-ARRAY"
    _create_device(client, device_id)
    response = client.post(
        f"/devices/{device_id}/sbom",
        json=[],
        headers=H,
    )
    assert response.status_code == 422


def test_oversized_sbom_returns_413(client):
    device_id = "SBOM-TOO-LARGE"
    _create_device(client, device_id)
    response = client.post(
        f"/devices/{device_id}/sbom",
        content=b" " * (2 * 1024 * 1024 + 1),
        headers={**H, "Content-Type": "application/json"},
    )
    assert response.status_code == 413
