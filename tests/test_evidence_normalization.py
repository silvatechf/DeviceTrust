import pytest

from app.evidence_normalization import NORMALIZER_VERSION, normalize_observation


@pytest.mark.parametrize(
    ("attribute", "value", "canonical", "normalized"),
    [
        ("manufacturer", "Acme Devices", "identity.manufacturer", "Acme Devices"),
        ("firmware_version", "Vendor-build-01", "firmware.version", "Vendor-build-01"),
        ("mac_address", "AA-BB-CC-DD-EE-FF", "network.mac_address", "aa:bb:cc:dd:ee:ff"),
        ("ip_address", "2001:0db8:0:0:0:0:0:1", "network.ip_address", "2001:db8::1"),
        ("hostname", "Sensor-01.Example.", "network.hostname", "sensor-01.example"),
        ("secure_boot", "ENABLED", "security.secure_boot", "true"),
        ("internet_exposed", "no", "management.internet_exposed", "false"),
    ],
)
def test_known_attributes_are_normalized_without_losing_raw_value(
    attribute, value, canonical, normalized
):
    result = normalize_observation(attribute, value)
    assert result.source_attribute == attribute
    assert result.canonical_attribute == canonical
    assert result.raw_value == value
    assert result.normalized_value == normalized
    assert result.error is None
    assert result.normalizer_version == NORMALIZER_VERSION


@pytest.mark.parametrize(
    ("attribute", "value", "error"),
    [
        ("mac_address", "not-a-mac", "invalid MAC address"),
        ("mac_address", "AA-BB:CC-DD-EE-FF", "invalid MAC address"),
        ("mac_address", "AA--BB-CC-DD-EE-FF", "invalid MAC address"),
        ("ip_address", "999.1.1.1", "invalid IP address"),
        ("secure_boot", "probably", "ambiguous boolean value"),
        ("hostname", "bad host name", "invalid hostname"),
        ("hostname", "sensor.example..", "invalid hostname"),
    ],
)
def test_invalid_known_values_are_not_coerced(attribute, value, error):
    result = normalize_observation(attribute, value)
    assert result.canonical_attribute is not None
    assert result.raw_value == value
    assert result.normalized_value is None
    assert result.error == error


def test_unknown_attribute_is_preserved_as_unclassified():
    result = normalize_observation("vendor.custom_field", "raw-value")
    assert result.canonical_attribute is None
    assert result.normalized_value is None
    assert result.raw_value == "raw-value"
    assert result.error is None


def test_normalization_is_deterministic():
    first = normalize_observation("mac_address", "AA:BB:CC:DD:EE:FF")
    second = normalize_observation("mac_address", "AA:BB:CC:DD:EE:FF")
    assert first == second
