import pytest

from app.posture import assess


def _security_configuration(**overrides):
    return {
        "default_credentials": False,
        "open_interfaces": [],
        **overrides,
    }


def _configuration_finding(security):
    result = assess({"device_id": "POSTURE-001", "security": security})
    return next(
        item for item in result["controls"]
        if item["control"] == "secure_configuration"
    )


@pytest.mark.parametrize(
    "security",
    [
        {"default_credentials": False},
        {"open_interfaces": []},
        {},
    ],
)
def test_secure_configuration_remains_unverified_when_evidence_is_incomplete(security):
    finding = _configuration_finding(security)

    assert finding["status"] == "unverified"
    assert finding["risk"] == "unknown"


def test_secure_configuration_is_compliant_only_when_both_inputs_are_present():
    finding = _configuration_finding(_security_configuration())

    assert finding["status"] == "compliant"


def test_known_default_credentials_remain_non_compliant_with_other_evidence_missing():
    finding = _configuration_finding({"default_credentials": True})

    assert finding["status"] == "non_compliant"
    assert finding["risk"] == "high"


def test_known_insecure_interface_is_not_hidden_by_missing_credential_evidence():
    finding = _configuration_finding({"open_interfaces": ["telnet"]})

    assert finding["status"] == "partial"
    assert finding["evidence"]["insecure_interfaces"] == ["telnet"]
