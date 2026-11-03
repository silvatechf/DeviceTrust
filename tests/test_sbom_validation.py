import pytest

from app.sbom import parse_cyclonedx, scan_local


def _component(name="openssl", version="1.1.1", purl="pkg:generic/openssl@1.1.1"):
    return {"type": "library", "name": name, "version": version, "purl": purl}


def test_rejects_non_object_component():
    with pytest.raises(ValueError, match="must be an object"):
        parse_cyclonedx({"bomFormat": "CycloneDX", "components": ["openssl"]})


def test_rejects_component_without_name_or_version():
    with pytest.raises(ValueError, match="invalid name"):
        parse_cyclonedx({"bomFormat": "CycloneDX", "components": [{"version": "1.0"}]})


def test_rejects_invalid_package_url():
    with pytest.raises(ValueError, match="invalid purl"):
        parse_cyclonedx({"bomFormat": "CycloneDX", "components": [_component(purl="not-a-purl")]})


def test_rejects_package_url_version_mismatch():
    with pytest.raises(ValueError, match="purl/version mismatch"):
        parse_cyclonedx({
            "bomFormat": "CycloneDX",
            "components": [_component(purl="pkg:generic/openssl@9.9.9")],
        })


def test_local_demo_match_requires_package_url():
    component = {"name": "openssl", "version": "1.1.1", "purl": None}
    assert scan_local([component]) == []


def test_local_demo_match_is_scoped_to_package_type():
    component = _component(purl="pkg:pypi/openssl@1.1.1")
    assert scan_local([component]) == []


def test_local_demo_match_uses_package_identity_and_version():
    component = _component()
    findings = scan_local([component])
    assert [finding["vuln_id"] for finding in findings] == ["DT-DEMO-0002"]
    assert findings[0]["source"] == "local-demo"


def test_local_demo_match_does_not_flag_fixed_version():
    component = _component(version="3.0.8", purl="pkg:generic/openssl@3.0.8")
    assert scan_local([component]) == []


def test_sample_sbom_has_two_expected_demo_matches():
    from pathlib import Path
    import json

    from app.sbom import scan

    sample = json.loads((Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_text())
    parsed = parse_cyclonedx(sample)
    findings = scan(parsed)
    assert {finding["vuln_id"] for finding in findings} == {"DT-DEMO-0001", "DT-DEMO-0002"}
