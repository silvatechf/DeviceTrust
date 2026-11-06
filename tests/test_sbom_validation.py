import pytest

from app.sbom import parse_cyclonedx, scan_local


def _document(components, spec_version="1.5"):
    return {"bomFormat": "CycloneDX", "specVersion": spec_version, "components": components}


def _component(name="openssl", version="1.1.1", purl="pkg:generic/openssl@1.1.1"):
    return {"type": "library", "name": name, "version": version, "purl": purl}


def test_rejects_missing_cyclonedx_spec_version():
    with pytest.raises(ValueError, match="Unsupported or missing CycloneDX specVersion"):
        parse_cyclonedx({"bomFormat": "CycloneDX", "components": []})


def test_rejects_unsupported_cyclonedx_spec_version():
    with pytest.raises(ValueError, match="Unsupported or missing CycloneDX specVersion"):
        parse_cyclonedx(_document([], spec_version="1.6"))


def test_rejects_non_object_component():
    with pytest.raises(ValueError, match="must be an object"):
        parse_cyclonedx(_document(["openssl"]))


def test_rejects_component_without_name_or_version():
    with pytest.raises(ValueError, match="invalid name"):
        parse_cyclonedx(_document([{"version": "1.0"}]))


def test_rejects_invalid_package_url():
    with pytest.raises(ValueError, match="invalid purl"):
        parse_cyclonedx(_document([_component(purl="not-a-purl")]))


def test_rejects_package_url_version_mismatch():
    with pytest.raises(ValueError, match="purl/version mismatch"):
        parse_cyclonedx(_document([_component(purl="pkg:generic/openssl@9.9.9")]))


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
    import json
    from pathlib import Path

    from app.sbom import scan

    sample = json.loads((Path(__file__).parent.parent / "samples" / "sensor_sbom.json").read_text())
    parsed = parse_cyclonedx(sample)
    findings = scan(parsed)
    assert {finding["vuln_id"] for finding in findings} == {"DT-DEMO-0001", "DT-DEMO-0002"}

def test_parser_preserves_original_name_and_version_for_provenance():
    parsed = parse_cyclonedx(
        _document([_component(name="  OpenSSL  ", version="  1.1.1  ")])
    )
    assert parsed[0]["source_name"] == "  OpenSSL  "
    assert parsed[0]["source_version"] == "  1.1.1  "
    assert parsed[0]["name"] == "openssl"
    assert parsed[0]["version"] == "1.1.1"
