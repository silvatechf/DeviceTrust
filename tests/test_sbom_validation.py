import pytest

from app.sbom import parse_cyclonedx, parse_cyclonedx_document, scan_local


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



def test_parser_preserves_bom_and_component_references():
    document = _document([
        {
            **_component(),
            "bom-ref": "component-openssl-1",
        }
    ])
    document["serialNumber"] = "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79"
    document["version"] = 2
    document["metadata"] = {
        "component": {
            "type": "application",
            "bom-ref": "product-sensor-x",
            "name": "Sensor X",
            "version": "1.2.3",
            "purl": "pkg:generic/sensor-x@1.2.3",
        }
    }

    parsed = parse_cyclonedx_document(document)

    assert parsed["serial_number"] == document["serialNumber"]
    assert parsed["version"] == 2
    assert parsed["metadata_component"] == {
        "bom_ref": "product-sensor-x",
        "type": "application",
        "name": "Sensor X",
        "version": "1.2.3",
        "purl": "pkg:generic/sensor-x@1.2.3",
    }
    assert parsed["components"][0]["bom_ref"] == "component-openssl-1"
    assert parse_cyclonedx(document)[0]["bom_ref"] == "component-openssl-1"


def test_parser_rejects_duplicate_bom_refs_across_metadata_and_components():
    document = _document([
        {**_component(), "bom-ref": "shared-reference"}
    ])
    document["metadata"] = {
        "component": {
            "type": "application",
            "bom-ref": "shared-reference",
            "name": "Sensor X",
        }
    }

    with pytest.raises(ValueError, match="Duplicate CycloneDX bom-ref"):
        parse_cyclonedx_document(document)


def test_parser_rejects_duplicate_component_bom_refs():
    document = _document([
        {**_component(), "bom-ref": "duplicate"},
        {**_component(name="other"), "bom-ref": "duplicate"},
    ])

    with pytest.raises(ValueError, match="Duplicate CycloneDX bom-ref"):
        parse_cyclonedx_document(document)


@pytest.mark.parametrize(
    "serial_number",
    ["not-a-uuid", "urn:uuid:not-a-uuid", 123],
)
def test_parser_rejects_invalid_bom_serial_number(serial_number):
    document = _document([])
    document["serialNumber"] = serial_number

    with pytest.raises(ValueError, match="serialNumber must be a URN UUID"):
        parse_cyclonedx_document(document)


@pytest.mark.parametrize("version", [0, -1, True, "2", 1.5])
def test_parser_rejects_invalid_bom_version(version):
    document = _document([])
    document["version"] = version

    with pytest.raises(ValueError, match="BOM version must be a positive integer"):
        parse_cyclonedx_document(document)


def test_parser_rejects_invalid_component_bom_ref():
    document = _document([{**_component(), "bom-ref": " " * 3}])

    with pytest.raises(ValueError, match="invalid bom-ref"):
        parse_cyclonedx_document(document)


def test_parser_keeps_bom_metadata_optional_for_legacy_documents():
    parsed = parse_cyclonedx_document(_document([_component()]))

    assert parsed["serial_number"] is None
    assert parsed["version"] is None
    assert parsed["metadata_component"] is None
    assert parsed["components"][0]["bom_ref"] is None
