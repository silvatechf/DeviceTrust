import json
from types import SimpleNamespace

from app.product_sbom import _component_identity

from .conftest import H


def _release(client, product_name="Diff Fixture"):
    product = client.post(
        "/products",
        json={"manufacturer": "Example Vendor", "product_name": product_name},
        headers=H,
    )
    assert product.status_code == 201
    response = client.post(
        f"/products/{product.json()['id']}/releases",
        json={"version": "1.0.0"},
        headers=H,
    )
    assert response.status_code == 201
    return response.json()["id"]


def _component(name, version, purl=None):
    result = {"type": "library", "name": name, "version": version}
    if purl is not None:
        result["purl"] = purl
    return result


def _import(client, release_id, components):
    response = client.post(
        f"/product-releases/{release_id}/sbom",
        json={
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": components,
        },
        headers=H,
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _diff(client, release_id, from_import_id, to_import_id):
    return client.get(
        f"/product-releases/{release_id}/sbom/diff",
        params={
            "from_import_id": from_import_id,
            "to_import_id": to_import_id,
        },
        headers=H,
    )


def test_product_sbom_diff_reports_add_remove_and_all_change_dimensions(client):
    release_id = _release(client)
    previous_id = _import(
        client,
        release_id,
        [
            _component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
            _component("stable-lib", "1.0.0", "pkg:generic/stable-lib@1.0.0"),
            _component("legacy-name", "1.0.0", "pkg:generic/renamed@1.0.0"),
            _component("removed-lib", "3.0.0", "pkg:generic/removed-lib@3.0.0"),
            _component("unidentified-old", "1.0.0"),
        ],
    )
    current_id = _import(
        client,
        release_id,
        [
            _component("requests", "2.32.0", "pkg:pypi/requests@2.32.0"),
            _component("stable-lib", "1.0.0", "pkg:generic/stable-lib@1.0.0"),
            _component("new-name", "1.0.0", "pkg:generic/renamed@1.0.0"),
            _component("added-lib", "1.0.0", "pkg:generic/added-lib@1.0.0"),
            _component("unidentified-new", "2.0.0"),
        ],
    )

    imports_before = client.get(
        f"/product-releases/{release_id}/sbom", headers=H
    ).json()
    components_before = {
        import_id: client.get(f"/sbom/imports/{import_id}/components", headers=H).json()
        for import_id in (previous_id, current_id)
    }
    audit_before = client.get("/audit", headers=H).json()

    response = _diff(client, release_id, previous_id, current_id)

    assert response.status_code == 200
    body = response.json()
    assert body["summary"] == {
        "added": 1,
        "removed": 1,
        "changed": 2,
        "version_changed": 1,
        "name_changed": 1,
        "unchanged": 1,
        "ambiguous": 0,
        "unidentified_previous": 1,
        "unidentified_current": 1,
    }
    assert body["added"][0]["name"] == "added-lib"
    assert body["removed"][0]["name"] == "removed-lib"
    changes_by_previous_name = {
        item["previous"]["name"]: item for item in body["changed"]
    }
    assert changes_by_previous_name["legacy-name"]["changes"] == ["name"]
    assert changes_by_previous_name["requests"]["changes"] == ["version"]
    assert body["unidentified"]["previous"][0]["name"] == "unidentified-old"
    assert body["unidentified"]["current"][0]["name"] == "unidentified-new"

    assert client.get(f"/product-releases/{release_id}/sbom", headers=H).json() == imports_before
    for import_id in (previous_id, current_id):
        assert client.get(
            f"/sbom/imports/{import_id}/components", headers=H
        ).json() == components_before[import_id]
    assert client.get("/audit", headers=H).json() == audit_before


def test_product_sbom_diff_reports_simultaneous_version_and_name_changes(client):
    release_id = _release(client, "Simultaneous Change Fixture")
    previous_id = _import(
        client,
        release_id,
        [_component("old-name", "1.0.0", "pkg:generic/shared@1.0.0")],
    )
    current_id = _import(
        client,
        release_id,
        [_component("new-name", "2.0.0", "pkg:generic/shared@2.0.0")],
    )

    response = _diff(client, release_id, previous_id, current_id)

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["changed"] == 1
    assert body["summary"]["version_changed"] == 1
    assert body["summary"]["name_changed"] == 1
    assert body["changed"] == [
        {
            "identity": "pkg:generic/shared",
            "previous": body["changed"][0]["previous"],
            "current": body["changed"][0]["current"],
            "changes": ["version", "name"],
        }
    ]
    assert body["changed"][0]["previous"]["name"] == "old-name"
    assert body["changed"][0]["current"]["name"] == "new-name"
    assert body["changed"][0]["previous"]["version"] == "1.0.0"
    assert body["changed"][0]["current"]["version"] == "2.0.0"


def test_product_sbom_diff_preserves_qualifiers_and_subpath_identity(client):
    release_id = _release(client, "PURL Boundary Fixture")
    previous_id = _import(
        client,
        release_id,
        [
            _component(
                "qualified-lib",
                "1.0.0",
                "pkg:generic/qualified-lib@1.0.0?arch=x86#modules/core",
            ),
            _component(
                "subpath-lib",
                "1.0.0",
                "pkg:generic/subpath-lib@1.0.0?arch=x86#modules/alpha",
            ),
        ],
    )
    current_id = _import(
        client,
        release_id,
        [
            _component(
                "qualified-lib",
                "2.0.0",
                "pkg:generic/qualified-lib@2.0.0?arch=arm#modules/core",
            ),
            _component(
                "subpath-lib",
                "2.0.0",
                "pkg:generic/subpath-lib@2.0.0?arch=x86#modules/beta",
            ),
        ],
    )

    response = _diff(client, release_id, previous_id, current_id)

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["added"] == 2
    assert body["summary"]["removed"] == 2
    assert body["summary"]["changed"] == 0
    assert body["summary"]["version_changed"] == 0
    assert body["added"] == sorted(body["added"], key=lambda item: item["purl"])
    assert {item["name"] for item in body["added"]} == {
        "qualified-lib",
        "subpath-lib",
    }
    assert {item["name"] for item in body["removed"]} == {
        "qualified-lib",
        "subpath-lib",
    }


def test_product_sbom_diff_handles_equivalent_component_content(client):
    release_id = _release(client, "Equivalent Content Fixture")
    first_id = _import(
        client,
        release_id,
        [
            _component("alpha", "1.0.0", "pkg:generic/alpha@1.0.0"),
            _component("beta", "2.0.0", "pkg:generic/beta@2.0.0"),
        ],
    )
    second_id = _import(
        client,
        release_id,
        [
            _component("beta", "2.0.0", "pkg:generic/beta@2.0.0"),
            _component("alpha", "1.0.0", "pkg:generic/alpha@1.0.0"),
        ],
    )
    assert first_id != second_id

    response = _diff(client, release_id, first_id, second_id)

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["unchanged"] == 2
    assert body["summary"]["added"] == 0
    assert body["summary"]["removed"] == 0
    assert body["summary"]["changed"] == 0
    assert body["changed"] == []
    assert body["ambiguous"] == []


def test_product_sbom_diff_same_import_is_deterministically_unchanged(client):
    release_id = _release(client, "Self Comparison Fixture")
    import_id = _import(
        client,
        release_id,
        [
            _component("stable", "1.0.0", "pkg:generic/stable@1.0.0"),
            _component("no-purl", "1.0.0"),
        ],
    )

    response = _diff(client, release_id, import_id, import_id)

    assert response.status_code == 200
    body = response.json()
    assert body["from_import_id"] == body["to_import_id"] == import_id
    assert body["summary"] == {
        "added": 0,
        "removed": 0,
        "changed": 0,
        "version_changed": 0,
        "name_changed": 0,
        "unchanged": 1,
        "ambiguous": 0,
        "unidentified_previous": 1,
        "unidentified_current": 1,
    }
    assert body["added"] == []
    assert body["removed"] == []
    assert body["changed"] == []
    assert body["ambiguous"] == []


def test_product_sbom_diff_reverse_direction_reverses_changes(client):
    release_id = _release(client, "Reverse Direction Fixture")
    earlier_id = _import(
        client,
        release_id,
        [
            _component("old-version", "1.0.0", "pkg:generic/versioned@1.0.0"),
            _component("removed-in-forward", "1.0.0", "pkg:generic/removed@1.0.0"),
        ],
    )
    later_id = _import(
        client,
        release_id,
        [
            _component("new-version", "2.0.0", "pkg:generic/versioned@2.0.0"),
            _component("added-in-forward", "1.0.0", "pkg:generic/added@1.0.0"),
        ],
    )

    forward = _diff(client, release_id, earlier_id, later_id).json()
    reverse = _diff(client, release_id, later_id, earlier_id).json()

    assert forward["added"][0]["name"] == "added-in-forward"
    assert forward["removed"][0]["name"] == "removed-in-forward"
    assert reverse["added"][0]["name"] == "removed-in-forward"
    assert reverse["removed"][0]["name"] == "added-in-forward"
    assert forward["changed"][0]["previous"]["version"] == "1.0.0"
    assert forward["changed"][0]["current"]["version"] == "2.0.0"
    assert reverse["changed"][0]["previous"]["version"] == "2.0.0"
    assert reverse["changed"][0]["current"]["version"] == "1.0.0"


def test_component_identity_treats_invalid_legacy_purls_as_unidentified():
    assert _component_identity(SimpleNamespace(purl="not a valid package url")) is None
    assert _component_identity(SimpleNamespace(purl=None)) is None


def test_product_sbom_diff_does_not_guess_duplicate_purl_matches(client):
    release_id = _release(client, "Duplicate PURL Fixture")
    previous_id = _import(
        client,
        release_id,
        [
            _component("duplicate-a", "1.0.0", "pkg:generic/duplicate@1.0.0"),
            _component("duplicate-b", "2.0.0", "pkg:generic/duplicate@2.0.0"),
        ],
    )
    current_id = _import(
        client,
        release_id,
        [_component("duplicate-current", "3.0.0", "pkg:generic/duplicate@3.0.0")],
    )

    response = _diff(client, release_id, previous_id, current_id)

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["ambiguous"] == 1
    assert body["summary"]["added"] == 0
    assert body["summary"]["removed"] == 0
    assert body["summary"]["changed"] == 0
    assert body["ambiguous"][0]["identity"] == "pkg:generic/duplicate"
    assert len(body["ambiguous"][0]["previous"]) == 2
    assert len(body["ambiguous"][0]["current"]) == 1


def test_product_sbom_diff_requires_authentication_and_same_release(client):
    release_id = _release(client, "First Release")
    other_release_id = _release(client, "Second Release")
    first_import = _import(
        client, release_id, [_component("lib", "1.0.0", "pkg:generic/lib@1.0.0")]
    )
    other_import = _import(
        client, other_release_id, [_component("lib", "1.0.0", "pkg:generic/lib@1.0.0")]
    )
    path = f"/product-releases/{release_id}/sbom/diff"
    params = {"from_import_id": first_import, "to_import_id": other_import}

    assert client.get(path, params=params).status_code == 401
    assert _diff(client, release_id, 999999, first_import).status_code == 404
    assert _diff(client, release_id, first_import, 999999).status_code == 404
    assert client.get(
        f"/product-releases/{other_release_id}/sbom/diff",
        params=params,
        headers=H,
    ).status_code == 404
    assert client.get(
        path,
        params={"from_import_id": 0, "to_import_id": first_import},
        headers=H,
    ).status_code == 422
