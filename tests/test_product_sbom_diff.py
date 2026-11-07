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


def test_product_sbom_diff_reports_add_remove_version_and_unidentified(client):
    release_id = _release(client)
    previous_id = _import(
        client,
        release_id,
        [
            _component("requests", "2.31.0", "pkg:pypi/requests@2.31.0"),
            _component("stable-lib", "1.0.0", "pkg:generic/stable-lib@1.0.0"),
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
            _component("added-lib", "1.0.0", "pkg:generic/added-lib@1.0.0"),
            _component("unidentified-new", "2.0.0"),
        ],
    )

    response = client.get(
        f"/product-releases/{release_id}/sbom/diff",
        params={"from_import_id": previous_id, "to_import_id": current_id},
        headers=H,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"] == {
        "added": 1,
        "removed": 1,
        "version_changed": 1,
        "metadata_changed": 0,
        "unchanged": 1,
        "ambiguous": 0,
        "unidentified_previous": 1,
        "unidentified_current": 1,
    }
    assert body["added"][0]["name"] == "added-lib"
    assert body["removed"][0]["name"] == "removed-lib"
    assert body["version_changed"][0]["previous"]["version"] == "2.31.0"
    assert body["version_changed"][0]["current"]["version"] == "2.32.0"
    assert body["unidentified"]["previous"][0]["name"] == "unidentified-old"
    assert body["unidentified"]["current"][0]["name"] == "unidentified-new"


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

    response = client.get(
        f"/product-releases/{release_id}/sbom/diff",
        params={"from_import_id": previous_id, "to_import_id": current_id},
        headers=H,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["ambiguous"] == 1
    assert body["summary"]["added"] == 0
    assert body["summary"]["removed"] == 0
    assert body["summary"]["version_changed"] == 0
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
    assert client.get(path, params={**params, "to_import_id": 999999}, headers=H).status_code == 404
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
