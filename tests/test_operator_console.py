def test_operator_console_is_served_with_security_headers(client):
    response = client.get("/")
    assert response.status_code == 200
    assert "DeviceTrust" in response.text
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in response.headers["content-security-policy"]
    assert response.headers["cache-control"] == "no-store"


def test_operator_console_assets_are_served_without_inline_script(client):
    html = client.get("/").text
    script = client.get("/assets/app.js")
    stylesheet = client.get("/assets/app.css")
    assert script.status_code == 200
    assert stylesheet.status_code == 200
    assert 'src="/assets/app.js" defer' in html
    assert "<script>" not in html
    assert "localStorage" not in script.text
    assert "sessionStorage" not in script.text


def test_api_docs_remain_available_outside_console_csp(client):
    response = client.get("/docs")
    assert response.status_code == 200
    assert "swagger-ui" in response.text.lower()
    assert "content-security-policy" not in response.headers

def test_product_sbom_console_workflow_is_exposed_without_inline_scripts(client):
    html = client.get("/").text
    script = client.get("/assets/app.js").text
    assert 'data-view="product-sbom"' in html
    assert 'id="view-product-sbom"' in html
    assert 'id="product-form"' in html
    assert 'id="release-form"' in html
    assert 'id="product-sbom-form"' in html
    assert 'id="run-assessment"' in html
    assert "/products" in script
    assert "/product-releases/" in script
    assert "/sbom/imports/" in script
    assert "Idempotency-Key" in script
    assert "state.selectedImportAccepted" in script
    assert 'item.status !== "accepted"' in script
    assert "applicability.status" in script
    assert "applicability.interpretation" in script
    assert "finding.applicability].filter(Boolean)" not in script
    assert "localStorage" not in script
    assert "sessionStorage" not in script
