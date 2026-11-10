"""Integrated API/CLI proof for the product-release review and VEX workflow."""

import json

import httpx

from app import cli, intelligence, sbom

from .conftest import H
from .test_decision_approvals import _approval_submission, _operator, _sign_author


class _TestClientTransport(httpx.BaseTransport):
    """Forward the synchronous CLI HTTP client into the in-process API test client."""

    def __init__(self, api_client):
        self.api_client = api_client

    def handle_request(self, request):
        response = self.api_client.request(
            request.method,
            request.url.raw_path.decode("ascii"),
            headers=dict(request.headers),
            content=request.content,
        )
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=response.content,
            request=request,
        )


def _run_cli(capsys, transport, *args):
    exit_code = cli.main(
        ["--api-url", "http://127.0.0.1:8000", *args],
        transport=transport,
    )
    captured = capsys.readouterr()
    assert exit_code == cli.EXIT_OK, captured.err
    assert captured.err == ""
    return json.loads(captured.out)


def test_product_release_api_cli_review_and_vex_workflow(
    client, capsys, monkeypatch, tmp_path
):
    """Exercise the user-facing API/CLI sequence without external intelligence calls."""

    async def deterministic_scan(components, *, include_component_index=False):
        return (
            sbom.scan_local(components, include_component_index=include_component_index),
            {"status": "complete", "source": "local-demo", "queried": 0},
        )

    async def deterministic_intelligence(findings):
        return findings, {
            "kev": {"status": "disabled"},
            "epss": {"status": "disabled"},
        }

    monkeypatch.setattr(sbom, "scan_with_metadata_async", deterministic_scan)
    monkeypatch.setattr(intelligence, "enrich_findings", deterministic_intelligence)

    # Product/release creation is intentionally separate from the CLI import command.
    product = client.post(
        "/products",
        headers=H,
        json={
            "manufacturer": "Synthetic Workflow Vendor",
            "product_name": "Synthetic Edge Gateway",
            "external_reference": "P0-WORKFLOW",
        },
    )
    assert product.status_code == 201, product.text
    release = client.post(
        f"/products/{product.json()['id']}/releases",
        headers=H,
        json={"version": "3.1.0", "hardware_revision": "A"},
    )
    assert release.status_code == 201, release.text
    release_id = release.json()["id"]

    author_id, author_token = _operator(
        "P0 workflow author",
        scopes={
            "assessment:review",
            "assessment:read",
            "assessment:sign",
            "assessment:approve",
            "evidence:read",
            "evidence:write",
            "sbom:read",
            "sbom:write",
            "inventory:write",
            "assessment:write",
            "audit:read",
            "vex:export",
        },
    )
    monkeypatch.setenv("DEVICETRUST_AUTH_MODE", "managed")
    monkeypatch.setenv("DEVICETRUST_API_KEY", author_token)

    bom_path = tmp_path / "workflow-sbom.json"
    bom_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                "version": 1,
                "metadata": {
                    "component": {
                        "bom-ref": "synthetic-edge-gateway",
                        "type": "device",
                        "name": "Synthetic Edge Gateway",
                        "version": "3.1.0",
                    }
                },
                "components": [
                    {
                        "type": "library",
                        "name": "busybox",
                        "version": "1.31.0",
                        "purl": "pkg:generic/busybox@1.31.0",
                        "bom-ref": "busybox-1",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    transport = _TestClientTransport(client)
    imported = _run_cli(
        capsys,
        transport,
        "import",
        "--release-id",
        str(release_id),
        "--file",
        str(bom_path),
        "--source-reference",
        "p0-integration-test",
    )
    assert imported["created"] is True
    import_id = imported["id"]

    assessment = _run_cli(
        capsys,
        transport,
        "assess",
        "--import-id",
        str(import_id),
        "--idempotency-key",
        "p0-workflow-assessment-001",
    )
    assessment_id = assessment["id"]
    assert assessment["status"] == "complete"

    history = _run_cli(capsys, transport, "history", "--import-id", str(import_id))
    assert [item["id"] for item in history] == [assessment_id]

    findings = _run_cli(
        capsys,
        transport,
        "findings",
        "--import-id",
        str(import_id),
        "--assessment-id",
        str(assessment_id),
    )
    assert len(findings) == 1
    finding_id = findings[0]["id"]
    assert findings[0]["vuln_id"] == "DT-DEMO-0001"

    observation = client.post(
        "/evidence",
        headers={"X-API-Key": author_token},
        json={
            "source_type": "manual",
            "attribute": "firmware_note",
            "value": "Synthetic evidence supporting the reviewed finding",
        },
    )
    assert observation.status_code == 201, observation.text
    artifact = client.post(
        f"/evidence/{observation.json()['id']}/artifacts",
        headers={
            "X-API-Key": author_token,
            "Content-Type": "application/octet-stream",
        },
        content=b"synthetic product security evidence",
    )
    assert artifact.status_code == 201, artifact.text
    artifact_id = artifact.json()["id"]

    decision = client.post(
        f"/sbom/assessment-findings/{finding_id}/decisions",
        headers={
            "X-API-Key": author_token,
            "Idempotency-Key": "p0-workflow-decision-001",
        },
        json={
            "state": "in_triage",
            "detail": "Synthetic finding reviewed for the integrated workflow test.",
            "evidence_references": [artifact_id],
        },
    )
    assert decision.status_code == 201, decision.text
    decision_id = decision.json()["id"]

    vex_url = f"/product-releases/{release_id}/sbom/{import_id}/vex"
    vex_params = {"assessment_id": assessment_id}
    blocked = client.post(
        vex_url,
        params=vex_params,
        headers={"X-API-Key": author_token},
    )
    assert blocked.status_code == 409
    blocked_detail = blocked.json()["detail"]
    assert blocked_detail["code"] == "vex_export_blocked"
    assert any(
        blocker["code"] == "evidence_manifest_missing_or_invalid"
        for blocker in blocked_detail["blockers"]
    )

    manifest = client.post(
        f"/sbom/decisions/{decision_id}/evidence-manifest",
        headers={"X-API-Key": author_token},
        json={"artifact_ids": [artifact_id]},
    )
    assert manifest.status_code == 201, manifest.text
    assert manifest.json()["integrity_valid"] is True

    _sign_author(client, author_token, decision_id, author_id)

    approver_id, approver_token = _operator(
        "P0 workflow independent approver",
        scopes={"assessment:approve", "assessment:read"},
    )
    approval_payload = _approval_submission(
        client, decision_id, approver_id, approver_token
    )
    approval = client.post(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": approver_token},
        json=approval_payload,
    )
    assert approval.status_code == 201, approval.text

    approval_status = client.get(
        f"/sbom/decisions/{decision_id}/approval",
        headers={"X-API-Key": author_token},
    )
    assert approval_status.status_code == 200
    assert approval_status.json()["approval_policy_satisfied"] is True

    exported = client.post(
        vex_url,
        params=vex_params,
        headers={"X-API-Key": author_token},
    )
    assert exported.status_code == 200, exported.text
    result = exported.json()
    assert result["decision_count"] == 1
    assert result["vulnerability_count"] == 1
    assert result["bom"]["vulnerabilities"][0]["id"] == "DT-DEMO-0001"
    assert result["bom"]["vulnerabilities"][0]["analysis"]["state"] == "in_triage"

    audit_history = client.get("/audit", headers={"X-API-Key": author_token})
    assert audit_history.status_code == 200
    assert any(
        entry["action"] == "product_sbom.vex.export"
        and entry["entity"] == str(import_id)
        for entry in audit_history.json()
    )
