import json

import httpx

from app import cli


def test_assess_sends_auth_and_idempotency_key_and_emits_json(monkeypatch, capsys):
    monkeypatch.setenv("DEVICETRUST_API_KEY", "test-token")

    def handler(request):
        assert request.method == "POST"
        assert request.url.path == "/sbom/imports/7/assessments"
        assert request.headers["X-API-Key"] == "test-token"
        assert request.headers["Idempotency-Key"] == "run-001"
        return httpx.Response(201, json={"id": 12, "created": True})

    code = cli.main(
        ["assess", "--import-id", "7", "--idempotency-key", "run-001"],
        transport=httpx.MockTransport(handler),
    )

    captured = capsys.readouterr()
    assert code == cli.EXIT_OK
    assert json.loads(captured.out) == {"id": 12, "created": True}
    assert captured.err == ""


def test_history_uses_authenticated_read_endpoint(monkeypatch, capsys):
    monkeypatch.setenv("DEVICETRUST_API_KEY", "test-token")

    def handler(request):
        assert request.method == "GET"
        assert request.url.path == "/sbom/imports/7/assessments"
        assert request.headers["X-API-Key"] == "test-token"
        return httpx.Response(200, json=[{"id": 12, "status": "complete"}])

    code = cli.main(["history", "--import-id", "7"], transport=httpx.MockTransport(handler))

    assert code == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out) == [{"id": 12, "status": "complete"}]


def test_findings_uses_import_and_assessment_scope(monkeypatch, capsys):
    monkeypatch.setenv("DEVICETRUST_API_KEY", "test-token")

    def handler(request):
        assert request.url.path == "/sbom/imports/7/assessments/12/findings"
        return httpx.Response(200, json=[])

    code = cli.main(
        ["findings", "--import-id", "7", "--assessment-id", "12"],
        transport=httpx.MockTransport(handler),
    )

    assert code == cli.EXIT_OK
    assert json.loads(capsys.readouterr().out) == []


def test_missing_token_fails_without_network(monkeypatch, capsys):
    monkeypatch.delenv("DEVICETRUST_API_KEY", raising=False)

    code = cli.main(["history", "--import-id", "7"])

    captured = capsys.readouterr()
    assert code == cli.EXIT_CONFIG
    assert "DEVICETRUST_API_KEY" in captured.err
    assert "test-token" not in captured.err


def test_non_loopback_http_url_is_rejected(monkeypatch, capsys):
    monkeypatch.setenv("DEVICETRUST_API_KEY", "test-token")

    code = cli.main(["--api-url", "http://example.com", "history", "--import-id", "7"])

    assert code == cli.EXIT_CONFIG
    assert "HTTPS" in capsys.readouterr().err


def test_authentication_failure_has_dedicated_exit_code(monkeypatch, capsys):
    monkeypatch.setenv("DEVICETRUST_API_KEY", "test-token")

    def handler(_request):
        return httpx.Response(403, json={"detail": "Insufficient API credential scope"})

    code = cli.main(["history", "--import-id", "7"], transport=httpx.MockTransport(handler))

    assert code == cli.EXIT_AUTH
    assert json.loads(capsys.readouterr().err)["exit_code"] == cli.EXIT_AUTH


def test_api_conflict_is_reported_as_api_error(monkeypatch, capsys):
    monkeypatch.setenv("DEVICETRUST_API_KEY", "test-token")

    def handler(_request):
        return httpx.Response(409, json={"detail": "Idempotency-Key conflict"})

    code = cli.main(
        ["assess", "--import-id", "7", "--idempotency-key", "run-001"],
        transport=httpx.MockTransport(handler),
    )

    assert code == cli.EXIT_API
    assert "409" in capsys.readouterr().err


def test_non_positive_ids_are_rejected_before_request(monkeypatch, capsys):
    monkeypatch.setenv("DEVICETRUST_API_KEY", "test-token")

    code = cli.main(["history", "--import-id", "0"])

    assert code == cli.EXIT_CONFIG
    assert "positive integer" in capsys.readouterr().err
