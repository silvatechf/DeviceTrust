from app import sbom


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _FakeClient:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def post(self, *_args, **_kwargs):
        return _FakeResponse(self.payload)


def _component():
    return [{
        "name": "openssl",
        "version": "3.0.0",
        "purl": "pkg:generic/openssl@3.0.0",
    }]


def test_osv_skips_malformed_response_payload(monkeypatch):
    monkeypatch.setattr(
        sbom.httpx,
        "Client",
        lambda timeout: _FakeClient(["unexpected", None]),
    )

    assert sbom.scan_osv(_component()) == []


def test_osv_skips_malformed_entries_and_normalizes_severity(monkeypatch):
    payload = {
        "vulns": [
            None,
            {"id": "CVE-2026-0001", "database_specific": None},
            {"id": 42, "database_specific": {"severity": "HIGH"}},
            {"id": "CVE-2026-0002", "database_specific": {"severity": "HIGH"}},
            {"id": "CVE-2026-0003", "database_specific": {"severity": ["HIGH"]}},
        ]
    }
    monkeypatch.setattr(
        sbom.httpx,
        "Client",
        lambda timeout: _FakeClient(payload),
    )

    findings = sbom.scan_osv(_component())

    assert [item["vuln_id"] for item in findings] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    ]
    assert [item["severity"] for item in findings] == ["unknown", "high", "unknown"]
