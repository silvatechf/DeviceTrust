from app import sbom


class _FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self.payload


class _FakeClient:
    def __init__(self, payload=None, error=None):
        self.payload = payload if payload is not None else {"vulns": []}
        self.error = error
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def post(self, url, *, json, timeout):
        self.calls.append((url, json, timeout))
        if self.error:
            raise self.error
        return _FakeResponse(self.payload)


def _component(name="openssl", version="3.0.0", purl="pkg:generic/openssl@3.0.0"):
    return {"name": name, "version": version, "purl": purl}


def test_osv_skips_malformed_response_payload(monkeypatch):
    client = _FakeClient(["unexpected", None])
    monkeypatch.setattr(sbom.httpx, "Client", lambda: client)

    findings, status = sbom.scan_osv_with_status([_component()])

    assert findings == []
    assert status["status"] == "incomplete"
    assert status["queried"] == 1


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
    monkeypatch.setattr(sbom.httpx, "Client", lambda: _FakeClient(payload))

    findings = sbom.scan_osv([_component()])

    assert [item["vuln_id"] for item in findings] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
        "CVE-2026-0003",
    ]
    assert [item["severity"] for item in findings] == ["unknown", "high", "unknown"]


def test_osv_deduplicates_queries_and_maps_findings_to_each_occurrence(monkeypatch):
    client = _FakeClient({"vulns": [{"id": "GHSA-test", "database_specific": {"severity": "HIGH"}}]})
    monkeypatch.setattr(sbom.httpx, "Client", lambda: client)
    components = [
        _component("openssl"),
        _component("renamed-occurrence"),
        _component("different-version", version="3.0.1", purl="pkg:generic/openssl@3.0.1"),
    ]

    findings, status = sbom.scan_osv_with_status(components, include_component_index=True)

    assert len(client.calls) == 2
    assert [item["component_index"] for item in findings] == [0, 1, 2]
    assert status["status"] == "complete"
    assert status["queried"] == 2
    assert status["query_candidates"] == 2
    assert status["deduplicated_occurrences"] == 1


def test_osv_query_budget_marks_remaining_components_incomplete(monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(sbom.httpx, "Client", lambda: client)
    monkeypatch.setattr(sbom, "MAX_OSV_QUERIES_PER_IMPORT", 1)
    components = [
        _component("one", purl="pkg:generic/one@1"),
        _component("two", purl="pkg:generic/two@1"),
    ]

    findings, status = sbom.scan_osv_with_status(components)

    assert findings == []
    assert len(client.calls) == 1
    assert status["status"] == "incomplete"
    assert status["deadline_exhausted"] is True
    assert status["queried"] == 1


def test_osv_deadline_prevents_starting_another_query(monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(sbom.httpx, "Client", lambda: client)
    ticks = iter([0.0, 0.0, 11.0])
    monkeypatch.setattr(sbom.time, "monotonic", lambda: next(ticks))
    components = [
        _component("one", purl="pkg:generic/one@1"),
        _component("two", purl="pkg:generic/two@1"),
    ]

    _, status = sbom.scan_osv_with_status(components)

    assert len(client.calls) == 1
    assert status["status"] == "incomplete"
    assert status["deadline_exhausted"] is True


def test_osv_http_failure_is_explicitly_incomplete(monkeypatch):
    client = _FakeClient(error=sbom.httpx.ConnectError("unavailable"))
    monkeypatch.setattr(sbom.httpx, "Client", lambda: client)

    _, status = sbom.scan_osv_with_status([_component()])

    assert status["status"] == "incomplete"
    assert status["request_failures"] is True
    assert status["queried"] == 1


def test_osv_components_without_purl_make_coverage_incomplete(monkeypatch):
    client = _FakeClient()
    monkeypatch.setattr(sbom.httpx, "Client", lambda: client)

    _, status = sbom.scan_osv_with_status([_component(purl=None)])

    assert status["status"] == "incomplete"
    assert status["skipped_without_purl"] == 1
    assert status["queried"] == 0
