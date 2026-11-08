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
    assert status["budget_exhausted"] is True
    assert status["deadline_exhausted"] is False
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



def test_async_osv_enrichment_cancels_at_total_deadline(monkeypatch):
    import asyncio

    class _SlowAsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def post(self, *_args, **_kwargs):
            await asyncio.sleep(1)
            return _FakeResponse({"vulns": []})

    monkeypatch.setattr(sbom.httpx, "AsyncClient", _SlowAsyncClient)
    monkeypatch.setattr(sbom, "OSV_ENRICHMENT_DEADLINE_SECONDS", 0.01)

    findings, status = asyncio.run(sbom.scan_osv_with_status_async([_component()]))

    assert findings == []
    assert status["status"] == "incomplete"
    assert status["deadline_exhausted"] is True
    assert status["queried"] == 1


def test_async_osv_enrichment_preserves_partial_findings_on_deadline(monkeypatch):
    import asyncio

    class _PartialAsyncClient:
        def __init__(self):
            self.calls = 0

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def post(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                return _FakeResponse({
                    "vulns": [{"id": "GHSA-partial", "database_specific": {"severity": "HIGH"}}]
                })
            await asyncio.sleep(1)
            return _FakeResponse({"vulns": []})

    client = _PartialAsyncClient()
    monkeypatch.setattr(sbom.httpx, "AsyncClient", lambda: client)
    monkeypatch.setattr(sbom, "OSV_ENRICHMENT_DEADLINE_SECONDS", 0.01)
    components = [
        _component("first", purl="pkg:generic/first@1"),
        _component("second", purl="pkg:generic/second@1"),
    ]

    findings, status = asyncio.run(
        sbom.scan_osv_with_status_async(components, include_component_index=True)
    )

    assert [finding["vuln_id"] for finding in findings] == ["GHSA-partial"]
    assert findings[0]["component_index"] == 0
    assert status["status"] == "incomplete"
    assert status["deadline_exhausted"] is True
    assert status["queried"] == 2


def test_async_osv_enrichment_completes_within_deadline(monkeypatch):
    import asyncio

    client = _FakeClient({"vulns": []})

    class _AsyncClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def post(self, *_args, **_kwargs):
            return _FakeResponse(client.payload)

    monkeypatch.setattr(sbom.httpx, "AsyncClient", _AsyncClient)

    findings, status = asyncio.run(sbom.scan_osv_with_status_async([_component()]))

    assert findings == []
    assert status["status"] == "complete"
    assert status["queried"] == 1


def test_async_osv_deadline_includes_query_preparation(monkeypatch):
    import asyncio
    import time

    class _SlowComponents(list):
        def __iter__(self):
            time.sleep(0.02)
            return super().__iter__()

    class _AsyncClient:
        async def __aenter__(self):
            await asyncio.sleep(0)
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def post(self, *_args, **_kwargs):
            raise AssertionError("OSV request must not start after the absolute deadline")

    monkeypatch.setattr(sbom.httpx, "AsyncClient", _AsyncClient)
    monkeypatch.setattr(sbom, "OSV_ENRICHMENT_DEADLINE_SECONDS", 0.01)

    findings, status = asyncio.run(
        sbom.scan_osv_with_status_async(
            _SlowComponents([_component()])
        )
    )

    assert findings == []
    assert status["status"] == "incomplete"
    assert status["deadline_exhausted"] is True
    assert status["queried"] == 0
