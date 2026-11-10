"""Authenticated command-line client for DeviceTrust SBOM workflows."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx

EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_NETWORK = 3
EXIT_AUTH = 4
EXIT_API = 5
EXIT_SERVER = 6
MAX_SBOM_BYTES = 2 * 1024 * 1024


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devicetrust",
        description="Import CycloneDX SBOMs and run or inspect assessments through the DeviceTrust API.",
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("DEVICETRUST_API_URL", "http://127.0.0.1:8000"),
        help="DeviceTrust API base URL (default: DEVICETRUST_API_URL or localhost).",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    import_command = commands.add_parser("import", help="Import a CycloneDX JSON SBOM for a product release.")
    import_command.add_argument("--release-id", type=int, required=True)
    import_command.add_argument("--file", required=True, help="Path to a local CycloneDX JSON file.")
    import_command.add_argument(
        "--source-reference",
        help="Optional pipeline/build reference recorded by the API (maximum 500 characters).",
    )

    assess = commands.add_parser("assess", help="Create or retrieve an idempotent assessment run.")
    assess.add_argument("--import-id", type=int, required=True)
    assess.add_argument("--idempotency-key", required=True)

    history = commands.add_parser("history", help="List assessment runs for an SBOM import.")
    history.add_argument("--import-id", type=int, required=True)

    findings = commands.add_parser("findings", help="List findings for an assessment run.")
    findings.add_argument("--import-id", type=int, required=True)
    findings.add_argument("--assessment-id", type=int, required=True)
    return parser


def _validate_base_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("API URL must be an absolute HTTP(S) URL without credentials, query or fragment.")
    loopback = parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https" and not loopback:
        raise ValueError("Non-loopback API endpoints must use HTTPS.")
    return value.rstrip("/")


def _positive_id(value: int, name: str) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer.")


def _request_path(args: argparse.Namespace) -> tuple[str, str, dict[str, str]]:
    if args.command == "assess":
        _positive_id(args.import_id, "import-id")
        if not args.idempotency_key.strip() or len(args.idempotency_key) > 128:
            raise ValueError("idempotency-key must contain 1 to 128 non-whitespace characters.")
        return (
            "POST",
            f"/sbom/imports/{args.import_id}/assessments",
            {"Idempotency-Key": args.idempotency_key},
        )
    if args.command == "history":
        _positive_id(args.import_id, "import-id")
        return "GET", f"/sbom/imports/{args.import_id}/assessments", {}
    _positive_id(args.import_id, "import-id")
    _positive_id(args.assessment_id, "assessment-id")
    return (
        "GET",
        f"/sbom/imports/{args.import_id}/assessments/{args.assessment_id}/findings",
        {},
    )


def _read_sbom_file(value: str) -> bytes:
    path = Path(value)
    try:
        if not path.is_file():
            raise ValueError("SBOM file must be an existing regular file.")
        if path.stat().st_size > MAX_SBOM_BYTES:
            raise ValueError("SBOM file exceeds the 2 MiB limit.")
        content = path.read_bytes()
    except OSError:
        raise ValueError("SBOM file could not be read.") from None
    if len(content) > MAX_SBOM_BYTES:
        raise ValueError("SBOM file exceeds the 2 MiB limit.")
    if not content:
        raise ValueError("SBOM file must not be empty.")
    return content


def _emit_error(code: int, message: str) -> int:
    print(json.dumps({"error": message, "exit_code": code}, sort_keys=True), file=sys.stderr)
    return code


def main(argv: list[str] | None = None, *, transport: httpx.BaseTransport | None = None) -> int:
    args = _parser().parse_args(argv)
    token = os.getenv("DEVICETRUST_API_KEY", "")
    if not token:
        return _emit_error(EXIT_CONFIG, "DEVICETRUST_API_KEY is not configured.")

    try:
        base_url = _validate_base_url(args.api_url)
        if args.command == "import":
            _positive_id(args.release_id, "release-id")
            if args.source_reference is not None and len(args.source_reference) > 500:
                raise ValueError("source-reference must not exceed 500 characters.")
            body = _read_sbom_file(args.file)
            method = "POST"
            path = f"/product-releases/{args.release_id}/sbom"
            extra_headers = {"Content-Type": "application/json"}
            params = {"source_type": "pipeline"}
            if args.source_reference is not None:
                params["source_reference"] = args.source_reference
        else:
            method, path, extra_headers = _request_path(args)
            body = None
            params = None
    except ValueError as error:
        return _emit_error(EXIT_CONFIG, str(error))

    try:
        with httpx.Client(
            base_url=base_url,
            headers={"X-API-Key": token, **extra_headers, "Accept": "application/json"},
            timeout=httpx.Timeout(10.0, connect=3.0),
            transport=transport,
            follow_redirects=False,
        ) as client:
            response = client.request(method, path, content=body, params=params)
    except httpx.TimeoutException:
        return _emit_error(EXIT_NETWORK, "DeviceTrust API request timed out.")
    except httpx.HTTPError:
        return _emit_error(EXIT_NETWORK, "DeviceTrust API could not be reached.")

    if response.status_code in {401, 403}:
        return _emit_error(EXIT_AUTH, f"DeviceTrust API rejected the request (HTTP {response.status_code}).")
    if response.status_code >= 500:
        return _emit_error(EXIT_SERVER, f"DeviceTrust API failed (HTTP {response.status_code}).")
    if response.is_error:
        try:
            payload = response.json()
            detail = payload.get("detail", "Request rejected") if isinstance(payload, dict) else "Request rejected"
        except ValueError:
            detail = "Request rejected"
        return _emit_error(EXIT_API, f"HTTP {response.status_code}: {detail}")

    try:
        payload = response.json()
    except ValueError:
        return _emit_error(EXIT_SERVER, "DeviceTrust API returned a non-JSON response.")
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
