"""Conservative CycloneDX 1.5 VEX export for reviewed product SBOM findings."""

from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from uuid import UUID, uuid5

import jsonschema
import rfc8785
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import decision_approvals, decision_evidence, decision_signatures, vulnerability_decisions
from .db import (
    ProductRelease,
    SBOMAssessment,
    SBOMAssessmentFinding,
    SBOMComponent,
    SBOMImport,
    VulnerabilityDecision,
)

SPEC_VERSION = "1.5"
EXPORT_NAMESPACE = UUID("d8f6c66e-3b19-4c15-a8a2-75ac44c0a6e1")
SCHEMA_PATH = Path(__file__).with_name("cyclonedx-bom-1.5.schema.json")
VULNERABILITY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")


class VEXExportConflict(ValueError):
    """Raised when selected reviewed decisions cannot be exported without guessing."""


class VEXSchemaUnavailable(RuntimeError):
    """Raised when the pinned CycloneDX schema cannot be loaded or validated."""


def _utc_iso(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _canonical_digest(value: object) -> str:
    return hashlib.sha256(rfc8785.dumps(value)).hexdigest()


def _load_schema() -> dict:
    try:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        jsonschema.Draft7Validator.check_schema(schema)
        return schema
    except (OSError, json.JSONDecodeError, jsonschema.SchemaError):
        raise VEXSchemaUnavailable("Pinned CycloneDX 1.5 schema is unavailable or invalid") from None


def _component_metadata(raw: object) -> dict:
    if not isinstance(raw, dict):
        raise VEXExportConflict("product_identity_missing")
    component = {
        "type": raw.get("type"),
        "name": raw.get("name"),
    }
    if raw.get("bom_ref"):
        component["bom-ref"] = raw["bom_ref"]
    if raw.get("version") is not None:
        component["version"] = raw["version"]
    if raw.get("purl") is not None:
        component["purl"] = raw["purl"]
    if component["type"] not in {
        "application", "framework", "library", "container", "platform",
        "operating-system", "device", "device-driver", "firmware", "file",
        "machine-learning-model", "data",
    } or not isinstance(component["name"], str) or not component["name"].strip():
        raise VEXExportConflict("product_identity_invalid")
    return component


def export_cyclonedx_vex(
    db: Session, *, release_id: int, import_id: int, assessment_id: int
) -> dict:
    """Build a deterministic VEX BOM for one accepted import and one completed run.

    No source intelligence is promoted to a manufacturer decision. Each statement
    must have a current decision, trusted author signature, independent approval,
    and a valid revision-bound evidence manifest.
    """
    release = db.get(ProductRelease, release_id)
    imported = db.get(SBOMImport, import_id)
    assessment = db.get(SBOMAssessment, assessment_id)
    if release is None:
        raise LookupError("Product release not found")
    if (
        imported is None
        or imported.product_release_id != release_id
        or imported.status != "accepted"
        or imported.format != "CycloneDX"
        or imported.spec_version != SPEC_VERSION
    ):
        raise LookupError("Accepted CycloneDX 1.5 import not found for product release")
    if (
        assessment is None
        or assessment.sbom_import_id != import_id
        or assessment.status != "complete"
    ):
        raise LookupError("Completed assessment not found for selected SBOM import")

    metadata = imported.bom_metadata or {}
    source_serial = metadata.get("serial_number")
    source_version = metadata.get("version")
    if not isinstance(source_serial, str) or not source_serial.startswith("urn:uuid:"):
        raise VEXExportConflict("source_bom_serial_number_missing")
    try:
        UUID(source_serial.removeprefix("urn:uuid:"))
    except ValueError:
        raise VEXExportConflict("source_bom_serial_number_invalid") from None
    if isinstance(source_version, bool) or not isinstance(source_version, int) or source_version < 1:
        raise VEXExportConflict("source_bom_version_invalid")
    product_component = _component_metadata(metadata.get("metadata_component"))

    components = db.scalars(
        select(SBOMComponent)
        .where(SBOMComponent.sbom_import_id == import_id)
        .order_by(SBOMComponent.ordinal, SBOMComponent.id)
    ).all()
    refs: dict[str, list[SBOMComponent]] = defaultdict(list)
    for component in components:
        if component.bom_ref:
            refs[component.bom_ref].append(component)

    findings = db.scalars(
        select(SBOMAssessmentFinding)
        .where(SBOMAssessmentFinding.assessment_id == assessment_id)
        .order_by(SBOMAssessmentFinding.id)
    ).all()

    latest_decisions: list[VulnerabilityDecision] = []
    blockers: list[dict] = []
    for finding in findings:
        component = db.get(SBOMComponent, finding.sbom_component_id)
        if component is None or component.sbom_import_id != import_id:
            blockers.append({"finding_id": finding.id, "code": "component_import_mismatch"})
            continue
        history = db.scalars(
            select(VulnerabilityDecision)
            .where(VulnerabilityDecision.assessment_finding_id == finding.id)
            .order_by(VulnerabilityDecision.revision.desc(), VulnerabilityDecision.id.desc())
        ).all()
        if not history:
            continue
        decision = history[0]
        if not component.bom_ref or len(refs.get(component.bom_ref, [])) != 1:
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "component_bom_ref_missing_or_ambiguous"})
            continue
        if not isinstance(finding.vuln_id, str) or not VULNERABILITY_ID.fullmatch(finding.vuln_id):
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "vulnerability_id_invalid"})
            continue
        if decision.state not in vulnerability_decisions.VEX_STATES:
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "analysis_state_unsupported"})
            continue
        if decision.state == "resolved_with_pedigree":
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "pedigree_evidence_not_supported"})
            continue
        if decision.justification is not None and decision.justification not in vulnerability_decisions.VEX_JUSTIFICATIONS:
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "analysis_justification_unsupported"})
            continue
        if not isinstance(decision.detail, str) or not decision.detail.strip():
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "decision_detail_missing"})
            continue

        manifest = decision_evidence.get_manifest(db, decision.id)
        if manifest is None or not manifest.get("integrity_valid"):
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "evidence_manifest_missing_or_invalid"})
            continue
        signature = decision_signatures.get_decision_signature(db, decision.id)
        if signature is None or signature.get("trust_valid") is not True:
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "author_signature_untrusted"})
            continue
        approval = decision_approvals.get_decision_approval(db, decision.id)
        if approval.get("approval_policy_satisfied") is not True:
            blockers.append({"finding_id": finding.id, "decision_id": decision.id, "code": "independent_approval_unsatisfied"})
            continue
        latest_decisions.append(decision)

    if blockers:
        raise VEXExportConflict(json.dumps({"code": "vex_export_blocked", "blockers": blockers}, sort_keys=True))

    groups: dict[str, dict] = {}
    provenance_decisions = []
    for decision in latest_decisions:
        finding = db.get(SBOMAssessmentFinding, decision.assessment_finding_id)
        component = db.get(SBOMComponent, finding.sbom_component_id)
        signature = decision_signatures.get_decision_signature(db, decision.id)
        approval = decision_approvals.get_decision_approval(db, decision.id)
        manifest = decision_evidence.get_manifest(db, decision.id)
        analysis_tuple = (
            decision.state,
            decision.justification,
            tuple(sorted(decision.responses or [])),
            decision.detail,
        )
        current = groups.get(finding.vuln_id)
        if current is not None and current["analysis_tuple"] != analysis_tuple:
            raise VEXExportConflict(json.dumps({
                "code": "conflicting_analysis_for_vulnerability",
                "vulnerability_id": finding.vuln_id,
                "decision_ids": sorted(current["decision_ids"] + [decision.id]),
            }, sort_keys=True))
        if current is None:
            current = {
                "analysis_tuple": analysis_tuple,
                "decision_ids": [],
                "refs": set(),
                "timestamps": [],
            }
            groups[finding.vuln_id] = current
        current["decision_ids"].append(decision.id)
        current["refs"].add(component.bom_ref)
        current["timestamps"].append(decision.created_at)
        provenance_decisions.append({
            "decision_id": decision.id,
            "revision": decision.revision,
            "signature_envelope_sha256": signature["current_envelope_sha256"],
            "approval_envelope_sha256": sorted(
                item["envelope_sha256"]
                for item in approval["approvals"]
                if item.get("eligible_for_current_revision") is True
            ),
            "evidence_manifest_sha256": manifest["manifest_sha256"],
        })

    vulnerabilities = []
    for vuln_id in sorted(groups):
        item = groups[vuln_id]
        state, justification, responses, detail = item["analysis_tuple"]
        timestamps = item["timestamps"]
        analysis = {
            "state": state,
            "detail": detail,
            "firstIssued": _utc_iso(min(timestamps)),
            "lastUpdated": _utc_iso(max(timestamps)),
        }
        if justification is not None:
            analysis["justification"] = justification
        if responses:
            analysis["response"] = list(responses)
        vulnerabilities.append({
            "id": vuln_id,
            "analysis": analysis,
            "affects": [{"ref": ref} for ref in sorted(item["refs"])],
        })

    provenance_decisions.sort(key=lambda item: item["decision_id"])
    provenance = {
        "source_bom_serial_number": source_serial,
        "source_bom_version": source_version,
        "source_import_id": imported.id,
        "source_import_sha256": imported.content_sha256,
        "assessment_id": assessment.id,
        "decisions": provenance_decisions,
    }
    serial_seed = {
        "source_import_sha256": imported.content_sha256,
        "assessment_id": assessment.id,
        "provenance": provenance,
    }
    document_serial = f"urn:uuid:{uuid5(EXPORT_NAMESPACE, _canonical_digest(serial_seed))}"
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": document_serial,
        "version": 1,
        "metadata": {"component": product_component},
        "vulnerabilities": vulnerabilities,
        "properties": [
            {"name": "devicetrust:source-bom-serial-number", "value": source_serial},
            {"name": "devicetrust:source-bom-version", "value": str(source_version)},
            {"name": "devicetrust:source-import-sha256", "value": imported.content_sha256},
            {"name": "devicetrust:assessment-id", "value": str(assessment.id)},
            {"name": "devicetrust:provenance-sha256", "value": _canonical_digest(provenance)},
        ],
    }
    try:
        validator = jsonschema.Draft7Validator(_load_schema(), format_checker=jsonschema.FormatChecker())
        errors = sorted(validator.iter_errors(bom), key=lambda error: list(error.path))
    except VEXSchemaUnavailable:
        raise
    if errors:
        raise VEXExportConflict(json.dumps({
            "code": "cyclonedx_schema_validation_failed",
            "errors": [
                {"path": list(error.path), "message": error.message[:300]}
                for error in errors[:20]
            ],
        }, sort_keys=True))

    canonical = rfc8785.dumps(bom)
    return {
        "bom": bom,
        "bom_sha256": hashlib.sha256(canonical).hexdigest(),
        "provenance": provenance,
        "provenance_sha256": _canonical_digest(provenance),
        "decision_count": len(latest_decisions),
        "vulnerability_count": len(vulnerabilities),
    }
