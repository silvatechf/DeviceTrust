"""Evidence-based posture assessment with explicit unknown states."""
from datetime import date

RANK = {"low": 1, "medium": 2, "high": 3}
INSECURE_IFACES = {"telnet", "ftp", "http", "tftp", "snmpv1", "snmpv2c"}
CRA = "CRA Annex I Part I"  # Informative mapping only; not a compliance claim.
CRA_UPD = "CRA Annex I Part I / Part II"


def _finding(control, status, evidence, why, risk, action, ref=CRA):
    return {
        "control": control,
        "status": status,
        "evidence": evidence,
        "justification": why,
        "risk": risk,
        "recommendation": action,
        "cra_reference": ref,
    }


def _unknown(control, fields, ref=CRA):
    return _finding(
        control,
        "unverified",
        {key: None for key in fields},
        "Evidence not provided; cannot be assumed compliant.",
        "unknown",
        f"Provide: {', '.join(fields)}.",
        ref,
    )


def assess(device: dict) -> dict:
    security = device["security"]
    today = date.today()
    findings = []

    identity = {
        "unique_identity": security.get("unique_identity"),
        "authentication": security.get("authentication"),
    }
    if identity["unique_identity"] is None:
        findings.append(_unknown("device_identification", ["unique_identity"]))
    elif not identity["unique_identity"]:
        findings.append(_finding(
            "device_identification", "non_compliant", identity,
            "Device lacks a unique identity.", "high",
            "Provision unique per-device identity.",
        ))
    elif identity["authentication"] == "device_certificate":
        findings.append(_finding(
            "device_identification", "compliant", identity,
            "Unique identity bound to a device certificate.", "low", "None.",
        ))
    else:
        findings.append(_finding(
            "device_identification", "partial", identity,
            "Unique ID exists but is not cryptographically bound.", "medium",
            "Use per-device X.509 certificates.",
        ))

    insecure = sorted(
        {item.lower() for item in (security.get("open_interfaces") or [])}
        & INSECURE_IFACES
    )
    config_evidence = {
        "default_credentials": security.get("default_credentials"),
        "open_interfaces": security.get("open_interfaces"),
        "insecure_interfaces": insecure,
    }
    default_credentials = security.get("default_credentials")
    open_interfaces = security.get("open_interfaces")
    if default_credentials is True:
        findings.append(_finding(
            "secure_configuration", "non_compliant", config_evidence,
            "Shipped with default credentials.", "high",
            "Force unique credentials at first use.",
        ))
    elif insecure:
        findings.append(_finding(
            "secure_configuration", "partial", config_evidence,
            f"Insecure interfaces declared: {', '.join(insecure)}.",
            "medium", "Disable or replace with encrypted equivalents.",
        ))
    elif default_credentials is None or open_interfaces is None:
        findings.append(_unknown(
            "secure_configuration", ["default_credentials", "open_interfaces"]
        ))
    else:
        findings.append(_finding(
            "secure_configuration", "compliant", config_evidence,
            "No default credentials or insecure interfaces declared.",
            "low", "None.",
        ))

    management = security.get("management_interfaces")
    exposed_management = [
        item for item in (management or [])
        if item.get("internet_exposed") is True
    ]
    device_exposed = security.get("internet_exposed")
    exposure_evidence = {
        "internet_exposed": device_exposed,
        "management_interfaces": management,
        "internet_exposed_management_interfaces": exposed_management,
    }
    if device_exposed is True or exposed_management:
        findings.append(_finding(
            "network_exposure", "non_compliant", exposure_evidence,
            "A device or management interface is declared internet-exposed.",
            "high",
            "Remove direct internet reachability; use network segmentation and a controlled remote-access gateway.",
        ))
    elif (
        device_exposed is False
        and management is not None
        and all(item.get("internet_exposed") is False for item in management)
    ):
        findings.append(_finding(
            "network_exposure", "compliant", exposure_evidence,
            "Declared evidence indicates no direct internet exposure for the device or listed management interfaces.",
            "low",
            "Revalidate exposure periodically and retain evidence provenance.",
        ))
    else:
        findings.append(_unknown(
            "network_exposure", ["internet_exposed", "management_interfaces"]
        ))

    transit = security.get("encryption_in_transit")
    at_rest = security.get("encryption_at_rest")
    crypto_evidence = {
        "encryption_in_transit": transit,
        "encryption_at_rest": at_rest,
    }
    if transit is None and at_rest is None:
        findings.append(_unknown("data_protection", list(crypto_evidence)))
    elif transit is False:
        findings.append(_finding(
            "data_protection", "non_compliant", crypto_evidence,
            "Data travels unencrypted.", "high", "Enforce TLS 1.2+/DTLS.",
        ))
    elif transit and at_rest:
        findings.append(_finding(
            "data_protection", "compliant", crypto_evidence,
            "Protected in transit and at rest.", "low", "None.",
        ))
    else:
        findings.append(_finding(
            "data_protection", "partial", crypto_evidence,
            "Only partial data protection evidenced.", "medium",
            "Cover both transit and storage.",
        ))

    authentication = security.get("authentication")
    auth_evidence = {"authentication": authentication}
    if authentication is None:
        findings.append(_unknown("interface_access_control", ["authentication"]))
    elif authentication in ("none", "password_default"):
        findings.append(_finding(
            "interface_access_control", "non_compliant", auth_evidence,
            "Interfaces lack effective authentication.", "high",
            "Require strong per-device authentication.",
        ))
    elif authentication == "password_custom":
        findings.append(_finding(
            "interface_access_control", "partial", auth_evidence,
            "Password-only authentication.", "medium",
            "Add certificates or MFA for management.",
        ))
    else:
        findings.append(_finding(
            "interface_access_control", "compliant", auth_evidence,
            "Certificate-based authentication.", "low", "None.",
        ))

    mechanism = security.get("update_mechanism")
    support_until = device.get("support_until")
    support_expired = bool(support_until and support_until < today)
    update_evidence = {
        "update_mechanism": mechanism,
        "support_until": str(support_until) if support_until else None,
        "support_expired": support_expired,
    }
    if mechanism is None:
        findings.append(_unknown(
            "secure_software_update", ["update_mechanism"], CRA_UPD
        ))
    elif mechanism == "none" or support_expired:
        reason = "Support period ended." if support_expired else "No update mechanism."
        findings.append(_finding(
            "secure_software_update", "non_compliant", update_evidence,
            reason, "high",
            "Provide signed updates and a documented support policy.",
            CRA_UPD,
        ))
    elif mechanism == "automatic_signed":
        findings.append(_finding(
            "secure_software_update", "compliant", update_evidence,
            "Signed automatic updates within support period.", "low",
            "None.", CRA_UPD,
        ))
    else:
        findings.append(_finding(
            "secure_software_update", "partial", update_evidence,
            f"Update mechanism '{mechanism}' lacks signed automation.",
            "medium", "Move to signed automatic updates.", CRA_UPD,
        ))

    logging = security.get("logging_enabled")
    logging_evidence = {"logging_enabled": logging}
    if logging is None:
        findings.append(_unknown("security_state_awareness", ["logging_enabled"]))
    elif logging:
        findings.append(_finding(
            "security_state_awareness", "compliant", logging_evidence,
            "Security-relevant events are logged.", "low", "None.",
        ))
    else:
        findings.append(_finding(
            "security_state_awareness", "non_compliant", logging_evidence,
            "No security logging.", "medium",
            "Emit security events to the platform.",
        ))

    secure_boot = security.get("secure_boot")
    firmware_signed = security.get("firmware_signed")
    integrity_evidence = {
        "secure_boot": secure_boot,
        "firmware_signed": firmware_signed,
    }
    if secure_boot is None and firmware_signed is None:
        findings.append(_unknown("device_integrity", list(integrity_evidence)))
    elif secure_boot and firmware_signed:
        findings.append(_finding(
            "device_integrity", "compliant", integrity_evidence,
            "Secure boot and signed firmware.", "low", "None.",
        ))
    elif secure_boot is False and firmware_signed is False:
        findings.append(_finding(
            "device_integrity", "non_compliant", integrity_evidence,
            "No integrity protection.", "high",
            "Enable secure boot and firmware signing.",
        ))
    else:
        findings.append(_finding(
            "device_integrity", "partial", integrity_evidence,
            "Integrity protection incomplete or unverified.", "medium",
            "Complete both measures.",
        ))

    counts = {}
    for item in findings:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    ranked = [RANK[item["risk"]] for item in findings if item["risk"] in RANK]
    highest_risk = {value: key for key, value in RANK.items()}[max(ranked)] if ranked else "unknown"
    verified = len(findings) - counts.get("unverified", 0)
    return {
        "device_id": device["device_id"],
        "controls": findings,
        "summary": counts,
        "highest_risk": highest_risk,
        "evidence_coverage": f"{verified}/{len(findings)}",
        "disclaimer": "Supports assessment and documentation; it does not certify CRA compliance.",
    }
