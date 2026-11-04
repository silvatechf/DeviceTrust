"""Deterministic, side-effect-free normalization for selected evidence attributes."""

import re
from dataclasses import dataclass
from ipaddress import ip_address

NORMALIZER_VERSION = "1.0.0"

ATTRIBUTE_ALIASES = {
    "manufacturer": "identity.manufacturer",
    "identity.manufacturer": "identity.manufacturer",
    "model": "identity.model",
    "identity.model": "identity.model",
    "serial_number": "identity.serial_number",
    "identity.serial_number": "identity.serial_number",
    "mac_address": "network.mac_address",
    "network.mac_address": "network.mac_address",
    "ip_address": "network.ip_address",
    "network.ip_address": "network.ip_address",
    "hostname": "network.hostname",
    "network.hostname": "network.hostname",
    "firmware_version": "firmware.version",
    "firmware.version": "firmware.version",
    "secure_boot": "security.secure_boot",
    "security.secure_boot": "security.secure_boot",
    "firmware_signed": "security.firmware_signed",
    "security.firmware_signed": "security.firmware_signed",
    "internet_exposed": "management.internet_exposed",
    "management.internet_exposed": "management.internet_exposed",
}

_BOOLEAN_VALUES = {
    "true": "true",
    "1": "true",
    "yes": "true",
    "enabled": "true",
    "false": "false",
    "0": "false",
    "no": "false",
    "disabled": "false",
}
_HOSTNAME_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass(frozen=True)
class NormalizedEvidence:
    source_attribute: str
    canonical_attribute: str | None
    raw_value: str
    normalized_value: str | None
    normalizer_version: str
    error: str | None = None


def _normalize_value(attribute: str, value: str) -> str:
    if attribute == "network.mac_address":
        candidate = value.strip()
        if re.fullmatch(r"[0-9A-Fa-f]{12}", candidate):
            compact = candidate
        elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", candidate):
            compact = candidate.replace(":", "")
        elif re.fullmatch(r"(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}", candidate):
            compact = candidate.replace("-", "")
        else:
            raise ValueError("invalid MAC address")
        return ":".join(compact[index:index + 2] for index in range(0, 12, 2)).lower()

    if attribute == "network.ip_address":
        try:
            return str(ip_address(value.strip()))
        except ValueError:
            raise ValueError("invalid IP address") from None

    if attribute in {
        "security.secure_boot",
        "security.firmware_signed",
        "management.internet_exposed",
    }:
        normalized = _BOOLEAN_VALUES.get(value.strip().lower())
        if normalized is None:
            raise ValueError("ambiguous boolean value")
        return normalized

    if attribute == "network.hostname":
        hostname = value.strip()
        if hostname.endswith("."):
            hostname = hostname[:-1]
        if not hostname or len(hostname) > 253 or any(
            not _HOSTNAME_LABEL.fullmatch(label) for label in hostname.split(".")
        ):
            raise ValueError("invalid hostname")
        return hostname.lower()

    # Identity and firmware strings remain opaque; do not guess vendor semantics.
    return value


def normalize_observation(attribute: str, value: str) -> NormalizedEvidence:
    """Return a normalized projection while preserving the submitted raw value."""
    canonical = ATTRIBUTE_ALIASES.get(attribute)
    if canonical is None:
        return NormalizedEvidence(
            source_attribute=attribute,
            canonical_attribute=None,
            raw_value=value,
            normalized_value=None,
            normalizer_version=NORMALIZER_VERSION,
        )

    try:
        normalized = _normalize_value(canonical, value)
    except ValueError as error:
        return NormalizedEvidence(
            source_attribute=attribute,
            canonical_attribute=canonical,
            raw_value=value,
            normalized_value=None,
            normalizer_version=NORMALIZER_VERSION,
            error=str(error),
        )

    return NormalizedEvidence(
        source_attribute=attribute,
        canonical_attribute=canonical,
        raw_value=value,
        normalized_value=normalized,
        normalizer_version=NORMALIZER_VERSION,
    )
