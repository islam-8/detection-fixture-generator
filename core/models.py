"""
Core data models for the Detection Fixture Generator.

Everything in this module describes the *shape of an alert* -- the fields
a SIEM or EDR console would show an analyst -- never the mechanics of a
technique. There is no code anywhere in this project that performs process
injection, encodes data into DNS queries, mutates its own bytecode, or
crafts a malformed packet. It generates the telemetry a detection engine
would already have produced if those things happened, so detection rules,
correlation logic, and IR playbooks can be tested against realistic,
schema-consistent data without a live technique ever running.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class EventCategory(Enum):
    PROCESS = "process"
    NETWORK_DNS = "network_dns"
    FILE = "file"
    MEMORY = "memory"
    PROTOCOL_ANOMALY = "protocol_anomaly"


@dataclass(frozen=True, slots=True)
class MitreTechnique:
    """A reference to a public MITRE ATT&CK technique ID -- documentation
    metadata only, used to tag *why* a synthetic alert looks the way it
    does, exactly the way a real EDR product labels its detections."""

    technique_id: str
    name: str

    def __str__(self) -> str:
        return f"{self.technique_id} ({self.name})"


# A small, illustrative reference set -- not exhaustive, not a technique
# implementation guide. See https://attack.mitre.org for the full matrix.
T1055_012_PROCESS_HOLLOWING = MitreTechnique("T1055.012", "Process Hollowing")
T1071_004_DNS_C2 = MitreTechnique("T1071.004", "Application Layer Protocol: DNS")
T1027_002_SOFTWARE_PACKING = MitreTechnique("T1027.002", "Obfuscated Files or Information: Software Packing")
T1499_002_PROTOCOL_EXPLOIT = MitreTechnique("T1499", "Endpoint Denial of Service")  # nearest public parent for protocol-parser anomalies


@dataclass(slots=True)
class DetectionAlert:
    """A single synthetic alert record, shaped like what an EDR/SIEM console
    or JSONL export would actually contain: identity, correlation keys,
    the technique it's meant to represent, and a bag of detection-specific
    fields (never technique *mechanics* -- see each generator's docstring)."""

    event_id: str
    timestamp: float
    host: str
    category: EventCategory
    severity: Severity
    technique: MitreTechnique
    title: str
    description: str
    process_id: int | None = None
    process_name: str | None = None
    parent_process_id: int | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    scenario_id: str | None = None  # correlates multiple alerts into one synthetic incident

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "host": self.host,
            "category": self.category.value,
            "severity": self.severity.value,
            "technique_id": self.technique.technique_id,
            "technique_name": self.technique.name,
            "title": self.title,
            "description": self.description,
            "process_id": self.process_id,
            "process_name": self.process_name,
            "parent_process_id": self.parent_process_id,
            "fields": self.fields,
            "scenario_id": self.scenario_id,
        }


def new_event_id() -> str:
    return str(uuid.uuid4())
