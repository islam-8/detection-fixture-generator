"""
Protocol/parser anomaly indicator generator -- the IPS-side detection for
malformed-packet and parser-exploitation attempts (e.g. the class of bugs
behind zero-click issues like declared-length-vs-actual-length mismatches
or malformed chunked structures).

This generates the alert an IPS/IDS (Suricata/Snort-style) or an
application-layer parser's own exception telemetry would emit *after*
rejecting a malformed input -- field names like declared_length,
actual_length, and parser_exception_type. It does not construct malformed
packets, does not implement any wire-format parser, and does not target
any integer-overflow or buffer condition. The byte-length numbers below
are independent random integers chosen to *look like* a plausible
length-mismatch in a log line, not values derived from or usable to
reconstruct a working malformed payload.
"""
from __future__ import annotations

import random
from typing import ClassVar

from core.models import (
    DetectionAlert, EventCategory, Severity, T1499_002_PROTOCOL_EXPLOIT, new_event_id,
)
from generators.base import FixtureGenerator

_PROTOCOLS = ("image/heif-chunk-parser", "mms-baseband-frame", "custom-binary-rpc")


class ProtocolAnomalyGenerator(FixtureGenerator):
    generator_name: ClassVar[str] = "protocol_anomaly"

    def generate(
        self, *, host: str, scenario_id: str, start_timestamp: float, rng: random.Random
    ) -> list[DetectionAlert]:
        protocol = rng.choice(_PROTOCOLS)
        declared_length = rng.randint(4096, 65536)
        actual_length = declared_length + rng.randint(1, 4096)  # declared-vs-actual mismatch, the anomaly signal itself
        source_ip = f"198.51.100.{rng.randint(2, 254)}"  # TEST-NET-2 (RFC 5737): always non-routable, safe in examples

        return [
            DetectionAlert(
                event_id=new_event_id(), timestamp=start_timestamp, host=host,
                category=EventCategory.PROTOCOL_ANOMALY, severity=Severity.CRITICAL,
                technique=T1499_002_PROTOCOL_EXPLOIT,
                title=f"Malformed {protocol} payload rejected by parser guard",
                description=f"Inbound {protocol} data from {source_ip} declared a field length of "
                             f"{declared_length} bytes but the actual payload segment measured {actual_length} "
                             "bytes -- the parser's bounds check rejected the input before allocating a buffer. "
                             "This is the class of anomaly associated with zero-click parser-exploitation "
                             "attempts; the guard functioned as intended here.",
                fields={
                    "protocol": protocol, "source_ip": source_ip, "declared_length_bytes": declared_length,
                    "actual_length_bytes": actual_length, "length_delta_bytes": actual_length - declared_length,
                    "parser_action": "rejected", "parser_exception_type": "LengthBoundsViolation",
                },
                scenario_id=scenario_id,
            )
        ]
