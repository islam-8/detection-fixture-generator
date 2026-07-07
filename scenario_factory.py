"""
Scenario factory (Factory pattern).

A "scenario" is a named, ordered combination of FixtureGenerators sharing
one host, one scenario_id, and an ascending timeline -- representing what
a SOC would see across a single synthetic incident's stages, e.g. a
dropper's arrival, its in-memory injection, and its subsequent C2 beacon.
This is what makes the output useful for testing *correlation* rules and
IR playbooks, not just single-alert detection logic.
"""
from __future__ import annotations

import random
import time
import uuid
from enum import Enum

from core.models import DetectionAlert
from generators.base import FixtureGenerator
from generators.dns_tunneling import DnsTunnelingGenerator
from generators.polymorphic_loader import PolymorphicLoaderGenerator
from generators.process_injection import ProcessHollowingGenerator
from generators.protocol_anomaly import ProtocolAnomalyGenerator


class ScenarioType(Enum):
    NETWORK_EXPLOIT_ATTEMPT_BLOCKED = "network_exploit_attempt_blocked"
    FILELESS_INTRUSION = "fileless_intrusion"
    PACKED_DROPPER_WITH_C2 = "packed_dropper_with_c2"
    FULL_CHAIN = "full_chain"


# Each scenario is just an ordered list of generator instances -- the
# factory's whole job is running them in sequence with a shared identity.
_SCENARIO_STAGES: dict[ScenarioType, list[FixtureGenerator]] = {
    ScenarioType.NETWORK_EXPLOIT_ATTEMPT_BLOCKED: [ProtocolAnomalyGenerator()],
    ScenarioType.FILELESS_INTRUSION: [ProcessHollowingGenerator(), DnsTunnelingGenerator()],
    ScenarioType.PACKED_DROPPER_WITH_C2: [PolymorphicLoaderGenerator(), DnsTunnelingGenerator()],
    ScenarioType.FULL_CHAIN: [
        ProtocolAnomalyGenerator(), PolymorphicLoaderGenerator(), ProcessHollowingGenerator(), DnsTunnelingGenerator(),
    ],
}

_STAGE_GAP_SECONDS = 45.0  # rough real-world gap between distinct kill-chain stages, not per-alert jitter


class ScenarioFactory:
    """Builds a full, correlated incident timeline for a named scenario type."""

    @staticmethod
    def available_scenarios() -> list[str]:
        return [s.value for s in ScenarioType]

    @staticmethod
    def create(
        scenario_type: ScenarioType, host: str, seed: int | None = None, start_timestamp: float | None = None,
    ) -> list[DetectionAlert]:
        rng = random.Random(seed)
        scenario_id = str(uuid.uuid4())
        cursor = start_timestamp if start_timestamp is not None else time.time()

        alerts: list[DetectionAlert] = []
        for generator in _SCENARIO_STAGES[scenario_type]:
            stage_alerts = generator.generate(host=host, scenario_id=scenario_id, start_timestamp=cursor, rng=rng)
            alerts.extend(stage_alerts)
            if stage_alerts:
                cursor = stage_alerts[-1].timestamp + _STAGE_GAP_SECONDS
        return alerts
