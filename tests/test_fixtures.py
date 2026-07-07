"""
Test suite for the Detection Fixture Generator. Pure Python, no external
services required. Run with: python3 tests/test_fixtures.py
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.entropy import random_high_entropy_label, random_low_entropy_label, shannon_entropy  # noqa: E402
from core.timing import JitterPolicy, jittered_timestamps  # noqa: E402
from replay import replay_to_sink  # noqa: E402
from scenario_factory import ScenarioFactory, ScenarioType  # noqa: E402

FAILURES: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)
        print(f"  FAILED: {message}")
    else:
        print(f"  ok: {message}")


def test_entropy() -> None:
    print("\n[entropy]")
    check(shannon_entropy("") == 0.0, "empty string has zero entropy")
    check(shannon_entropy("aaaaaaaa") == 0.0, "a single repeated character has zero entropy")
    check(abs(shannon_entropy("ab") - 1.0) < 1e-9, "two equally likely symbols -> exactly 1 bit of entropy")

    import random
    rng = random.Random(1)
    low = random_low_entropy_label(rng)
    high = random_high_entropy_label(rng)
    check(shannon_entropy(high) > shannon_entropy(low), "high-entropy label scores higher than low-entropy label")


def test_timing() -> None:
    print("\n[timing]")
    import random
    rng = random.Random(2)
    policy = JitterPolicy(base_interval_seconds=1.0, jitter_seconds=0.5, min_interval_seconds=0.05)
    timestamps = jittered_timestamps(1000.0, 10, policy, rng)
    check(len(timestamps) == 10, "produces the requested number of timestamps")
    check(timestamps == sorted(timestamps), "timestamps are strictly ascending")
    check(timestamps[0] == 1000.0, "first timestamp matches the requested start")
    gaps = [b - a for a, b in zip(timestamps, timestamps[1:])]
    check(all(g >= policy.min_interval_seconds for g in gaps), "no gap falls below the configured floor")
    check(any(abs(g - policy.base_interval_seconds) > 1e-9 for g in gaps), "jitter actually varies the gaps (not all identical)")


def test_scenarios() -> None:
    print("\n[scenarios]")
    for scenario_type in ScenarioType:
        alerts = ScenarioFactory.create(scenario_type, host="TEST-HOST", seed=123, start_timestamp=5000.0)
        check(len(alerts) > 0, f"{scenario_type.value}: produces at least one alert")
        check(len({a.scenario_id for a in alerts}) == 1, f"{scenario_type.value}: single shared scenario_id")
        check(all(a.host == "TEST-HOST" for a in alerts), f"{scenario_type.value}: all alerts tagged with the requested host")
        timestamps = [a.timestamp for a in alerts]
        check(timestamps == sorted(timestamps), f"{scenario_type.value}: ascending timeline")

    a1 = ScenarioFactory.create(ScenarioType.FULL_CHAIN, host="H", seed=99, start_timestamp=0.0)
    a2 = ScenarioFactory.create(ScenarioType.FULL_CHAIN, host="H", seed=99, start_timestamp=0.0)
    check(
        [a.to_dict() for a in a1 if True] and
        [(a.title, a.timestamp) for a in a1] == [(a.title, a.timestamp) for a in a2],
        "identical seed + start_timestamp reproduces an identical timeline (deterministic fixtures)",
    )

    json_blob = json.dumps([a.to_dict() for a in a1])
    reloaded = json.loads(json_blob)
    check(len(reloaded) == len(a1), "full alert set round-trips through JSON")


async def test_replay_pacing() -> None:
    print("\n[replay pacing]")
    alerts = ScenarioFactory.create(ScenarioType.NETWORK_EXPLOIT_ATTEMPT_BLOCKED, host="H", seed=1, start_timestamp=0.0)
    alerts += ScenarioFactory.create(ScenarioType.NETWORK_EXPLOIT_ATTEMPT_BLOCKED, host="H", seed=2, start_timestamp=0.0)
    received: list[float] = []

    import time as time_module

    async def sink(alert) -> None:
        received.append(time_module.monotonic())

    policy = JitterPolicy(base_interval_seconds=0.15, jitter_seconds=0.05, min_interval_seconds=0.05)
    start = time_module.monotonic()
    await replay_to_sink(alerts, sink, policy)
    elapsed = time_module.monotonic() - start

    check(len(received) == len(alerts), "sink received every alert")
    expected_min = policy.min_interval_seconds * (len(alerts) - 1)
    check(elapsed >= expected_min, f"replay took at least the minimum expected wall-clock time ({elapsed:.2f}s >= {expected_min:.2f}s)")


async def main() -> None:
    test_entropy()
    test_timing()
    test_scenarios()
    await test_replay_pacing()

    print()
    if FAILURES:
        print(f"=== {len(FAILURES)} CHECK(S) FAILED ===")
        for message in FAILURES:
            print(f"  - {message}")
        sys.exit(1)
    print("=== ALL CHECKS PASSED ===")


if __name__ == "__main__":
    asyncio.run(main())
