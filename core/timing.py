"""
Timestamp jitter utility for realistic synthetic event pacing.

Real operational telemetry never arrives at perfectly uniform intervals.
This is used two ways in this project:
  1. When batch-generating a scenario's alerts, jitter spaces out their
     `timestamp` fields so a correlation rule under test sees realistic
     inter-event gaps instead of identical or robotically-even timestamps.
  2. In replay.py's async live-feed mode, the *actual* asyncio.sleep()
     between emitted events is jittered the same way, to test whether a
     SIEM's ingestion pipeline and time-window correlation rules behave
     correctly against non-uniform arrival timing.

This is pacing for synthetic test data quality, not traffic-shaping to
evade a live defender -- there is no target system on the other end here,
only a file or local test sink the operator controls.
"""
from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(slots=True)
class JitterPolicy:
    base_interval_seconds: float = 2.0
    jitter_seconds: float = 1.0
    min_interval_seconds: float = 0.05

    def __post_init__(self) -> None:
        if self.base_interval_seconds < 0 or self.jitter_seconds < 0:
            raise ValueError("intervals must be non-negative")

    def next_interval(self, rng: random.Random) -> float:
        interval = self.base_interval_seconds + rng.uniform(-self.jitter_seconds, self.jitter_seconds)
        return max(interval, self.min_interval_seconds)


def jittered_timestamps(start: float, count: int, policy: JitterPolicy, rng: random.Random) -> list[float]:
    """Produce `count` ascending timestamps starting at `start`, spaced by
    policy.next_interval() each step."""
    timestamps = [start]
    for _ in range(count - 1):
        timestamps.append(timestamps[-1] + policy.next_interval(rng))
    return timestamps
