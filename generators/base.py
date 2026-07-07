"""
Abstract interface for technique-specific fixture generators (Strategy pattern).

Each concrete generator produces a short, correlated sequence of
DetectionAlert records representing what a detection engine would log for
one stage of a synthetic incident. Subclasses only ever populate
*descriptive fields* (process names, entropy scores, anomaly flags,
byte-length deltas) -- see each module's docstring for the exact
detection-relevant fields it models and why.
"""
from __future__ import annotations

import random
from abc import ABC, abstractmethod
from typing import ClassVar

from core.models import DetectionAlert


class FixtureGenerator(ABC):
    """Base class for all technique-specific alert generators."""

    generator_name: ClassVar[str] = "unnamed_generator"

    @abstractmethod
    def generate(self, *, host: str, scenario_id: str, start_timestamp: float, rng: random.Random) -> list[DetectionAlert]:
        """Return one or more correlated DetectionAlert records for this technique,
        anchored at start_timestamp on the given host and tagged with scenario_id
        so downstream tooling can group them into a single synthetic incident."""
        raise NotImplementedError
