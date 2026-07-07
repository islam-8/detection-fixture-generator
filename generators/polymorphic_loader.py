"""
Polymorphic/Metamorphic Loader heuristic indicator generator (MITRE T1027.002).

Detection engines can't signature-match a polymorphic sample by hash (that
is the entire point of the technique), so real products instead alert on
*behavioral and static-heuristic proxies*: a binary hash never seen before
paired with a familiar behavioral fingerprint, section-table irregularities
consistent with a packer stub, and elevated file entropy. This generator
produces exactly those descriptive fields -- a random hash string, a
random entropy score in the range packed/encrypted sections typically
occupy, boolean anomaly flags -- for a synthetic sample.

No mutation engine, packer, or self-modifying code exists anywhere in this
project. The "hash changes every time" property of real polymorphic
malware is represented here as literally generating a new random hash
string per call, not by actually varying any executable bytes.
"""
from __future__ import annotations

import random
from typing import ClassVar

from core.models import DetectionAlert, EventCategory, Severity, T1027_002_SOFTWARE_PACKING, new_event_id
from core.timing import JitterPolicy, jittered_timestamps
from generators.base import FixtureGenerator

_LOADER_FILENAMES = ("update_helper.exe", "sysdiag_tool.exe", "cache_optimizer.exe")


class PolymorphicLoaderGenerator(FixtureGenerator):
    generator_name: ClassVar[str] = "polymorphic_loader"

    def generate(
        self, *, host: str, scenario_id: str, start_timestamp: float, rng: random.Random
    ) -> list[DetectionAlert]:
        filename = rng.choice(_LOADER_FILENAMES)
        pid = rng.randint(1000, 65000)
        novel_hash = f"sha256:{rng.randbytes(16).hex()}"
        file_entropy = round(rng.uniform(7.2, 7.98), 3)  # near-random-data range typical of packed/encrypted sections
        behavioral_fingerprint = f"bx-{rng.randbytes(4).hex()}"  # stands in for a vendor's behavioral-clustering ID

        timestamps = jittered_timestamps(
            start_timestamp, count=2, policy=JitterPolicy(base_interval_seconds=0.2, jitter_seconds=0.1), rng=rng
        )

        return [
            DetectionAlert(
                event_id=new_event_id(), timestamp=timestamps[0], host=host, category=EventCategory.FILE,
                severity=Severity.MEDIUM, technique=T1027_002_SOFTWARE_PACKING,
                title="Executable with high section entropy and no known-good hash",
                description=f"{filename} (PID {pid}) has file entropy {file_entropy} bits/byte -- consistent with "
                             "a packed or encrypted section -- and its hash does not match any previously observed "
                             "or allow-listed binary.",
                process_id=pid, process_name=filename,
                fields={
                    "file_hash": novel_hash, "file_entropy_bits_per_byte": file_entropy,
                    "entropy_baseline_bits_per_byte": 6.0, "hash_previously_seen": False,
                    "import_table_anomaly": rng.choice([True, False]),
                },
                scenario_id=scenario_id,
            ),
            DetectionAlert(
                event_id=new_event_id(), timestamp=timestamps[1], host=host, category=EventCategory.FILE,
                severity=Severity.HIGH, technique=T1027_002_SOFTWARE_PACKING,
                title="Novel hash matches a known behavioral fingerprint",
                description=f"Although the hash for {filename} has never been seen before, its runtime behavior "
                             f"clusters against known-bad behavioral fingerprint {behavioral_fingerprint} -- "
                             "consistent with a polymorphic/metamorphic sample whose static signature changes "
                             "per-build while its functional behavior stays constant.",
                process_id=pid, process_name=filename,
                fields={
                    "file_hash": novel_hash, "behavioral_fingerprint": behavioral_fingerprint,
                    "static_signature_match": False, "behavioral_signature_match": True,
                },
                scenario_id=scenario_id,
            ),
        ]
