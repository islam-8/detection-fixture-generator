"""
Process Hollowing indicator generator (MITRE T1055.012).

What real EDR products actually alert on for this technique -- and all
this generator produces -- is a cluster of *behavioral deviations*
observable from outside the process, without ever needing to touch a
target process's memory:
  - a process was created in a suspended state, then had its primary
    thread's context altered before resuming (observable via ETW/kernel
    callbacks, not something this code performs)
  - the module later mapped into that process's address space doesn't
    match the on-disk image the process was launched from (a hash/path
    mismatch, which this generator represents as two string fields that
    intentionally differ -- it never loads or maps anything)
  - a memory region became executable after being writable, with no
    backing file (the classic "unbacked executable memory" heuristic)

This module builds a small Python dict describing each of those flags. It
does not call CreateProcess, does not touch any real address space, and
does not use ctypes for anything -- it is a values-only description of
what a real EDR's telemetry schema for this technique looks like.
"""
from __future__ import annotations

import random
from typing import ClassVar

from core.models import (
    DetectionAlert, EventCategory, Severity, T1055_012_PROCESS_HOLLOWING, new_event_id,
)
from core.timing import JitterPolicy, jittered_timestamps
from generators.base import FixtureGenerator

_LEGITIMATE_HOST_PROCESSES = ("svchost.exe", "explorer.exe", "rundll32.exe", "werfault.exe")
_SPOOFED_PARENTS = ("services.exe", "winlogon.exe", "wininit.exe")


class ProcessHollowingGenerator(FixtureGenerator):
    generator_name: ClassVar[str] = "process_hollowing"

    def generate(
        self, *, host: str, scenario_id: str, start_timestamp: float, rng: random.Random
    ) -> list[DetectionAlert]:
        target_process = rng.choice(_LEGITIMATE_HOST_PROCESSES)
        parent_process = rng.choice(_SPOOFED_PARENTS)
        pid = rng.randint(1000, 65000)
        parent_pid = rng.randint(400, 999)

        timestamps = jittered_timestamps(
            start_timestamp, count=3, policy=JitterPolicy(base_interval_seconds=0.3, jitter_seconds=0.15), rng=rng
        )

        on_disk_hash = f"sha256:{rng.randbytes(8).hex()}..."
        mapped_hash = f"sha256:{rng.randbytes(8).hex()}..."  # deliberately different string -- represents a mismatch

        return [
            DetectionAlert(
                event_id=new_event_id(), timestamp=timestamps[0], host=host, category=EventCategory.PROCESS,
                severity=Severity.MEDIUM, technique=T1055_012_PROCESS_HOLLOWING,
                title="Process created in suspended state",
                description=f"{parent_process} (PID {parent_pid}) spawned {target_process} (PID {pid}) with "
                             "CREATE_SUSPENDED; suspended launches followed by thread-context modification are a "
                             "known precursor to hollowing.",
                process_id=pid, process_name=target_process, parent_process_id=parent_pid,
                fields={"creation_flags": "CREATE_SUSPENDED", "stage": 1, "total_stages": 3},
                scenario_id=scenario_id,
            ),
            DetectionAlert(
                event_id=new_event_id(), timestamp=timestamps[1], host=host, category=EventCategory.MEMORY,
                severity=Severity.HIGH, technique=T1055_012_PROCESS_HOLLOWING,
                title="Executable memory region with no backing file",
                description=f"PID {pid} contains a memory region marked PAGE_EXECUTE_READWRITE that is not "
                             "backed by any mapped file on disk -- code is present in memory that was never "
                             "loaded from an executable image.",
                process_id=pid, process_name=target_process, parent_process_id=parent_pid,
                fields={
                    "memory_protection": "PAGE_EXECUTE_READWRITE", "region_backed_by_file": False,
                    "region_size_bytes": rng.choice([4096, 8192, 65536, 131072]), "stage": 2, "total_stages": 3,
                },
                scenario_id=scenario_id,
            ),
            DetectionAlert(
                event_id=new_event_id(), timestamp=timestamps[2], host=host, category=EventCategory.PROCESS,
                severity=Severity.CRITICAL, technique=T1055_012_PROCESS_HOLLOWING,
                title="On-disk image hash does not match mapped image",
                description=f"The executable on disk for PID {pid} ({target_process}) does not match the hash "
                             "of what is actually mapped into its address space -- strong indicator the original "
                             "image was hollowed out and replaced.",
                process_id=pid, process_name=target_process, parent_process_id=parent_pid,
                fields={
                    "on_disk_hash": on_disk_hash, "mapped_image_hash": mapped_hash, "hash_mismatch": True,
                    "stage": 3, "total_stages": 3,
                },
                scenario_id=scenario_id,
            ),
        ]
