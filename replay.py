"""
Async live-feed replay emitter via Network Sockets (UDP Syslog Integration).
"""
from __future__ import annotations

import asyncio
import json
import random
import socket
from pathlib import Path
from typing import Awaitable, Callable

from core.models import DetectionAlert
from core.timing import JitterPolicy

Sink = Callable[[DetectionAlert], Awaitable[None]]

async def replay_to_sink(
    alerts: list[DetectionAlert], sink: Sink, pacing: JitterPolicy, rng: random.Random | None = None
) -> None:
    """Emit `alerts` to `sink` one at a time, sleeping a jittered interval between each."""
    rng = rng or random.Random()
    for index, alert in enumerate(alerts):
        await sink(alert)
        if index < len(alerts) - 1:
            await asyncio.sleep(pacing.next_interval(rng))

async def replay_to_syslog_and_file(
    alerts: list[DetectionAlert], path: Path, pacing: JitterPolicy, host: str = "127.0.0.1", port: int = 514, rng: random.Random | None = None
) -> None:
    """
    Advanced Sink: Appends alert to a local JSONL file AND streams it immediately 
    over a live UDP socket to a local Syslog/SIEM collector (rsyslog).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    with path.open("a", encoding="utf-8") as file_handle:

        async def _network_and_file_sink(alert: DetectionAlert) -> None:
            alert_dict = alert.to_dict()
            payload = json.dumps(alert_dict)
            
            file_handle.write(payload + "\n")
            file_handle.flush()
            
            syslog_message = f"<14>1 {alert_dict.get('timestamp')} {alert_dict.get('host')} EDR_ALERT - - - {payload}"
            sock.sendto(syslog_message.encode("utf-8"), (host, port))

        await replay_to_sink(alerts, _network_and_file_sink, pacing, rng)
    
    sock.close()

async def replay_to_jsonl_file(
    alerts: list[DetectionAlert], path: Path, pacing: JitterPolicy, rng: random.Random | None = None
) -> None:
    await replay_to_syslog_and_file(alerts, path, pacing, rng=rng)
