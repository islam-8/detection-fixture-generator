"""
CLI for the Detection Fixture Generator.

    fixtures generate full_chain --host WKSTN-4471 --out incident.jsonl
    fixtures replay full_chain --host WKSTN-4471 --out live_feed.jsonl --base-interval 2 --jitter 1
    fixtures list-scenarios
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path

from core.timing import JitterPolicy
from replay import replay_to_jsonl_file
from scenario_factory import ScenarioFactory, ScenarioType


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fixtures", description="EDR/SIEM detection fixture generator")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate", help="Write a scenario's alerts to a JSONL file immediately")
    generate.add_argument("scenario", choices=[s.value for s in ScenarioType])
    generate.add_argument("--host", default="WKSTN-0001")
    generate.add_argument("--seed", type=int, default=None, help="Deterministic RNG seed for reproducible fixtures")
    generate.add_argument("--out", type=Path, default=Path("./fixtures.jsonl"))

    replay = subparsers.add_parser("replay", help="Emit a scenario's alerts to a JSONL file at jittered real-time intervals")
    replay.add_argument("scenario", choices=[s.value for s in ScenarioType])
    replay.add_argument("--host", default="WKSTN-0001")
    replay.add_argument("--seed", type=int, default=None)
    replay.add_argument("--out", type=Path, default=Path("./live_feed.jsonl"))
    replay.add_argument("--base-interval", type=float, default=2.0, help="Average seconds between emitted events")
    replay.add_argument("--jitter", type=float, default=1.0, help="Max +/- random jitter, in seconds")

    subparsers.add_parser("list-scenarios", help="List available scenario types")

    return parser


def cmd_generate(args: argparse.Namespace) -> int:
    scenario_type = ScenarioType(args.scenario)
    alerts = ScenarioFactory.create(scenario_type, host=args.host, seed=args.seed)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as fh:
        for alert in alerts:
            fh.write(json.dumps(alert.to_dict()) + "\n")
    print(f"wrote {len(alerts)} alert(s) for scenario '{args.scenario}' to {args.out}")
    return 0


async def cmd_replay(args: argparse.Namespace) -> int:
    scenario_type = ScenarioType(args.scenario)
    alerts = ScenarioFactory.create(scenario_type, host=args.host, seed=args.seed, start_timestamp=time.time())
    pacing = JitterPolicy(base_interval_seconds=args.base_interval, jitter_seconds=args.jitter)
    print(f"replaying {len(alerts)} alert(s) to {args.out} (~{args.base_interval}s +/-{args.jitter}s apart)...")
    await replay_to_jsonl_file(alerts, args.out, pacing)
    print("done")
    return 0


def cmd_list_scenarios(_args: argparse.Namespace) -> int:
    for name in ScenarioFactory.available_scenarios():
        print(f"  - {name}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "generate":
        return cmd_generate(args)
    if args.command == "replay":
        return asyncio.run(cmd_replay(args))
    if args.command == "list-scenarios":
        return cmd_list_scenarios(args)

    parser.error(f"unknown command {args.command!r}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
