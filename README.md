# Detection Fixture Generator

Generates structured, correlated, MITRE ATT&CK-tagged synthetic alerts —
the telemetry a detection engine (EDR/SIEM) would already produce for
specific attack techniques — for testing detection rules, correlation
logic, and IR playbooks against realistic data.

## What this is, and what it deliberately is not

Every field in every generated alert is descriptive metadata: process
names, entropy scores, byte-length deltas, boolean anomaly flags. **No
technique is actually implemented anywhere in this project**:

- `process_injection.py` never touches a real process or memory address
  space — it produces the *fields* a hollowing detector would populate.
- `dns_tunneling.py` never encodes or recovers data through DNS — the
  high-entropy labels are random noise used only to give the
  `entropy_score` field a realistic value.
- `polymorphic_loader.py` contains no mutation engine or packer — the
  "changes every run" property of real polymorphic malware is represented
  by literally generating a new random hash string per call.
- `protocol_anomaly.py` builds no malformed packets and implements no
  wire-format parser — it generates the alert a parser's bounds check
  would emit *after* rejecting bad input.

If you need this for red-team/purple-team exercises that actually execute
techniques against live infrastructure, that's a different, much more
sensitive category of tooling with its own authorization requirements —
this project intentionally stays on the "synthetic telemetry" side of that
line.

## Architecture

```
detection_fixture_generator/
├── core/
│   ├── models.py     # DetectionAlert, Severity, EventCategory, MitreTechnique
│   ├── entropy.py    # Shannon entropy (standard stats, used for realistic score fields)
│   └── timing.py     # Jitter policy for realistic timestamp/pacing
├── generators/
│   ├── base.py                  # FixtureGenerator interface (Strategy pattern)
│   ├── process_injection.py     # T1055.012 Process Hollowing indicators
│   ├── dns_tunneling.py         # T1071.004 DNS C2 beacon indicators
│   ├── polymorphic_loader.py    # T1027.002 Software Packing heuristics
│   └── protocol_anomaly.py      # Malformed-payload / parser-guard alerts
├── scenario_factory.py   # Factory pattern: correlates generators into a multi-stage incident
├── replay.py             # Async jittered live-feed emitter (paces writes to a local sink)
├── cli.py                # generate / replay / list-scenarios
└── tests/test_fixtures.py
```

**Strategy pattern**: every generator implements the same
`generate(host, scenario_id, start_timestamp, rng) -> list[DetectionAlert]`
contract (`generators/base.py`), so `scenario_factory.py` never needs to
know which specific technique it's assembling.

**Factory pattern**: `ScenarioFactory` maps a `ScenarioType` to an ordered
list of generator instances and runs them with one shared `scenario_id`,
one host, and an ascending timeline — e.g. `FULL_CHAIN` produces a
protocol-exploit-attempt alert, a dropper-execution alert pair, a
hollowing sequence, and a DNS-beacon pair, all correlatable as one
synthetic incident.

## Running it

```bash
python3 tests/test_fixtures.py     # no dependencies beyond the standard library

python3 cli.py list-scenarios
python3 cli.py generate full_chain --host WKSTN-4471 --seed 42 --out incident.jsonl
python3 cli.py replay fileless_intrusion --host SRV-DC01 --out live_feed.jsonl \
    --base-interval 2 --jitter 1
```

`generate` writes every alert immediately. `replay` uses `asyncio.sleep`
between writes, jittered per `core/timing.py`, so an ingestion pipeline
under test sees events arrive at a realistic, non-uniform pace instead of
one instantaneous batch — useful for testing time-window correlation
rules. The sink is always a local file (or, via `replay.replay_to_sink`,
any async callback you supply) — nothing here opens a connection to a
third party.

## Determinism

Pass `--seed` to get byte-for-byte reproducible fixtures — useful for
regression-testing detection rules ("this exact incident must always
trigger this exact alert"). Omit it for fresh randomized data each run.
