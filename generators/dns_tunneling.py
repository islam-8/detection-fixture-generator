"""
DNS Tunneling / C2-over-DNS indicator generator (MITRE T1071.004).

What flags this technique to a real detection engine is *statistical
shape*, not packet content -- query-name entropy, query volume/frequency
per host, unusual record-type mix, and NXDOMAIN ratio. This generator
computes exactly those descriptive statistics over locally-generated
random labels (core/entropy.py's random_high_entropy_label) and packages
them as alert fields.

It does not implement a tunnel: nothing here maps arbitrary input bytes
into a DNS query and nothing recovers bytes back out of one. The
high-entropy labels exist only so the entropy_score field has a realistic
value to show a detection rule under test -- they don't encode anything.
"""
from __future__ import annotations

import random
from typing import ClassVar

from core.entropy import random_high_entropy_label, shannon_entropy
from core.models import DetectionAlert, EventCategory, Severity, T1071_004_DNS_C2, new_event_id
from core.timing import JitterPolicy, jittered_timestamps
from generators.base import FixtureGenerator

_C2_LOOKALIKE_DOMAINS = ("update-cdn-cache.net", "telemetry-sync.info", "static-assets-edge.com")


class DnsTunnelingGenerator(FixtureGenerator):
    generator_name: ClassVar[str] = "dns_tunneling"

    def generate(
        self, *, host: str, scenario_id: str, start_timestamp: float, rng: random.Random
    ) -> list[DetectionAlert]:
        parent_domain = rng.choice(_C2_LOOKALIKE_DOMAINS)
        query_count = rng.randint(40, 120)  # abnormal volume for a single host in the observation window

        sample_labels = [random_high_entropy_label(rng, length=rng.randint(32, 55)) for _ in range(5)]
        avg_entropy = sum(shannon_entropy(label) for label in sample_labels) / len(sample_labels)
        sample_query = f"{sample_labels[0]}.{parent_domain}"

        nxdomain_ratio = round(rng.uniform(0.6, 0.9), 2)  # tunneling clients often mistype/rotate subdomains

        timestamps = jittered_timestamps(
            start_timestamp, count=2, policy=JitterPolicy(base_interval_seconds=1.0, jitter_seconds=0.4), rng=rng
        )

        return [
            DetectionAlert(
                event_id=new_event_id(), timestamp=timestamps[0], host=host, category=EventCategory.NETWORK_DNS,
                severity=Severity.HIGH, technique=T1071_004_DNS_C2,
                title="Anomalous DNS query volume to a single parent domain",
                description=f"{host} issued {query_count} distinct subdomain queries against {parent_domain} in "
                             "the observation window -- volume and uniqueness far exceed normal resolver caching "
                             "patterns for legitimate CDN/telemetry traffic.",
                fields={
                    "parent_domain": parent_domain, "query_count_in_window": query_count,
                    "window_seconds": 300, "sample_query": sample_query, "query_type": rng.choice(["TXT", "A", "CNAME"]),
                },
                scenario_id=scenario_id,
            ),
            DetectionAlert(
                event_id=new_event_id(), timestamp=timestamps[1], host=host, category=EventCategory.NETWORK_DNS,
                severity=Severity.HIGH, technique=T1071_004_DNS_C2,
                title="High-entropy DNS query labels with elevated NXDOMAIN ratio",
                description=f"Subdomain labels queried against {parent_domain} average {avg_entropy:.2f} bits/char "
                             "of Shannon entropy (baseline for legitimate hostnames is typically well under 3.0), "
                             f"and {int(nxdomain_ratio * 100)}% resolved NXDOMAIN -- consistent with "
                             "encoded-data-as-subdomain tunneling rather than organic browsing/CDN lookups.",
                fields={
                    "average_entropy_bits_per_char": round(avg_entropy, 3), "entropy_baseline_bits_per_char": 3.0,
                    "nxdomain_ratio": nxdomain_ratio, "sample_high_entropy_labels": sample_labels,
                },
                scenario_id=scenario_id,
            ),
        ]
