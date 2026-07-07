"""
Shannon entropy utility.

Real detection engines score strings (DNS labels, filenames, command
lines) by entropy because high-entropy text is a common side effect of
encoding/encryption/compression -- this is standard, publicly documented
detection-engineering math (the same formula used in any statistics
textbook), not something specific to any attack technique. Used here only
to populate a realistic `entropy_score` field on synthetic alerts.
"""
from __future__ import annotations

import math
import random
import string
from collections import Counter


def shannon_entropy(text: str) -> float:
    """Standard Shannon entropy in bits per character. Higher = less predictable."""
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def random_low_entropy_label(rng: random.Random, length: int = 10) -> str:
    """A label that looks like an ordinary hostname/subdomain -- low entropy,
    for generating realistic *benign* baseline traffic alongside anomalies."""
    return "".join(rng.choices(string.ascii_lowercase, k=length))


def random_high_entropy_label(rng: random.Random, length: int = 42) -> str:
    """A label with the statistical shape of encoded/compressed data (base32-ish
    alphabet, uniform character distribution) -- for populating the
    `entropy_score` field on a synthetic DNS-tunneling alert. This produces
    random noise, not an encode/decode capability: nothing here maps
    arbitrary bytes into this string or recovers bytes back out of it."""
    alphabet = string.ascii_lowercase + "234567"  # RFC 4648 base32 alphabet shape
    return "".join(rng.choices(alphabet, k=length))
