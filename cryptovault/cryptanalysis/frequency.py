"""English letter frequency analysis and chi-squared fitness testing.

Used to score plaintext candidates during brute-force attacks.
English text has a characteristic letter frequency distribution
(ETAOINSHRDLCUMWFGYPBVKJXQZ) that differs significantly from
random or ciphertext distributions.
"""

from __future__ import annotations

import math
from collections import Counter

# Expected English letter frequencies (from large corpora)
ENGLISH_FREQ: dict[str, float] = {
    "a": 0.08167,
    "b": 0.01492,
    "c": 0.02782,
    "d": 0.04253,
    "e": 0.12702,
    "f": 0.02228,
    "g": 0.02015,
    "h": 0.06094,
    "i": 0.06966,
    "j": 0.00153,
    "k": 0.00772,
    "l": 0.04025,
    "m": 0.02406,
    "n": 0.06749,
    "o": 0.07507,
    "p": 0.01929,
    "q": 0.00095,
    "r": 0.05987,
    "s": 0.06327,
    "t": 0.09056,
    "u": 0.02758,
    "v": 0.00978,
    "w": 0.02360,
    "x": 0.00150,
    "y": 0.01974,
    "z": 0.00074,
}


def frequency_analysis(text: str) -> dict[str, float]:
    """Compute normalized letter frequency distribution of text.

    Args:
        text: Input text (case-insensitive, non-alpha chars ignored).

    Returns:
        Dict mapping each letter (a-z) to its relative frequency (0.0-1.0).
    """
    lower = text.lower()
    alpha_chars = [c for c in lower if c.isalpha()]
    total = len(alpha_chars)

    if total == 0:
        return {ch: 0.0 for ch in "abcdefghijklmnopqrstuvwxyz"}

    counts = Counter(alpha_chars)
    return {ch: counts.get(ch, 0) / total for ch in "abcdefghijklmnopqrstuvwxyz"}


def chi_squared_test(text: str) -> float:
    """Compute chi-squared statistic against English frequency distribution.

    Lower values indicate text that more closely matches English.
    Used to rank brute-force candidates (best fitness = lowest chi-squared).

    Args:
        text: Input text to evaluate.

    Returns:
        Chi-squared statistic (lower is more English-like).
    """
    observed = frequency_analysis(text)
    n = sum(obs * 1 for obs in observed.values())

    if n == 0:
        return float("inf")

    chi_sq = 0.0
    for ch in "abcdefghijklmnopqrstuvwxyz":
        expected = ENGLISH_FREQ[ch] * n
        obs = observed[ch] * n
        if expected > 0:
            chi_sq += (obs - expected) ** 2 / expected

    return chi_sq


def frequency_table(text: str) -> str:
    """Generate a formatted frequency table for display.

    Args:
        text: Input text to analyze.

    Returns:
        Multi-line string with letter frequencies as a bar chart.
    """
    freq = frequency_analysis(text)
    sorted_letters = sorted(freq.items(), key=lambda x: x[1], reverse=True)

    lines: list[str] = []
    for ch, f in sorted_letters:
        bar_len = int(f * 50)
        bar = "█" * bar_len
        lines.append(f"  {ch} {f:.4f} {bar}")

    return "\n".join(lines)
