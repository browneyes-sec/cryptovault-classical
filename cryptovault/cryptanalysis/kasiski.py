"""Kasiski examination for Vigenère cipher key recovery.

The Kasiski examination (1863) finds repeated trigrams in ciphertext
to determine the key length. Once the key length is known, each
column can be treated as a Caesar cipher and broken independently.
"""

from __future__ import annotations

import string
from collections import Counter
from math import gcd
from functools import reduce

from cryptovault.cryptanalysis.frequency import ENGLISH_FREQ


def kasiski_examination(ciphertext: str, min_trigram_len: int = 3) -> list[int]:
    """Find repeated trigrams and compute GCD-based key length candidates.

    Args:
        ciphertext: The ciphertext to analyze.
        min_trigram_len: Minimum length of repeated pattern to search for.

    Returns:
        List of candidate key lengths, sorted by frequency (most likely first).
    """
    alpha_only = "".join(c.lower() for c in ciphertext if c.isalpha())

    if len(alpha_only) < min_trigram_len + 2:
        return []

    distances: list[int] = []

    for trigram_len in range(min_trigram_len, min(6, len(alpha_only) // 2) + 1):
        seen: dict[str, list[int]] = {}
        for i in range(len(alpha_only) - trigram_len + 1):
            trigram = alpha_only[i : i + trigram_len]
            if trigram in seen:
                for prev_pos in seen[trigram]:
                    distances.append(i - prev_pos)
                seen[trigram].append(i)
            else:
                seen[trigram] = [i]

    if not distances:
        return []

    def gcd_list(nums: list[int]) -> int:
        return reduce(gcd, nums)

    overall_gcd = gcd_list(distances) if distances else 1

    candidate_counts: Counter[int] = Counter()
    for d in distances:
        for k in range(2, min(21, d + 1)):
            if d % k == 0:
                candidate_counts[k] += 1

    for k in range(2, 21):
        if k % overall_gcd == 0 and overall_gcd > 1:
            candidate_counts[k] += 5

    sorted_candidates = [k for k, _ in candidate_counts.most_common()]
    return sorted_candidates


def estimate_key_length(ciphertext: str) -> int:
    """Estimate Vigenère key length using combined Kasiski + IoC analysis.

    Args:
        ciphertext: The ciphertext to analyze.

    Returns:
        Most probable key length (1-20).
    """
    from cryptovault.cryptanalysis.index_of_coincidence import average_ioc_by_columns

    candidates = kasiski_examination(ciphertext)

    if not candidates:
        best_kl = 1
        best_ioc = 0.0
        for kl in range(1, min(21, len(ciphertext) // 3 + 1)):
            avg_ioc = average_ioc_by_columns(ciphertext, kl)
            if avg_ioc > best_ioc:
                best_ioc = avg_ioc
                best_kl = kl
        return best_kl

    best_kl = candidates[0]
    best_score = 0.0

    for kl in candidates[:10]:
        avg_ioc = average_ioc_by_columns(ciphertext, kl)
        rank_bonus = 1.0 / (candidates.index(kl) + 1)
        score = avg_ioc + rank_bonus * 0.01
        if score > best_score:
            best_score = score
            best_kl = kl

    return best_kl


def _frequency_score(column: str) -> float:
    """Score a single column against English frequency (lower = more English-like).

    Args:
        column: Single column of ciphertext characters.

    Returns:
        Chi-squared statistic.
    """
    n = len(column)
    if n == 0:
        return float("inf")

    counts = Counter(column)
    chi_sq = 0.0
    for ch in string.ascii_lowercase:
        expected = ENGLISH_FREQ[ch] * n
        obs = counts.get(ch, 0)
        if expected > 0:
            chi_sq += (obs - expected) ** 2 / expected
    return chi_sq


def recover_key(ciphertext: str, key_length: int) -> str:
    """Recover the Vigenère key by brute-forcing each column as a Caesar cipher.

    Args:
        ciphertext: The Vigenère ciphertext.
        key_length: The estimated key length.

    Returns:
        Recovered key string.
    """
    alpha_only = [c.lower() for c in ciphertext if c.isalpha()]

    if key_length <= 0 or len(alpha_only) < key_length:
        msg = f"Invalid key_length {key_length} for ciphertext of length {len(alpha_only)}"
        raise ValueError(msg)

    columns: list[str] = [""] * key_length
    for i, ch in enumerate(alpha_only):
        columns[i % key_length] += ch

    key_chars: list[str] = []
    for col in columns:
        best_shift = 0
        best_score = float("inf")

        for shift in range(26):
            shifted = "".join(
                chr((ord(c) - ord("a") - shift) % 26 + ord("a")) for c in col
            )
            score = _frequency_score(shifted)
            if score < best_score:
                best_score = score
                best_shift = shift

        key_chars.append(chr(ord("a") + best_shift))

    return "".join(key_chars)
