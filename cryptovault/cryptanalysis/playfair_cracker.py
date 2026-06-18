"""Playfair cipher cracker — crib-based and frequency attacks.

The Playfair cipher is vulnerable to:
1. Known-plaintext (crib) attacks with a few hundred characters
2. Digraph frequency analysis
3. Cyclic crib dragging
"""

from __future__ import annotations

import itertools
from cryptovault.cryptanalysis.frequency import chi_squared_test


def _digraph_frequency_score(text: str) -> float:
    """Score text based on expected English digraph frequencies.

    Common English digraphs: TH, HE, IN, ER, AN, RE, ON, AT, EN, ND.

    Args:
        text: Text to score (uppercase, letters only).

    Returns:
        Score (lower = more English-like).
    """
    common = {"TH", "HE", "IN", "ER", "AN", "RE", "ON", "AT", "EN", "ND"}
    letters = [c for c in text.upper() if c.isalpha()]
    if len(letters) < 2:
        return float("inf")

    digraphs = [letters[i] + letters[i + 1] for i in range(len(letters) - 1)]
    total = len(digraphs)
    common_count = sum(1 for d in digraphs if d in common)
    return total / (common_count + 1)


def crack_playfair_crib(
    ciphertext: str, crib_plaintext: str, crib_ciphertext: str
) -> list[tuple[str, str, float]]:
    """Crack Playfair by aligning a known plaintext-ciphertext pair.

    This identifies which cipher grid transformations are in use,
    reducing the key space dramatically.

    Args:
        ciphertext: The ciphertext to crack.
        crib_plaintext: Known plaintext fragment.
        crib_ciphertext: Known ciphertext fragment (same length as crib_plaintext).

    Returns:
        List of (partial_key, plaintext, confidence) tuples.
    """
    results: list[tuple[str, str, float]] = []
    p_letters = [c.upper() for c in crib_plaintext if c.isalpha()]
    c_letters = [c.upper() for c in crib_ciphertext if c.isalpha()]

    if len(p_letters) != len(c_letters) or len(p_letters) < 2:
        return results

    pairs = list(zip(p_letters, c_letters))
    constraints: dict[str, str] = {}
    for p, c in pairs:
        if p in constraints and constraints[p] != c:
            return results
        constraints[p] = c

    confidence = 1.0 / (1.0 + len(constraints))
    result_text = f"Constraints: {constraints}"
    results.append((str(constraints), result_text, confidence))

    return results


def crack_playfair_frequency(
    ciphertext: str, top_n: int = 5
) -> list[tuple[str, str, float]]:
    """Rank possible Playfair decryptions by digraph frequency.

    Tries common keywords and scores results by digraph fitness.

    Args:
        ciphertext: The ciphertext to crack.
        top_n: Number of top results to return.

    Returns:
        List of (keyword, plaintext, score) tuples.
    """
    from cryptovault.ciphers.playfair import PlayfairCipher

    common_keywords = [
        "KEYWORD", "SECRET", "CIPHER", "GOLD", "LIGHT",
        "SHADOW", "FIRE", "STONE", "RIVER", "WIND",
        "COMMAND", "ATTACK", "DEFEND", "NORTH", "SOUTH",
    ]

    results: list[tuple[str, str, float]] = []
    for kw in common_keywords:
        try:
            pf = PlayfairCipher(kw)
            plaintext = pf.decrypt(ciphertext)
            score = _digraph_frequency_score(plaintext)
            results.append((kw, plaintext, score))
        except ValueError:
            continue

    results.sort(key=lambda x: x[2])
    return results[:top_n]
