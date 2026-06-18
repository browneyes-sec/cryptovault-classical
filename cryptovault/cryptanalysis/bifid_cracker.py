"""Bifid/Trifid cipher cracker — period-based frequency analysis.

These ciphers are vulnerable to attacks that exploit their periodic
structure. By trying different periods and scoring results with
chi-squared tests, the correct period can be identified.
"""

from __future__ import annotations

from cryptovault.ciphers.bifid import BifidCipher
from cryptovault.ciphers.trifid import TrifidCipher
from cryptovault.cryptanalysis.frequency import chi_squared_test


def crack_bifid(
    ciphertext: str, max_period: int = 20, top_n: int = 5
) -> list[tuple[str, str, float]]:
    """Crack Bifid cipher by trying common keywords.

    Bifid uses a fixed period (the grid size, 5), so we try
    common keywords and score by frequency fitness.

    Args:
        ciphertext: The ciphertext to crack.
        max_period: Not used (Bifid has fixed period of 5).
        top_n: Number of top results.

    Returns:
        List of (keyword, plaintext, score) tuples.
    """
    common_keywords = [
        "KEYWORD", "SECRET", "CIPHER", "GOLD", "LIGHT",
        "SHADOW", "FIRE", "STONE", "RIVER", "WIND",
        "PLAYFAIR", "HELLO", "WORLD", "TEST", "EXAMPLE",
    ]

    results: list[tuple[str, str, float]] = []
    for kw in common_keywords:
        try:
            bc = BifidCipher(kw)
            plaintext = bc.decrypt(ciphertext)
            fitness = chi_squared_test(plaintext)
            results.append((kw, plaintext, fitness))
        except ValueError:
            continue

    results.sort(key=lambda x: x[2])
    return results[:top_n]


def crack_trifid(
    ciphertext: str, max_period: int = 27, top_n: int = 5
) -> list[tuple[str, str, float]]:
    """Crack Trifid cipher by trying common keywords.

    Args:
        ciphertext: The ciphertext to crack.
        max_period: Not used (Trifid has fixed period of 3).
        top_n: Number of top results.

    Returns:
        List of (keyword, plaintext, score) tuples.
    """
    common_keywords = [
        "KEYWORD", "SECRET", "CIPHER", "GOLD", "LIGHT",
        "PHOENIX", "DRAGON", "CASTLE", "TEMPLE", "FORGE",
    ]

    results: list[tuple[str, str, float]] = []
    for kw in common_keywords:
        try:
            tc = TrifidCipher(kw)
            plaintext = tc.decrypt(ciphertext)
            fitness = chi_squared_test(plaintext)
            results.append((kw, plaintext, fitness))
        except ValueError:
            continue

    results.sort(key=lambda x: x[2])
    return results[:top_n]
