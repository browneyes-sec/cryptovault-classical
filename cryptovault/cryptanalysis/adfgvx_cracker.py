"""ADFGVX cipher cracker — crib-based columnar reconstruction.

The ADFGVX cipher combines Polybius substitution with columnar
transposition. Known-plaintext attacks can recover the transposition
key, and frequency analysis can break the Polybius square.
"""

from __future__ import annotations

from cryptovault.ciphers.adfgvx import ADFGVXCipher
from cryptovault.cryptanalysis.frequency import chi_squared_test


def crack_adfgvx_crib(
    ciphertext: str, crib: str, max_trans_key_len: int = 10
) -> list[tuple[str, str, float]]:
    """Crack ADFGVX by testing transposition key lengths with a crib.

    Args:
        ciphertext: The ADFGVX ciphertext.
        crib: Known plaintext fragment.
        max_trans_key_len: Maximum transposition key length to try.

    Returns:
        List of (key, plaintext, score) tuples.
    """
    results: list[tuple[str, str, float]] = []
    cipher_letters = [c for c in ciphertext.upper() if c in "ADFGVX"]

    for trans_len in range(2, min(max_trans_key_len + 1, len(cipher_letters) // 2)):
        for poly_key in ["SECRET", "KEYWORD", "CIPHER", "GOLD", "LIGHT"]:
            trans_key = "A" * trans_len
            key_str = f"{poly_key},{trans_key}"
            try:
                ac = ADFGVXCipher(poly_key, trans_key)
                plaintext = ac.decrypt(ciphertext, key_str)

                if crib.upper() in plaintext.upper():
                    fitness = chi_squared_test(plaintext)
                    results.append((key_str, plaintext, fitness))
            except (ValueError, IndexError):
                continue

    results.sort(key=lambda x: x[2])
    return results[:5]


def crack_adfgvx_frequency(
    ciphertext: str, top_n: int = 5
) -> list[tuple[str, str, float]]:
    """Crack ADFGVX by trying common Polybius keys with frequency scoring.

    Args:
        ciphertext: The ADFGVX ciphertext.
        top_n: Number of top results.

    Returns:
        List of (key, plaintext, score) tuples.
    """
    common_poly_keys = [
        "SECRET", "KEYWORD", "CIPHER", "GOLD", "LIGHT",
        "SHADOW", "FIRE", "STONE", "RIVER", "WIND",
    ]
    common_trans_keys = [
        "CARGO", "ROUTE", "PATH", "KEY", "DELTA",
        "ALPHA", "BRAVO", "SCOUT", "RAIDER", "HAWK",
    ]

    results: list[tuple[str, str, float]] = []
    for pk in common_poly_keys:
        for tk in common_trans_keys:
            try:
                ac = ADFGVXCipher(pk, tk)
                plaintext = ac.decrypt(ciphertext)
                fitness = chi_squared_test(plaintext)
                key_str = f"{pk},{tk}"
                results.append((key_str, plaintext, fitness))
            except (ValueError, IndexError):
                continue

    results.sort(key=lambda x: x[2])
    return results[:top_n]
