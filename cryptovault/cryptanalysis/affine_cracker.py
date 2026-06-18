"""Affine cipher cracker — brute-force over all valid (a, b) pairs.

The Affine cipher has 12 × 26 = 312 possible keys (12 values of a
coprime with 26, 26 values of b). Brute-force is trivial.
"""

from __future__ import annotations

import math
from cryptovault.ciphers.affine import AffineCipher, _VALID_A_VALUES
from cryptovault.cryptanalysis.frequency import chi_squared_test


def crack_affine(ciphertext: str, top_n: int = 5) -> list[tuple[str, str, float]]:
    """Brute-force all 312 Affine cipher keys.

    Args:
        ciphertext: The ciphertext to crack.
        top_n: Number of top results to return.

    Returns:
        List of (key, plaintext, chi_squared) tuples, sorted best-first.
    """
    cipher = AffineCipher(1, 0)
    results: list[tuple[str, str, float]] = []

    for a in _VALID_A_VALUES:
        for b in range(26):
            key_str = f"{a},{b}"
            plaintext = cipher.decrypt(ciphertext, key_str)
            fitness = chi_squared_test(plaintext)
            results.append((key_str, plaintext, fitness))

    results.sort(key=lambda x: x[2])
    return results[:top_n]


def crack_affine_with_known_plaintext(
    ciphertext: str, known_plaintext: str
) -> list[tuple[str, str, float]]:
    """Crack Affine by testing all keys against known plaintext.

    Args:
        ciphertext: The ciphertext to crack.
        known_plaintext: Known or guessed plaintext fragment.

    Returns:
        List of (key, plaintext, match_ratio) tuples.
    """
    cipher = AffineCipher(1, 0)
    results: list[tuple[str, str, float]] = []

    for a in _VALID_A_VALUES:
        for b in range(26):
            key_str = f"{a},{b}"
            plaintext = cipher.decrypt(ciphertext, key_str)

            matches = 0
            checked = 0
            for i in range(min(len(known_plaintext), len(plaintext))):
                if known_plaintext[i].isalpha():
                    if known_plaintext[i].lower() == plaintext[i].lower():
                        matches += 1
                    checked += 1

            ratio = matches / checked if checked > 0 else 0.0
            results.append((key_str, plaintext, ratio))

    results.sort(key=lambda x: x[2], reverse=True)
    return results
