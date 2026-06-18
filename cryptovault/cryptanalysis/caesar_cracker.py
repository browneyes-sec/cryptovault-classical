"""Caesar cipher cracker — brute-force and frequency-based attacks.

The Caesar cipher has only 26 possible keys, making brute-force
trivial. Frequency analysis improves ranking by selecting the shift
that produces text closest to English letter distribution.
"""

from __future__ import annotations

from cryptovault.ciphers.caesar import CaesarCipher, brute_force_caesar
from cryptovault.cryptanalysis.frequency import chi_squared_test, frequency_analysis


def crack_caesar(ciphertext: str) -> tuple[int, str, float]:
    """Crack Caesar cipher by returning the best shift.

    Uses chi-squared fitness against English frequency distribution.

    Args:
        ciphertext: The ciphertext to crack.

    Returns:
        Tuple of (best_shift, plaintext, confidence).
        Confidence is inverse chi-squared (higher = better).
    """
    results = brute_force_caesar(ciphertext)
    best_shift, best_plaintext, best_chi = results[0]

    confidence = 1.0 / (1.0 + best_chi)

    return best_shift, best_plaintext, confidence


def crack_caesar_with_known_plaintext(
    ciphertext: str, known_plaintext: str
) -> list[tuple[int, str, float]]:
    """Crack Caesar by testing all shifts against known plaintext fragment.

    Args:
        ciphertext: The ciphertext to crack.
        known_plaintext: A known or guessed plaintext fragment.

    Returns:
        List of (shift, plaintext, match_ratio) tuples where match_ratio
        is the fraction of positions matching the known fragment.
    """
    cipher = CaesarCipher(0)
    results: list[tuple[int, str, float]] = []

    for shift in range(26):
        plaintext = cipher.decrypt(ciphertext, shift)

        matches = 0
        checked = 0
        for i in range(min(len(known_plaintext), len(plaintext))):
            if known_plaintext[i].isalpha():
                if known_plaintext[i].lower() == plaintext[i].lower():
                    matches += 1
                checked += 1

        ratio = matches / checked if checked > 0 else 0.0
        results.append((shift, plaintext, ratio))

    results.sort(key=lambda x: x[2], reverse=True)
    return results
