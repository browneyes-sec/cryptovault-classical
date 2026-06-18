"""Rail Fence cipher cracker — brute-force over rail count.

The Rail Fence cipher has a small key space (number of rails),
typically 2-20. Brute-forcing all possibilities and ranking by
IoC or chi-squared is effective.
"""

from __future__ import annotations

from cryptovault.ciphers.railfence import RailFenceCipher
from cryptovault.cryptanalysis.frequency import chi_squared_test
from cryptovault.cryptanalysis.index_of_coincidence import index_of_coincidence


def crack_railfence(ciphertext: str, max_rails: int = 20, top_n: int = 5) -> list[tuple[int, str, float]]:
    """Brute-force Rail Fence cipher over all possible rail counts.

    Args:
        ciphertext: The ciphertext to crack.
        max_rails: Maximum number of rails to try.
        top_n: Number of top results to return.

    Returns:
        List of (rails, plaintext, chi_squared) tuples, sorted best-first.
    """
    results: list[tuple[int, str, float]] = []

    for rails in range(2, min(max_rails + 1, len(ciphertext))):
        try:
            rf = RailFenceCipher(rails)
            plaintext = rf.decrypt(ciphertext)
            fitness = chi_squared_test(plaintext)
            results.append((rails, plaintext, fitness))
        except ValueError:
            continue

    results.sort(key=lambda x: x[2])
    return results[:top_n]


def crack_railfence_by_ioc(ciphertext: str, max_rails: int = 20) -> int:
    """Estimate best rail count using Index of Coincidence.

    The correct rail count produces plaintext with IoC closest to
    English (~0.065).

    Args:
        ciphertext: The ciphertext to analyze.
        max_rails: Maximum number of rails to try.

    Returns:
        Best rail count.
    """
    best_rails = 2
    best_ioc = 0.0

    for rails in range(2, min(max_rails + 1, len(ciphertext))):
        try:
            rf = RailFenceCipher(rails)
            plaintext = rf.decrypt(ciphertext)
            ioc = index_of_coincidence(plaintext)
            if ioc > best_ioc:
                best_ioc = ioc
                best_rails = rails
        except ValueError:
            continue

    return best_rails
