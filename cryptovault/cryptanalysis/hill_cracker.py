"""Hill cipher cracker — known-plaintext matrix recovery.

The Hill cipher is completely broken with n² known plaintext-ciphertext
pairs (where n is the matrix dimension), since the key matrix can be
recovered by solving a system of linear equations over Z_26.
"""

from __future__ import annotations

from cryptovault.ciphers.hill import HillCipher, _matrix_mod_inverse, _matrix_multiply_mod


def crack_hill_known_plaintext(
    ciphertext: str, plaintext: str, n: int = 3
) -> list[tuple[str, str, float]]:
    """Crack Hill cipher using known plaintext-ciphertext pair.

    Args:
        ciphertext: The ciphertext.
        plaintext: Known plaintext (must be >= n² chars).
        n: Matrix dimension (2 or 3).

    Returns:
        List of (key_matrix, plaintext, confidence) tuples.
    """
    p_letters = [c.upper() for c in plaintext if c.isalpha()]
    c_letters = [c.upper() for c in ciphertext if c.isalpha()]

    required = n * n
    if len(p_letters) < required or len(c_letters) < required:
        return []

    p_matrix: list[list[int]] = []
    for i in range(n):
        row = [ord(p_letters[i * n + j]) - ord("A") for j in range(n)]
        p_matrix.append(row)

    c_matrix: list[list[int]] = []
    for i in range(n):
        row = [ord(c_letters[i * n + j]) - ord("A") for j in range(n)]
        c_matrix.append(row)

    try:
        p_inv = _matrix_mod_inverse(p_matrix)
        key_matrix = [[0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                key_matrix[i][j] = sum(
                    c_matrix[i][k] * p_inv[k][j] for k in range(n)
                ) % 26

        cipher = HillCipher(key_matrix)
        recovered = cipher.decrypt(ciphertext)
        return [(str(key_matrix), recovered, 1.0)]
    except (ValueError, ZeroDivisionError):
        return []


def crack_hill_brute_force_2x2(ciphertext: str, top_n: int = 5) -> list[tuple[str, str, float]]:
    """Brute-force all invertible 2×2 matrices mod 26.

    There are approximately 44,000 invertible 2×2 matrices mod 26.

    Args:
        ciphertext: The ciphertext to crack.
        top_n: Number of top results to return.

    Returns:
        List of (key, plaintext, chi_squared) tuples.
    """
    import math
    from cryptovault.cryptanalysis.frequency import chi_squared_test

    results: list[tuple[str, str, float]] = []

    for a in range(26):
        for b in range(26):
            for c in range(26):
                for d in range(26):
                    det = (a * d - b * c) % 26
                    if math.gcd(det, 26) != 1:
                        continue
                    key_matrix = [[a, b], [c, d]]
                    try:
                        cipher = HillCipher(key_matrix)
                        plaintext = cipher.decrypt(ciphertext)
                        fitness = chi_squared_test(plaintext)
                        results.append((str(key_matrix), plaintext, fitness))
                    except (ValueError, ZeroDivisionError):
                        continue

    results.sort(key=lambda x: x[2])
    return results[:top_n]
