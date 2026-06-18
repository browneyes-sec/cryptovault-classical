"""Hill cipher — polygraphic substitution using linear algebra.

Vulnerability: Known-plaintext attack (n² known plaintext-ciphertext
pairs recover the n×n key matrix).

The Hill cipher encrypts blocks of n letters using matrix multiplication
mod 26. The key is an n×n invertible matrix over Z_26.
"""

from __future__ import annotations

import math
import string

from cryptovault.ciphers.base import CipherBase


def _mod_inverse(a: int, m: int = 26) -> int:
    """Compute modular inverse of a mod m.

    Args:
        a: The integer.
        m: The modulus.

    Returns:
        Modular inverse.

    Raises:
        ValueError: If no inverse exists.
    """
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        msg = f"No modular inverse for {a} mod {m}"
        raise ValueError(msg)
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm."""
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


def _matrix_mod_inverse(matrix: list[list[int]], mod: int = 26) -> list[list[int]]:
    """Compute the inverse of a matrix mod m.

    Uses the adjugate matrix method: A^{-1} = det(A)^{-1} * adj(A) mod m.

    Args:
        matrix: n×n matrix of integers.
        mod: Modulus.

    Returns:
        Inverse matrix mod m.

    Raises:
        ValueError: If matrix is not invertible.
    """
    n = len(matrix)
    det = round(_determinant(matrix)) % mod
    det_inv = _mod_inverse(det, mod)

    cofactors = _cofactor_matrix(matrix)
    adjugate = _transpose(cofactors)

    result: list[list[int]] = []
    for row in adjugate:
        result.append([(int(round(val)) * det_inv) % mod for val in row])
    return result


def _determinant(matrix: list[list[int]]) -> float:
    """Compute determinant of a square matrix.

    Args:
        matrix: n×n matrix.

    Returns:
        Determinant value.
    """
    n = len(matrix)
    if n == 1:
        return float(matrix[0][0])
    if n == 2:
        return float(matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0])

    det = 0.0
    for c in range(n):
        minor = [row[:c] + row[c + 1 :] for row in matrix[1:]]
        det += ((-1) ** c) * matrix[0][c] * _determinant(minor)
    return det


def _cofactor_matrix(matrix: list[list[int]]) -> list[list[float]]:
    """Compute the matrix of cofactors.

    Args:
        matrix: n×n matrix.

    Returns:
        Cofactor matrix.
    """
    n = len(matrix)
    cofactors: list[list[float]] = []
    for i in range(n):
        row: list[float] = []
        for j in range(n):
            minor = [row[:j] + row[j + 1 :] for row in (matrix[:i] + matrix[i + 1 :])]
            cofactors_val = ((-1) ** (i + j)) * _determinant(minor)
            row.append(cofactors_val)
        cofactors.append(row)
    return cofactors


def _transpose(matrix: list[list[float]]) -> list[list[float]]:
    """Transpose a matrix."""
    return [list(row) for row in zip(*matrix)]


def _matrix_multiply_mod(
    matrix: list[list[int]], vector: list[int], mod: int = 26
) -> list[int]:
    """Multiply matrix by vector mod m.

    Args:
        matrix: n×n matrix.
        vector: Length-n vector.
        mod: Modulus.

    Returns:
        Result vector.
    """
    n = len(matrix)
    return [sum(matrix[i][j] * vector[j] for j in range(n)) % mod for i in range(n)]


class HillCipher(CipherBase):
    """Hill cipher — polygraphic substitution using matrix multiplication.

    Args:
        key_matrix: n×n invertible matrix over Z_26.
    """

    def __init__(self, key_matrix: list[list[int]] | None = None) -> None:
        if key_matrix is None:
            key_matrix = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]
        n = len(key_matrix)
        for row in key_matrix:
            if len(row) != n:
                msg = "Key matrix must be square"
                raise ValueError(msg)
        det = round(_determinant(key_matrix)) % 26
        if math.gcd(det, 26) != 1:
            msg = f"Key matrix is not invertible mod 26 (det={det})"
            raise ValueError(msg)
        self._matrix = key_matrix
        self._n = n
        self._inverse = _matrix_mod_inverse(key_matrix)

    @property
    def name(self) -> str:
        return "Hill Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt plaintext using Hill cipher.

        Args:
            plaintext: Text to encrypt (letters only, case preserved).
            key: Ignored (key is the matrix).

        Returns:
            Ciphertext string.
        """
        letters = [c.upper() for c in plaintext if c.isalpha()]

        pad_len = (self._n - len(letters) % self._n) % self._n
        letters.extend(["X"] * pad_len)

        result: list[str] = []
        for i in range(0, len(letters), self._n):
            block = [ord(c) - ord("A") for c in letters[i : i + self._n]]
            encrypted = _matrix_multiply_mod(self._matrix, block)
            result.extend(chr(ord("A") + v) for v in encrypted)

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Hill cipher ciphertext.

        Args:
            ciphertext: Text to decrypt.
            key: Ignored.

        Returns:
            Recovered plaintext.
        """
        letters = [c.upper() for c in ciphertext if c.isalpha()]

        result: list[str] = []
        for i in range(0, len(letters), self._n):
            block = [ord(c) - ord("A") for c in letters[i : i + self._n]]
            decrypted = _matrix_multiply_mod(self._inverse, block)
            result.extend(chr(ord("A") + v) for v in decrypted)

        return "".join(result)

    def crack(self, ciphertext: str, **kwargs: object) -> list[tuple[str, str, float]]:
        """Crack Hill cipher using known plaintext (crib).

        Args:
            ciphertext: The ciphertext.
            crib: Known plaintext fragment (must be >= n² chars).

        Returns:
            List of (key_matrix_str, plaintext, confidence) tuples.
        """
        crib = str(kwargs.get("crib", ""))
        if not crib:
            msg = "crib kwarg is required for Hill cracker"
            raise ValueError(msg)

        crib_letters = [c.upper() for c in crib if c.isalpha()]
        cipher_letters = [c.upper() for c in ciphertext if c.isalpha()]

        if len(crib_letters) < self._n * self._n:
            msg = f"Crib must be at least {self._n * self._n} letters for {self._n}×{self._n} matrix"
            raise ValueError(msg)

        crib_matrix: list[list[int]] = []
        for i in range(self._n):
            row = [ord(crib_letters[i * self._n + j]) - ord("A") for j in range(self._n)]
            crib_matrix.append(row)

        cipher_matrix: list[list[int]] = []
        for i in range(self._n):
            row = [ord(cipher_letters[i * self._n + j]) - ord("A") for j in range(self._n)]
            cipher_matrix.append(row)

        try:
            crib_inv = _matrix_mod_inverse(crib_matrix)
            key_matrix = [[0] * self._n for _ in range(self._n)]
            for i in range(self._n):
                for j in range(self._n):
                    key_matrix[i][j] = sum(
                        cipher_matrix[i][k] * crib_inv[k][j] for k in range(self._n)
                    ) % 26

            self._matrix = key_matrix
            self._inverse = _matrix_mod_inverse(key_matrix)
            plaintext = self.decrypt(ciphertext)
            key_str = str(key_matrix)
            return [(key_str, plaintext, 1.0)]
        except ValueError:
            return []
