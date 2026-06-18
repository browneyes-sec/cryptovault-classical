"""Affine cipher — monoalphabetic substitution using modular arithmetic.

Vulnerability: Known-plaintext attack, frequency analysis.

The Affine cipher uses the formula: E(x) = (a*x + b) mod 26
where 'a' must be coprime with 26 (12 possible values).
Decryption uses the modular inverse of a: D(y) = a_inv * (y - b) mod 26.
"""

from __future__ import annotations

import math
import string

from cryptovault.ciphers.base import CipherBase

# All values coprime with 26
_VALID_A_VALUES = [x for x in range(26) if math.gcd(x, 26) == 1]


def _mod_inverse(a: int, m: int = 26) -> int:
    """Compute modular inverse of a modulo m using extended Euclidean algorithm.

    Args:
        a: The integer.
        m: The modulus.

    Returns:
        Modular inverse of a mod m.

    Raises:
        ValueError: If inverse doesn't exist.
    """
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        msg = f"No modular inverse for {a} mod {m}"
        raise ValueError(msg)
    return x % m


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm.

    Args:
        a: First integer.
        b: Second integer.

    Returns:
        (gcd, x, y) such that a*x + b*y = gcd.
    """
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x


class AffineCipher(CipherBase):
    """Affine cipher with parameters (a, b).

    Args:
        a: Multiplicative key (must be coprime with 26).
        b: Additive key (0-25).
    """

    def __init__(self, a: int = 5, b: int = 8) -> None:
        if math.gcd(a, 26) != 1:
            msg = f"a={a} is not coprime with 26; valid values: {_VALID_A_VALUES}"
            raise ValueError(msg)
        self._a = a
        self._b = b

    @property
    def name(self) -> str:
        return "Affine Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using Affine cipher.

        E(x) = (a*x + b) mod 26

        Args:
            plaintext: Text to encrypt (only letters shifted).
            key: Optional "a,b" format key.

        Returns:
            Ciphertext with letters substituted.
        """
        a, b = self._a, self._b
        if key:
            parts = key.split(",")
            if len(parts) != 2:
                msg = f"Key must be in 'a,b' format, got {key!r}"
                raise ValueError(msg)
            a, b = int(parts[0]), int(parts[1])
            if math.gcd(a, 26) != 1:
                msg = f"a={a} is not coprime with 26"
                raise ValueError(msg)

        result: list[str] = []
        for ch in plaintext:
            if ch in string.ascii_lowercase:
                x = ord(ch) - ord("a")
                enc = (a * x + b) % 26
                result.append(chr(ord("a") + enc))
            elif ch in string.ascii_uppercase:
                x = ord(ch) - ord("A")
                enc = (a * x + b) % 26
                result.append(chr(ord("A") + enc))
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Affine cipher.

        D(y) = a_inv * (y - b) mod 26

        Args:
            ciphertext: Text to decrypt.
            key: Optional "a,b" format key.

        Returns:
            Recovered plaintext.
        """
        a, b = self._a, self._b
        if key:
            parts = key.split(",")
            if len(parts) != 2:
                msg = f"Key must be in 'a,b' format, got {key!r}"
                raise ValueError(msg)
            a, b = int(parts[0]), int(parts[1])
            if math.gcd(a, 26) != 1:
                msg = f"a={a} is not coprime with 26"
                raise ValueError(msg)

        a_inv = _mod_inverse(a, 26)
        result: list[str] = []
        for ch in ciphertext:
            if ch in string.ascii_lowercase:
                y = ord(ch) - ord("a")
                dec = (a_inv * (y - b)) % 26
                result.append(chr(ord("a") + dec))
            elif ch in string.ascii_uppercase:
                y = ord(ch) - ord("A")
                dec = (a_inv * (y - b)) % 26
                result.append(chr(ord("A") + dec))
            else:
                result.append(ch)
        return "".join(result)

    def crack(self, ciphertext: str, **kwargs: object) -> list[tuple[str, str, float]]:
        """Brute-force all valid (a, b) pairs, ranked by chi-squared fitness.

        Args:
            ciphertext: The ciphertext to crack.

        Returns:
            List of (key, plaintext, confidence) tuples.
        """
        from cryptovault.cryptanalysis.frequency import chi_squared_test

        results: list[tuple[str, str, float]] = []
        for a in _VALID_A_VALUES:
            for b in range(26):
                key_str = f"{a},{b}"
                plaintext = self.decrypt(ciphertext, key_str)
                fitness = chi_squared_test(plaintext)
                results.append((key_str, plaintext, fitness))

        results.sort(key=lambda x: x[2])
        return results
