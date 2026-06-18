"""Caesar cipher — monoalphabetic substitution with a fixed shift.

Vulnerability: Brute-force over 26 shifts, frequency analysis.

The Caesar cipher shifts each letter by a fixed number of positions
in the alphabet. With 26 possible shifts, it is trivially breakable
by trying all of them and selecting the most plausible plaintext.
"""

from __future__ import annotations

import string

from cryptovault.ciphers.base import CipherBase


class CaesarCipher(CipherBase):
    """Caesar cipher with configurable shift.

    Args:
        shift: Number of positions to shift (0-25). Defaults to 3.
    """

    def __init__(self, shift: int = 3) -> None:
        if not 0 <= shift <= 25:
            msg = f"Shift must be 0-25, got {shift}"
            raise ValueError(msg)
        self._shift = shift

    @property
    def name(self) -> str:
        return "Caesar Cipher"

    @property
    def shift(self) -> int:
        return self._shift

    def encrypt(self, plaintext: str, key: int | None = None) -> str:
        """Encrypt using Caesar shift.

        Args:
            plaintext: Text to encrypt (only letters are shifted).
            key: Shift value (0-25). If None, uses instance shift.

        Returns:
            Ciphertext with letters shifted, non-letters preserved.
        """
        shift = key if key is not None else self._shift
        if not 0 <= shift <= 25:
            msg = f"Shift must be 0-25, got {shift}"
            raise ValueError(msg)

        result: list[str] = []
        for ch in plaintext:
            if ch in string.ascii_lowercase:
                idx = (ord(ch) - ord("a") + shift) % 26
                result.append(chr(ord("a") + idx))
            elif ch in string.ascii_uppercase:
                idx = (ord(ch) - ord("A") + shift) % 26
                result.append(chr(ord("A") + idx))
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, ciphertext: str, key: int | None = None) -> str:
        """Decrypt by applying the inverse shift.

        Args:
            ciphertext: Text to decrypt.
            key: Shift value used during encryption. If None, uses instance shift.

        Returns:
            Recovered plaintext.
        """
        shift = key if key is not None else self._shift
        return self.encrypt(ciphertext, (26 - shift) % 26)

    def crack(self, ciphertext: str, **kwargs: object) -> list[tuple[int, str, float]]:
        """Brute-force all 26 shifts, ranked by chi-squared fitness.

        Args:
            ciphertext: The ciphertext to crack.

        Returns:
            List of (shift, plaintext, confidence) tuples.
        """
        return brute_force_caesar(ciphertext)


def brute_force_caesar(ciphertext: str) -> list[tuple[int, str, float]]:
    """Try all 26 shifts and rank results by English letter frequency fitness.

    Args:
        ciphertext: The ciphertext to brute-force.

    Returns:
        List of (shift, plaintext, confidence) tuples, best fit first.
    """
    from cryptovault.cryptanalysis.frequency import chi_squared_test

    results: list[tuple[int, str, float]] = []
    cipher = CaesarCipher(0)

    for shift in range(26):
        plaintext = cipher.decrypt(ciphertext, shift)
        fitness = chi_squared_test(plaintext)
        results.append((shift, plaintext, fitness))

    results.sort(key=lambda x: x[2])
    return results
