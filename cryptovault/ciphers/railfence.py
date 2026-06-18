"""Rail Fence cipher — transposition via zigzag pattern.

Vulnerability: Key is just the number of rails; low search space.

The Rail Fence cipher writes plaintext in a zigzag pattern across
a number of "rails" (rows), then reads off row by row.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase


class RailFenceCipher(CipherBase):
    """Rail Fence cipher — zigzag transposition.

    Args:
        rails: Number of rails (rows). Must be >= 2.
    """

    def __init__(self, rails: int = 2) -> None:
        if rails < 2:
            msg = f"Rails must be >= 2, got {rails}"
            raise ValueError(msg)
        self._rails = rails

    @property
    def name(self) -> str:
        return "Rail Fence Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using rail fence transposition.

        Args:
            plaintext: Text to encrypt (all characters, non-alpha included).
            key: Optional integer string for number of rails.

        Returns:
            Transposed ciphertext.
        """
        rails = self._rails
        if key:
            try:
                rails = int(key)
            except ValueError:
                msg = f"Key must be an integer (number of rails), got {key!r}"
                raise ValueError(msg)
            if rails < 2:
                msg = f"Rails must be >= 2, got {rails}"
                raise ValueError(msg)

        if not plaintext:
            return ""

        fence: list[list[str]] = [[] for _ in range(rails)]
        rail = 0
        direction = 1

        for ch in plaintext:
            fence[rail].append(ch)
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        return "".join("".join(row) for row in fence)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt rail fence ciphertext.

        Args:
            ciphertext: Text to decrypt.
            key: Optional integer string for number of rails.

        Returns:
            Recovered plaintext.
        """
        rails = self._rails
        if key:
            try:
                rails = int(key)
            except ValueError:
                msg = f"Key must be an integer (number of rails), got {key!r}"
                raise ValueError(msg)
            if rails < 2:
                msg = f"Rails must be >= 2, got {rails}"
                raise ValueError(msg)

        if not ciphertext:
            return ""

        n = len(ciphertext)
        fence: list[list[str | None]] = [[None] * n for _ in range(rails)]
        rail = 0
        direction = 1

        for col in range(n):
            fence[rail][col] = "*"
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        idx = 0
        for r in range(rails):
            for c in range(n):
                if fence[r][c] == "*":
                    fence[r][c] = ciphertext[idx]
                    idx += 1

        result: list[str] = []
        rail = 0
        direction = 1
        for col in range(n):
            assert fence[rail][col] is not None
            result.append(str(fence[rail][col]))
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        return "".join(result)
