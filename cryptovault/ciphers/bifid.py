"""Bifid cipher — fractionation + transposition using a Polybius square.

Vulnerability: Known-plaintext attack, period-based frequency analysis.

The Bifid cipher combines substitution and transposition by:
1. Converting each letter to (row, col) coordinates via a 5×5 grid.
2. Reading all row coordinates, then all column coordinates.
3. Re-pairing into (row, col) pairs and looking up letters.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase


def _build_polybius(key: str) -> list[list[str]]:
    """Build 5×5 Polybius square from keyword.

    Args:
        key: Keyword (I/J merged).

    Returns:
        5×5 grid.
    """
    seen: set[str] = set()
    order: list[str] = []
    for ch in key.upper():
        ch = "I" if ch == "J" else ch
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            order.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.add(ch)
            order.append(ch)
    return [order[i * 5 : (i + 1) * 5] for i in range(5)]


def _find(grid: list[list[str]], ch: str) -> tuple[int, int]:
    """Find character position in grid."""
    ch = "I" if (ch := ch.upper()) == "J" else ch
    for r in range(5):
        for c in range(5):
            if grid[r][c] == ch:
                return r, c
    msg = f"Character {ch!r} not in grid"
    raise ValueError(msg)


class BifidCipher(CipherBase):
    """Bifid cipher — fractionation transposition.

    Args:
        key: Keyword for 5×5 Polybius square.
    """

    def __init__(self, key: str = "KEYWORD") -> None:
        self._grid = _build_polybius(key)

    @property
    def name(self) -> str:
        return "Bifid Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using Bifid cipher.

        Args:
            plaintext: Text to encrypt (letters only).
            key: Optional key override.

        Returns:
            Ciphertext string.
        """
        if key:
            self._grid = _build_polybius(key)

        letters = [c.upper() for c in plaintext if c.isalpha()]
        rows: list[int] = []
        cols: list[int] = []
        for ch in letters:
            r, c = _find(self._grid, ch)
            rows.append(r)
            cols.append(c)

        combined = rows + cols
        result: list[str] = []
        for i in range(0, len(combined), 2):
            r, c = combined[i], combined[i + 1]
            result.append(self._grid[r][c])
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Bifid cipher.

        Args:
            ciphertext: Text to decrypt.
            key: Optional key override.

        Returns:
            Recovered plaintext.
        """
        if key:
            self._grid = _build_polybius(key)

        letters = [c.upper() for c in ciphertext if c.isalpha()]
        n = len(letters)
        coords: list[int] = []
        for ch in letters:
            r, c = _find(self._grid, ch)
            coords.append(r)
            coords.append(c)

        half = n
        rows = coords[:half]
        cols = coords[half:]

        result: list[str] = []
        for r, c in zip(rows, cols):
            result.append(self._grid[r][c])
        return "".join(result)
