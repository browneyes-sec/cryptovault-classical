"""Trifid cipher — 3D fractionation using a 27-character Polybius cube.

Vulnerability: Period-based frequency analysis.

The Trifid cipher extends Bifid into 3 dimensions using a 3×3×3 cube
(27 characters including a period for padding). Each letter maps to
three coordinates (level, row, col) which are then read sequentially
and re-paired into (level, row, col) triplets.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase

_ALPHABET27 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ."


def _build_cube(key: str) -> list[list[list[str]]]:
    """Build 3×3×3 cube from keyword.

    Args:
        key: Keyword for the cube (letters + period).

    Returns:
        3×3×3 cube.
    """
    seen: set[str] = set()
    order: list[str] = []
    for ch in key.upper():
        if ch.isalpha() or ch == ".":
            if ch not in seen:
                seen.add(ch)
                order.append(ch)
    for ch in _ALPHABET27:
        if ch not in seen:
            seen.add(ch)
            order.append(ch)

    cube: list[list[list[str]]] = []
    idx = 0
    for level in range(3):
        layer: list[list[str]] = []
        for row in range(3):
            layer.append(order[idx : idx + 3])
            idx += 3
        cube.append(layer)
    return cube


def _find3d(
    cube: list[list[list[str]]], ch: str
) -> tuple[int, int, int]:
    """Find character position in 3D cube."""
    ch = ch.upper()
    for level in range(3):
        for row in range(3):
            for col in range(3):
                if cube[level][row][col] == ch:
                    return level, row, col
    msg = f"Character {ch!r} not in cube"
    raise ValueError(msg)


class TrifidCipher(CipherBase):
    """Trifid cipher — 3D fractionation.

    Args:
        key: Keyword for 3×3×3 cube generation.
    """

    def __init__(self, key: str = "KEYWORD") -> None:
        self._cube = _build_cube(key)

    @property
    def name(self) -> str:
        return "Trifid Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using Trifid cipher.

        Args:
            plaintext: Text to encrypt (letters + period).
            key: Optional key override.

        Returns:
            Ciphertext string.
        """
        if key:
            self._cube = _build_cube(key)

        letters: list[str] = []
        for ch in plaintext.upper():
            if ch.isalpha() or ch == ".":
                letters.append(ch)

        levels: list[int] = []
        rows: list[int] = []
        cols: list[int] = []
        for ch in letters:
            l, r, c = _find3d(self._cube, ch)
            levels.append(l)
            rows.append(r)
            cols.append(c)

        combined = levels + rows + cols

        result: list[str] = []
        for i in range(0, len(combined), 3):
            level, row, col = combined[i], combined[i + 1], combined[i + 2]
            result.append(self._cube[level][row][col])
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Trifid cipher.

        Args:
            ciphertext: Text to decrypt.
            key: Optional key override.

        Returns:
            Recovered plaintext.
        """
        if key:
            self._cube = _build_cube(key)

        letters = [c.upper() for c in ciphertext if c.isalpha() or c == "."]
        n = len(letters)
        total_coords = n * 3
        third = total_coords // 3

        coords_from_text: list[int] = []
        for ch in letters:
            l, r, c = _find3d(self._cube, ch)
            coords_from_text.extend([l, r, c])

        levels = coords_from_text[:third]
        rows = coords_from_text[third : 2 * third]
        cols = coords_from_text[2 * third :]

        result: list[str] = []
        for l, r, c in zip(levels, rows, cols):
            result.append(self._cube[l][r][c])
        return "".join(result)
