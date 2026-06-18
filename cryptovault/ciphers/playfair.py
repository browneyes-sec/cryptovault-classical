"""Playfair cipher — digraph substitution using a 5×5 keyed grid.

Vulnerability: Crib-based attacks, frequency analysis of digraphs.

The Playfair cipher encrypts pairs of letters using a 5×5 Polybius
square generated from a keyword. I and J are combined into one cell.
Each digraph is encrypted by a rule based on its position in the grid:
- Same row: shift right
- Same column: shift down
- Rectangle: swap columns
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase


def _build_grid(key: str) -> list[list[str]]:
    """Build a 5×5 Polybius square from a keyword.

    Args:
        key: Keyword for the grid (letters only, case-insensitive).
             I and J are merged.

    Returns:
        5×5 grid of characters.
    """
    seen: set[str] = set()
    order: list[str] = []

    for ch in key.upper():
        if ch == "J":
            ch = "I"
        if ch.isalpha() and ch not in seen:
            seen.add(ch)
            order.append(ch)

    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.add(ch)
            order.append(ch)

    grid: list[list[str]] = []
    for r in range(5):
        row = order[r * 5 : (r + 1) * 5]
        grid.append(row)
    return grid


def _find_pos(grid: list[list[str]], ch: str) -> tuple[int, int]:
    """Find row, col of character in grid.

    Args:
        grid: 5×5 Polybius square.
        ch: Character to find (case-insensitive, J→I).

    Returns:
        (row, col) tuple.

    Raises:
        ValueError: If character not found.
    """
    ch = ch.upper()
    if ch == "J":
        ch = "I"
    for r in range(5):
        for c in range(5):
            if grid[r][c] == ch:
                return r, c
    msg = f"Character {ch!r} not found in grid"
    raise ValueError(msg)


def _prepare_plaintext(plaintext: str) -> list[str]:
    """Prepare plaintext for Playfair encryption.

    - Letters only, I and J merged
    - Split into digraphs
    - X inserted between repeated pairs and as padding

    Args:
        plaintext: Input text.

    Returns:
        List of digraph strings (each 2 chars).
    """
    letters: list[str] = []
    for ch in plaintext.upper():
        if ch == "J":
            ch = "I"
        if ch.isalpha():
            letters.append(ch)

    digraphs: list[str] = []
    i = 0
    while i < len(letters):
        a = letters[i]
        if i + 1 < len(letters):
            b = letters[i + 1]
            if a == b:
                digraphs.append(a + "X")
                i += 1
            else:
                digraphs.append(a + b)
                i += 2
        else:
            digraphs.append(a + "X")
            i += 1
    return digraphs


class PlayfairCipher(CipherBase):
    """Playfair cipher — encrypts pairs of letters using a 5×5 keyed grid.

    Args:
        key: Keyword for generating the Polybius square.
    """

    def __init__(self, key: str = "KEYWORD") -> None:
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)
        self._key = key
        self._grid = _build_grid(key)

    @property
    def name(self) -> str:
        return "Playfair Cipher"

    def _encrypt_pair(self, a: str, b: str) -> str:
        """Encrypt a single digraph.

        Args:
            a: First letter.
            b: Second letter.

        Returns:
            Encrypted digraph.
        """
        r1, c1 = _find_pos(self._grid, a)
        r2, c2 = _find_pos(self._grid, b)

        if r1 == r2:
            return self._grid[r1][(c1 + 1) % 5] + self._grid[r2][(c2 + 1) % 5]
        elif c1 == c2:
            return self._grid[(r1 + 1) % 5][c1] + self._grid[(r2 + 1) % 5][c2]
        else:
            return self._grid[r1][c2] + self._grid[r2][c1]

    def _decrypt_pair(self, a: str, b: str) -> str:
        """Decrypt a single digraph.

        Args:
            a: First letter of ciphertext digraph.
            b: Second letter of ciphertext digraph.

        Returns:
            Decrypted digraph.
        """
        r1, c1 = _find_pos(self._grid, a)
        r2, c2 = _find_pos(self._grid, b)

        if r1 == r2:
            return self._grid[r1][(c1 - 1) % 5] + self._grid[r2][(c2 - 1) % 5]
        elif c1 == c2:
            return self._grid[(r1 - 1) % 5][c1] + self._grid[(r2 - 1) % 5][c2]
        else:
            return self._grid[r1][c2] + self._grid[r2][c1]

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt plaintext using Playfair cipher.

        Args:
            plaintext: Text to encrypt (non-alpha chars ignored).
            key: Optional key override.

        Returns:
            Ciphertext string (uppercase letters, digraphs joined).
        """
        if key:
            self._key = key
            self._grid = _build_grid(key)

        digraphs = _prepare_plaintext(plaintext)
        result: list[str] = []
        for a, b in digraphs:
            result.append(self._encrypt_pair(a, b))
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Playfair ciphertext.

        Args:
            ciphertext: Text to decrypt (letters only).
            key: Optional key override.

        Returns:
            Decrypted plaintext (uppercase, with padding X retained).
        """
        if key:
            self._key = key
            self._grid = _build_grid(key)

        letters = [c.upper() for c in ciphertext if c.isalpha()]
        result: list[str] = []

        for i in range(0, len(letters) - 1, 2):
            result.append(self._decrypt_pair(letters[i], letters[i + 1]))

        return "".join(result)
