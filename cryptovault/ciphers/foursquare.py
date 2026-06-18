"""Four-Square cipher — digraph substitution using two keyed Polybius squares.

Vulnerability: Known-plaintext attack, frequency analysis of digraphs.

The Four-Square cipher uses a standard 5×5 square, two keyed squares,
and encrypts digraphs by looking up the first letter in the plain square
and the second in a keyed square, then taking the opposite corners.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase


def _build_square(key: str) -> list[list[str]]:
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


class FourSquareCipher(CipherBase):
    """Four-Square cipher — double keyed digraph substitution.

    Uses standard square (top-left), key1 square (bottom-right),
    key2 square (top-right), and standard square (bottom-left).

    Args:
        key1: Keyword for first keyed square (bottom-right).
        key2: Keyword for second keyed square (top-right).
    """

    def __init__(self, key1: str = "EXAMPLE", key2: str = "KEYWORD") -> None:
        self._plain = _build_square("")
        self._cipher1 = _build_square(key1)
        self._cipher2 = _build_square(key2)

    @property
    def name(self) -> str:
        return "Four-Square Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using Four-Square cipher.

        Args:
            plaintext: Text to encrypt (letters only, J→I).
            key: Optional "key1,key2" format.

        Returns:
            Ciphertext string.
        """
        if key:
            parts = key.split(",")
            if len(parts) == 2:
                self._cipher1 = _build_square(parts[0])
                self._cipher2 = _build_square(parts[1])

        letters: list[str] = []
        for ch in plaintext.upper():
            ch = "I" if ch == "J" else ch
            if ch.isalpha():
                letters.append(ch)

        if len(letters) % 2 != 0:
            letters.append("X")

        result: list[str] = []
        for i in range(0, len(letters), 2):
            r1, c1 = _find(self._plain, letters[i])
            r2, c2 = _find(self._cipher1, letters[i + 1])
            result.append(self._cipher2[r1][c2])
            result.append(self._plain[r2][c1])

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Four-Square cipher.

        Args:
            ciphertext: Text to decrypt.
            key: Optional "key1,key2" format.

        Returns:
            Recovered plaintext.
        """
        if key:
            parts = key.split(",")
            if len(parts) == 2:
                self._cipher1 = _build_square(parts[0])
                self._cipher2 = _build_square(parts[1])

        letters = [c.upper() for c in ciphertext if c.isalpha()]

        result: list[str] = []
        for i in range(0, len(letters), 2):
            r1, c1 = _find(self._cipher2, letters[i])
            r2, c2 = _find(self._plain, letters[i + 1])
            result.append(self._plain[r1][c2])
            result.append(self._cipher1[r2][c1])

        return "".join(result)
