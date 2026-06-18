"""ADFGVX cipher — WWI field cipher using 6×6 Polybius + columnar transposition.

Vulnerability: Known-plaintext attack, crib-based columnar reconstruction.

The ADFGVX cipher (1918) was used by Germany in WWI. It combines
a 6×6 Polybius square (using letters A, D, F, G, V, X as row/column
labels) with a columnar transposition. It can encode the full alphabet
plus digits 0-9.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase
from cryptovault.ciphers.transposition import _get_permutation

_ADFGVX_LABELS = "ADFGVX"


def _build_square(key: str) -> list[list[str]]:
    """Build 6×6 Polybius square from keyword.

    Args:
        key: Keyword for the square (letters + digits).

    Returns:
        6×6 grid containing A-Z and 0-9.
    """
    seen: set[str] = set()
    order: list[str] = []
    for ch in key.upper():
        if ch.isalnum() and ch not in seen:
            seen.add(ch)
            order.append(ch)
    for ch in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789":
        if ch not in seen:
            seen.add(ch)
            order.append(ch)
    return [order[i * 6 : (i + 1) * 6] for i in range(6)]


def _find(grid: list[list[str]], ch: str) -> tuple[int, int]:
    """Find character position in grid."""
    ch = ch.upper()
    for r in range(6):
        for c in range(6):
            if grid[r][c] == ch:
                return r, c
    msg = f"Character {ch!r} not in grid"
    raise ValueError(msg)


class ADFGVXCipher(CipherBase):
    """ADFGVX cipher — Polybius substitution + columnar transposition.

    The ciphertext format is: [2-char length prefix][transposed text].
    The length prefix encodes the number of original plaintext characters.

    Args:
        polybius_key: Keyword for 6×6 Polybius square.
        transposition_key: Keyword for columnar transposition.
    """

    def __init__(self, polybius_key: str = "SECRET", transposition_key: str = "CARGO") -> None:
        self._grid = _build_square(polybius_key)
        self._trans_key = transposition_key

    @property
    def name(self) -> str:
        return "ADFGVX Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using ADFGVX cipher.

        1. Substitute each character using 6×6 Polybius.
        2. Encode original length as 2-char ADFGVX prefix.
        3. Write substitution result row-by-row into columnar transposition.
        4. Read column-by-column.

        Args:
            plaintext: Text to encrypt (alphanumeric).
            key: Optional "polybius_key,transposition_key" format.

        Returns:
            Ciphertext using only ADFGVX characters.
        """
        if key:
            parts = key.split(",")
            if len(parts) == 2:
                self._grid = _build_square(parts[0])
                self._trans_key = parts[1]

        substitution: list[str] = []
        for ch in plaintext.upper():
            if ch.isalnum():
                r, c = _find(self._grid, ch)
                substitution.append(f"{_ADFGVX_LABELS[r]}{_ADFGVX_LABELS[c]}")

        sub_text = "".join(substitution)
        if not sub_text:
            return ""

        # Encode original plaintext length as 2 ADFGVX characters
        n_plaintext = len([c for c in plaintext.upper() if c.isalnum()])
        len_prefix = _ADFGVX_LABELS[n_plaintext // 6] + _ADFGVX_LABELS[n_plaintext % 6]

        # Prepend length prefix to substitution text
        full_text = len_prefix + sub_text

        perm = _get_permutation(self._trans_key)
        n_cols = len(self._trans_key)
        n_rows = -(-len(full_text) // n_cols)
        pad_len = n_rows * n_cols - len(full_text)
        padded = full_text + "A" * pad_len

        grid = [padded[i * n_cols : (i + 1) * n_cols] for i in range(n_rows)]

        result: list[str] = []
        for col_rank in range(n_cols):
            orig_col = perm.index(col_rank)
            for row in range(n_rows):
                result.append(grid[row][orig_col])

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt ADFGVX ciphertext.

        1. Reverse columnar transposition.
        2. Decode length prefix.
        3. Look up pairs of ADFGVX characters in the grid.

        Args:
            ciphertext: Text to decrypt (ADFGVX chars only).
            key: Optional "polybius_key,transposition_key" format.

        Returns:
            Recovered plaintext.
        """
        if key:
            parts = key.split(",")
            if len(parts) == 2:
                self._grid = _build_square(parts[0])
                self._trans_key = parts[1]

        if not ciphertext or len(ciphertext) < 2:
            return ""

        perm = _get_permutation(self._trans_key)
        n_cols = len(self._trans_key)
        n_rows = -(-len(ciphertext) // n_cols)
        total_cells = n_rows * n_cols
        padded = ciphertext + "A" * (total_cells - len(ciphertext))

        grid = [[""] * n_cols for _ in range(n_rows)]
        idx = 0
        for col_rank in range(n_cols):
            orig_col = perm.index(col_rank)
            for row in range(n_rows):
                grid[row][orig_col] = padded[idx]
                idx += 1

        sub_text = "".join("".join(row) for row in grid)

        # Decode length prefix (first 2 ADFGVX chars → number of plaintext chars)
        n_plaintext = _ADFGVX_LABELS.index(sub_text[0]) * 6 + _ADFGVX_LABELS.index(sub_text[1])

        # Decode pairs starting from position 2 (after length prefix)
        result: list[str] = []
        for i in range(n_plaintext):
            pair_start = 2 + i * 2
            row_idx = _ADFGVX_LABELS.index(sub_text[pair_start])
            col_idx = _ADFGVX_LABELS.index(sub_text[pair_start + 1])
            result.append(self._grid[row_idx][col_idx])

        return "".join(result)
