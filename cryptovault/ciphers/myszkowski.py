"""Myszkowski cipher — columnar transposition with repeated-key grouping.

Vulnerability: Anagramming attack, pattern analysis.

The Myszkowski cipher is a variant of columnar transposition where
characters with the same letter in the key are grouped together.
If the key is "SECRET", then S=0, E=1,2, C=3, R=4, T=5, and columns
with the same key letter are read as a block.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase


def _get_myszkowski_permutation(key: str) -> list[int]:
    """Compute Myszkowski permutation from keyword.

    Characters with the same letter get the same rank.

    Args:
        key: Keyword for transposition.

    Returns:
        List of rank values for each key position.
    """
    if not key:
        msg = "Key cannot be empty"
        raise ValueError(msg)

    ranks: list[int] = [0] * len(key)
    sorted_unique = sorted(set(key))
    for rank, ch in enumerate(sorted_unique):
        for i, k in enumerate(key):
            if k == ch:
                ranks[i] = rank
    return ranks


class MyszkowskiCipher(CipherBase):
    """Myszkowski cipher — columnar transposition with repeated-key grouping.

    Args:
        key: Keyword for column ordering.
    """

    def __init__(self, key: str = "KEY") -> None:
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)
        self._key = key

    @property
    def name(self) -> str:
        return "Myszkowski Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using Myszkowski transposition.

        Args:
            plaintext: Text to encrypt (letters only).
            key: Optional key override.

        Returns:
            Transposed ciphertext.
        """
        kw = key if key else self._key
        ranks = _get_myszkowski_permutation(kw)
        n_cols = len(kw)
        filtered = [c for c in plaintext if c.isalpha()]

        n_rows = -(-len(filtered) // n_cols)
        pad_len = n_rows * n_cols - len(filtered)
        filtered.extend([" "] * pad_len)

        grid = [filtered[i * n_cols : (i + 1) * n_cols] for i in range(n_rows)]

        unique_ranks = sorted(set(ranks))
        result: list[str] = []
        for rank in unique_ranks:
            cols_for_rank = [i for i, r in enumerate(ranks) if r == rank]
            for row in range(n_rows):
                for col in cols_for_rank:
                    result.append(grid[row][col])

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Myszkowski transposition.

        Args:
            ciphertext: Text to decrypt.
            key: Optional key override.

        Returns:
            Recovered plaintext.
        """
        kw = key if key else self._key
        ranks = _get_myszkowski_permutation(kw)
        n_cols = len(kw)
        n_rows = -(-len(ciphertext) // n_cols)

        total_cells = n_rows * n_cols
        padded = ciphertext + " " * (total_cells - len(ciphertext))

        grid: list[list[str]] = [[""] * n_cols for _ in range(n_rows)]

        idx = 0
        unique_ranks = sorted(set(ranks))
        for rank in unique_ranks:
            cols_for_rank = [i for i, r in enumerate(ranks) if r == rank]
            for row in range(n_rows):
                for col in cols_for_rank:
                    grid[row][col] = padded[idx]
                    idx += 1

        result: list[str] = []
        for row in grid:
            result.extend(row)

        return "".join(result).rstrip(" ")
