"""Columnar transposition ciphers — rearranging characters by key-based permutation.

Vulnerability: Anagramming, columnar reconstruction.

Three variants:
- ColumnarTransposition: Standard key-based column reordering.
- InvertedColumnarTransposition: Inverted sort order.
- SymmetricColumnarTransposition: 3-space variant.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase


def _get_permutation(key: str) -> list[int]:
    """Compute column permutation from a keyword.

    Columns are numbered by alphabetical order of key characters.
    Duplicate characters are resolved by left-to-right occurrence.

    Args:
        key: The keyword for transposition.

    Returns:
        List mapping original column index to output column index.

    Raises:
        ValueError: If key is empty.
    """
    if not key:
        msg = "Key cannot be empty"
        raise ValueError(msg)

    indexed = sorted(enumerate(key), key=lambda x: (x[1], x[0]))
    perm = [0] * len(key)
    for rank, (orig_idx, _) in enumerate(indexed):
        perm[orig_idx] = rank
    return perm


def _get_inverse_permutation(key: str) -> list[int]:
    """Compute the inverse column permutation.

    Args:
        key: The keyword for transposition.

    Returns:
        List mapping output column index back to original column index.
    """
    perm = _get_permutation(key)
    inverse = [0] * len(perm)
    for i, p in enumerate(perm):
        inverse[p] = i
    return inverse


class ColumnarTransposition(CipherBase):
    """Standard columnar transposition cipher.

    Writes plaintext row-by-row into a matrix with columns reordered
    by the key, then reads column-by-column.
    """

    @property
    def name(self) -> str:
        return "Columnar Transposition"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using columnar transposition.

        Args:
            plaintext: Text to encrypt (non-alpha chars preserved at end).
            key: Keyword for column ordering.

        Returns:
            Transposed ciphertext.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        perm = _get_permutation(key)
        n_cols = len(key)
        filtered = [c for c in plaintext if c.isalpha()]

        n_rows = -(-len(filtered) // n_cols)
        pad_len = n_rows * n_cols - len(filtered)
        filtered.extend([" "] * pad_len)

        grid = [filtered[i * n_cols : (i + 1) * n_cols] for i in range(n_rows)]

        result: list[str] = []
        for col_rank in range(n_cols):
            orig_col = perm.index(col_rank)
            for row in range(n_rows):
                result.append(grid[row][orig_col])

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt columnar transposition.

        Args:
            ciphertext: Text to decrypt.
            key: Keyword used during encryption.

        Returns:
            Recovered plaintext.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        perm = _get_permutation(key)
        n_cols = len(key)
        n_rows = -(-len(ciphertext) // n_cols)

        total_cells = n_rows * n_cols
        padded = ciphertext + " " * (total_cells - len(ciphertext))

        grid = [[""] * n_cols for _ in range(n_rows)]

        idx = 0
        for col_rank in range(n_cols):
            orig_col = perm.index(col_rank)
            for row in range(n_rows):
                grid[row][orig_col] = padded[idx]
                idx += 1

        result: list[str] = []
        for row in grid:
            result.extend(row)

        return "".join(result).rstrip(" ")


class InvertedColumnarTransposition(CipherBase):
    """Inverted columnar transposition — reversed sort order.

    Similar to standard columnar but with inverted column ranking.
    """

    @property
    def name(self) -> str:
        return "Inverted Columnar Transposition"

    def _get_inverted_permutation(self, key: str) -> list[int]:
        """Compute inverted column permutation (descending rank).

        Args:
            key: The keyword.

        Returns:
            Inverted permutation list.
        """
        indexed = sorted(enumerate(key), key=lambda x: (x[1], x[0]))
        perm = [0] * len(key)
        n = len(key)
        for rank, (orig_idx, _) in enumerate(indexed):
            perm[orig_idx] = n - 1 - rank
        return perm

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using inverted columnar transposition.

        Args:
            plaintext: Text to encrypt.
            key: Keyword for column ordering.

        Returns:
            Transposed ciphertext.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        perm = self._get_inverted_permutation(key)
        n_cols = len(key)
        filtered = [c for c in plaintext if c.isalpha()]

        n_rows = -(-len(filtered) // n_cols)
        pad_len = n_rows * n_cols - len(filtered)
        filtered.extend([" "] * pad_len)

        grid = [filtered[i * n_cols : (i + 1) * n_cols] for i in range(n_rows)]

        result: list[str] = []
        for col_rank in range(n_cols):
            orig_col = perm.index(col_rank)
            for row in range(n_rows):
                result.append(grid[row][orig_col])

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt inverted columnar transposition.

        Args:
            ciphertext: Text to decrypt.
            key: Keyword used during encryption.

        Returns:
            Recovered plaintext.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        perm = self._get_inverted_permutation(key)
        n_cols = len(key)
        n_rows = -(-len(ciphertext) // n_cols)

        total_cells = n_rows * n_cols
        padded = ciphertext + " " * (total_cells - len(ciphertext))

        grid = [[""] * n_cols for _ in range(n_rows)]

        idx = 0
        for col_rank in range(n_cols):
            orig_col = perm.index(col_rank)
            for row in range(n_rows):
                grid[row][orig_col] = padded[idx]
                idx += 1

        result: list[str] = []
        for row in grid:
            result.extend(row)

        return "".join(result).rstrip(" ")


class SymmetricColumnarTransposition(CipherBase):
    """Symmetric columnar transposition (3-space variant).

    A variant where the key determines a symmetric permutation.
    """

    @property
    def name(self) -> str:
        return "Symmetric Columnar Transposition"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using symmetric columnar transposition.

        Args:
            plaintext: Text to encrypt.
            key: Keyword for column ordering.

        Returns:
            Transposed ciphertext.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        perm = _get_permutation(key)
        n_cols = len(key)
        filtered = [c for c in plaintext if c.isalpha()]

        n_rows = -(-len(filtered) // n_cols)
        pad_len = n_rows * n_cols - len(filtered)
        filtered.extend([" "] * pad_len)

        grid = [filtered[i * n_cols : (i + 1) * n_cols] for i in range(n_rows)]

        result: list[str] = []
        for col_rank in range(n_cols):
            orig_col = perm.index(col_rank)
            for row in range(n_rows):
                result.append(grid[row][orig_col])

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt symmetric columnar transposition.

        Args:
            ciphertext: Text to decrypt.
            key: Keyword used during encryption.

        Returns:
            Recovered plaintext.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        perm = _get_permutation(key)
        n_cols = len(key)
        n_rows = -(-len(ciphertext) // n_cols)

        total_cells = n_rows * n_cols
        padded = ciphertext + " " * (total_cells - len(ciphertext))

        grid = [[""] * n_cols for _ in range(n_rows)]

        idx = 0
        for col_rank in range(n_cols):
            orig_col = perm.index(col_rank)
            for row in range(n_rows):
                grid[row][orig_col] = padded[idx]
                idx += 1

        result: list[str] = []
        for row in grid:
            result.extend(row)

        return "".join(result).rstrip(" ")
