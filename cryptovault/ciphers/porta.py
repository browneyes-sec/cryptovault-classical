"""Porta cipher — polyalphabetic cipher with a keyword-driven table.

Vulnerability: Known-plaintext attack, Kasiski-like analysis.

The Porta cipher uses a tabula recta with 13 different substitution
alphabets (one for each pair of key letters). It is reciprocal:
encrypt and decrypt use the same operation.
"""

from __future__ import annotations

import string

from cryptovault.ciphers.base import CipherBase


def _build_porta_tableau() -> list[str]:
    """Build the 13 Porta substitution tables.

    Each table is a self-inverse permutation of A-Z.
    Table k shifts the alphabet by k positions in a specific way.

    Returns:
        List of 13 substitution strings (each 26 chars).
    """
    tables: list[str] = []
    for k in range(13):
        mapping: list[str] = [""] * 26
        for i in range(26):
            if i < 13:
                # First half (A-M) maps to second half (N-Z) with shift k
                target = 13 + (i + k) % 13
                mapping[i] = chr(ord("A") + target)
            else:
                # Second half (N-Z) maps to first half (A-M) with shift k
                target = (i - 13 + k) % 13
                mapping[i] = chr(ord("A") + target)

        # Make it self-inverse: if i->j then j->i
        for i in range(26):
            j = ord(mapping[i]) - ord("A")
            if i != j:
                # Check if j maps back to i, if not fix it
                if ord(mapping[j]) - ord("A") != i:
                    # Set j to map to i
                    mapping[j] = chr(ord("A") + i)

        tables.append("".join(mapping))
    return tables


_PORTA_TABLES = _build_porta_tableau()


def _porta_substitute(ch: str, key_char: str) -> str:
    """Apply Porta substitution for a single character.

    Args:
        ch: Plaintext character (A-Z).
        key_char: Key character (A-Z).

    Returns:
        Substituted character.
    """
    key_val = (ord(key_char.upper()) - ord("A")) // 2  # 0-12
    ch_val = ord(ch.upper()) - ord("A")
    return _PORTA_TABLES[key_val][ch_val]


class PortaCipher(CipherBase):
    """Porta cipher — polyalphabetic substitution with reciprocal table.

    Args:
        key: Encryption keyword.
    """

    def __init__(self, key: str = "KEY") -> None:
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)
        self._key = key.upper()

    @property
    def name(self) -> str:
        return "Porta Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using Porta cipher.

        Args:
            plaintext: Text to encrypt (letters only).
            key: Optional key override.

        Returns:
            Ciphertext string.
        """
        kw = key.upper() if key else self._key
        if not kw:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        result: list[str] = []
        ki = 0
        for ch in plaintext:
            if ch.isalpha():
                enc_char = _porta_substitute(ch, kw[ki % len(kw)])
                result.append(enc_char if ch.isupper() else enc_char.lower())
                ki += 1
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Porta cipher (Porta is reciprocal).

        Args:
            ciphertext: Text to decrypt.
            key: Optional key override.

        Returns:
            Recovered plaintext.
        """
        return self.encrypt(ciphertext, key)
