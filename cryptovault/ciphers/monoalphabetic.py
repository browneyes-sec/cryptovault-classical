"""Monoalphabetic substitution cipher — general single-alphabet replacement.

Vulnerability: Frequency analysis, known-plaintext, crib-dragging.

The Monoalphabetic cipher is the most general form of letter-by-letter
substitution. The key is a 26-character permutation of the alphabet,
mapping each plaintext letter to a unique ciphertext letter.
"""

from __future__ import annotations

import string

from cryptovault.ciphers.base import CipherBase


class MonoalphabeticCipher(CipherBase):
    """Monoalphabetic substitution cipher with a custom alphabet mapping.

    Args:
        substitution_alphabet: 26-character string mapping A→sub[0], B→sub[1], etc.
                               Must be a permutation of A-Z.
    """

    def __init__(self, substitution_alphabet: str = "") -> None:
        if not substitution_alphabet:
            substitution_alphabet = "ZYXWVUTSRQPONMLKJIHGFEDCBA"
        sub = substitution_alphabet.upper()
        if len(sub) != 26 or set(sub) != set(string.ascii_uppercase):
            msg = "Substitution alphabet must be a permutation of A-Z"
            raise ValueError(msg)
        self._sub = sub
        self._reverse = [""] * 26
        for i, ch in enumerate(sub):
            self._reverse[ord(ch) - ord("A")] = chr(ord("A") + i)

    @property
    def name(self) -> str:
        return "Monoalphabetic Substitution"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using monoalphabetic substitution.

        Args:
            plaintext: Text to encrypt (letters shifted, non-letters preserved).
            key: Optional 26-char substitution alphabet.

        Returns:
            Ciphertext string.
        """
        sub = self._sub
        if key:
            k = key.upper()
            if len(k) != 26 or set(k) != set(string.ascii_uppercase):
                msg = "Key must be a permutation of A-Z (26 characters)"
                raise ValueError(msg)
            sub = k

        result: list[str] = []
        for ch in plaintext:
            if ch in string.ascii_lowercase:
                idx = ord(ch) - ord("a")
                result.append(sub[idx].lower())
            elif ch in string.ascii_uppercase:
                idx = ord(ch) - ord("A")
                result.append(sub[idx])
            else:
                result.append(ch)
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt monoalphabetic substitution.

        Args:
            ciphertext: Text to decrypt.
            key: Optional 26-char substitution alphabet.

        Returns:
            Recovered plaintext.
        """
        sub = self._sub
        if key:
            k = key.upper()
            if len(k) != 26 or set(k) != set(string.ascii_uppercase):
                msg = "Key must be a permutation of A-Z (26 characters)"
                raise ValueError(msg)
            sub = k

        reverse = [""] * 26
        for i, ch in enumerate(sub):
            reverse[ord(ch) - ord("A")] = chr(ord("A") + i)

        result: list[str] = []
        for ch in ciphertext:
            if ch in string.ascii_lowercase:
                idx = ord(ch) - ord("a")
                result.append(reverse[idx].lower())
            elif ch in string.ascii_uppercase:
                idx = ord(ch) - ord("A")
                result.append(reverse[idx])
            else:
                result.append(ch)
        return "".join(result)

    def crack(self, ciphertext: str, **kwargs: object) -> list[tuple[str, str, float]]:
        """Crack monoalphabetic cipher using frequency analysis.

        Uses hill-climbing with chi-squared fitness scoring.

        Args:
            ciphertext: The ciphertext to crack.
            **kwargs: Optional 'iterations' (default 1000).

        Returns:
            List of (key, plaintext, confidence) tuples.
        """
        import random

        from cryptovault.cryptanalysis.frequency import chi_squared_test

        iterations = int(kwargs.get("iterations", 1000))

        def _apply_mapping(text: str, mapping: str) -> str:
            rev = [""] * 26
            for i, ch in enumerate(mapping):
                rev[ord(ch) - ord("A")] = chr(ord("A") + i)
            result: list[str] = []
            for ch in text:
                if ch in string.ascii_uppercase:
                    result.append(rev[ord(ch) - ord("A")])
                elif ch in string.ascii_lowercase:
                    result.append(rev[ord(ch) - ord("A")].lower())
                else:
                    result.append(ch)
            return "".join(result)

        current_map = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        current_plain = _apply_mapping(ciphertext, current_map)
        current_score = chi_squared_test(current_plain)

        best_map = current_map
        best_plain = current_plain
        best_score = current_score

        for _ in range(iterations):
            new_map = list(current_map)
            i, j = random.sample(range(26), 2)
            new_map[i], new_map[j] = new_map[j], new_map[i]
            new_map_str = "".join(new_map)

            new_plain = _apply_mapping(ciphertext, new_map_str)
            new_score = chi_squared_test(new_plain)

            if new_score < current_score:
                current_map = new_map_str
                current_plain = new_plain
                current_score = new_score
                if new_score < best_score:
                    best_map = new_map_str
                    best_plain = new_plain
                    best_score = new_score

        confidence = 1.0 / (1.0 + best_score)
        return [(best_map, best_plain, confidence)]
