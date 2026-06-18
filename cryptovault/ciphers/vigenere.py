"""Vigenère cipher — polyalphabetic substitution using a keyword.

Vulnerability: Kasiski examination, Index of Coincidence.

The Vigenère cipher uses a keyword to determine the shift for each
position in the plaintext. Unlike Caesar, it resists simple frequency
analysis but is vulnerable to Kasiski and IoC-based attacks.
"""

from __future__ import annotations

import string

from cryptovault.ciphers.base import CipherBase


class VigenereCipher(CipherBase):
    """Vigenère cipher with full encrypt/decrypt support.

    Operates on letters only (a-z, A-Z). Non-letter characters are
    preserved but do not advance the key position.
    """

    @property
    def name(self) -> str:
        return "Vigenère Cipher"

    @staticmethod
    def _expand_key(text: str, key: str) -> str:
        """Repeat key to match the length of text (letters only).

        Args:
            text: The plaintext or ciphertext.
            key: The keyword to repeat.

        Returns:
            Key string expanded to match letter count in text.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)
        key_letters = [c for c in key if c.isalpha()]
        if not key_letters:
            msg = "Key must contain at least one letter"
            raise ValueError(msg)

        result: list[str] = []
        ki = 0
        for _ in text:
            result.append(key_letters[ki % len(key_letters)])
            ki += 1
        return "".join(result)

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using Vigenère polyalphabetic substitution on letters.

        C[i] = (P[i] + K[i]) % 26, applied only to letter characters.
        Non-letter characters are preserved unchanged.

        Args:
            plaintext: Text to encrypt.
            key: Encryption keyword (non-empty, letters only).

        Returns:
            Ciphertext string.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        expanded = self._expand_key(plaintext, key)
        result: list[str] = []
        ki = 0

        for p in plaintext:
            if p.isalpha():
                k = expanded[ki]
                ki += 1
                if p.isupper():
                    p_val = ord(p) - ord("A")
                    k_val = ord(k.upper()) - ord("A")
                    c_val = (p_val + k_val) % 26
                    result.append(chr(ord("A") + c_val))
                else:
                    p_val = ord(p) - ord("a")
                    k_val = ord(k.lower()) - ord("a")
                    c_val = (p_val + k_val) % 26
                    result.append(chr(ord("a") + c_val))
            else:
                result.append(p)

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt Vigenère ciphertext.

        P[i] = (C[i] - K[i]) % 26, applied only to letter characters.

        Args:
            ciphertext: Text to decrypt.
            key: The encryption keyword.

        Returns:
            Recovered plaintext.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)

        expanded = self._expand_key(ciphertext, key)
        result: list[str] = []
        ki = 0

        for c in ciphertext:
            if c.isalpha():
                k = expanded[ki]
                ki += 1
                if c.isupper():
                    c_val = ord(c) - ord("A")
                    k_val = ord(k.upper()) - ord("A")
                    p_val = (c_val - k_val) % 26
                    result.append(chr(ord("A") + p_val))
                else:
                    c_val = ord(c) - ord("a")
                    k_val = ord(k.lower()) - ord("a")
                    p_val = (c_val - k_val) % 26
                    result.append(chr(ord("a") + p_val))
            else:
                result.append(c)

        return "".join(result)

    def crack(self, ciphertext: str, **kwargs: object) -> list[tuple[str, str, float]]:
        """Attempt to crack Vigenère using Kasiski examination.

        Args:
            ciphertext: The ciphertext to crack.

        Returns:
            List of (key, plaintext, confidence) tuples, ranked by IoC fitness.
        """
        from cryptovault.cryptanalysis.kasiski import estimate_key_length, recover_key

        results: list[tuple[str, str, float]] = []
        max_key_length = min(20, len(ciphertext) // 3)

        if max_key_length < 2:
            return results

        for kl in range(2, max_key_length + 1):
            try:
                key = recover_key(ciphertext, kl)
                plaintext = self.decrypt(ciphertext, key)
                from cryptovault.cryptanalysis.index_of_coincidence import index_of_coincidence

                ioc = index_of_coincidence(plaintext)
                results.append((key, plaintext, ioc))
            except (ValueError, IndexError):
                continue

        results.sort(key=lambda x: x[2], reverse=True)
        return results
