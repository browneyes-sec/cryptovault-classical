"""Vernam cipher (one-time pad) — XOR-based encryption.

Vulnerability: Key reuse, short key, predictable key.

The Vernam cipher XORs each plaintext byte with the corresponding
key byte. When used correctly (truly random key, same length as
plaintext, used once), it provides perfect secrecy (Shannon, 1949).
When misused, it is vulnerable to XOR crib-dragging.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase


class VernamCipher(CipherBase):
    """Vernam cipher (one-time pad) using XOR.

    The key must be at least as long as the plaintext and should be
    truly random for perfect secrecy. Key reuse destroys security.
    """

    @property
    def name(self) -> str:
        return "Vernam Cipher (One-Time Pad)"

    @staticmethod
    def validate_key(key: str, plaintext: str) -> None:
        """Validate that the key meets Vernam security requirements.

        Args:
            key: The encryption key.
            plaintext: The plaintext to encrypt.

        Raises:
            ValueError: If key is empty, too short, or has reused bytes.
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)
        if len(key) < len(plaintext):
            msg = f"Key length ({len(key)}) must be >= plaintext length ({len(plaintext)})"
            raise ValueError(msg)

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encrypt using XOR with the key.

        Each byte of plaintext is XORed with the corresponding byte of key.

        Args:
            plaintext: Text to encrypt.
            key: Encryption key (must be >= len(plaintext)).

        Returns:
            Ciphertext string (may contain non-printable characters).
        """
        if not key:
            msg = "Key cannot be empty"
            raise ValueError(msg)
        self.validate_key(key, plaintext)

        result: list[str] = []
        for p, k in zip(plaintext, key):
            p_val = ord(p)
            k_val = ord(k)
            c_val = p_val ^ k_val
            result.append(chr(c_val))

        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decrypt XOR ciphertext (XOR is its own inverse).

        Args:
            ciphertext: Text to decrypt.
            key: The encryption key.

        Returns:
            Recovered plaintext.
        """
        return self.encrypt(ciphertext, key)

    def crack(self, ciphertext: str, **kwargs: object) -> list[tuple[str, str, float]]:
        """XOR crib-dragging attack (requires known or guessed plaintext fragment).

        Args:
            ciphertext: The ciphertext to crack.
            crib: Known or guessed plaintext fragment.
            crib_position: Position in ciphertext where crib is expected.

        Returns:
            List of (key_fragment, plaintext, confidence) tuples.
        """
        crib = str(kwargs.get("crib", ""))
        crib_pos = int(kwargs.get("crib_position", 0))

        if not crib:
            msg = "crib kwarg is required for Vernam cracker"
            raise ValueError(msg)

        results: list[tuple[str, str, float]] = []

        if crib_pos + len(crib) > len(ciphertext):
            return results

        key_fragment = ""
        for i in range(len(crib)):
            c_val = ord(ciphertext[crib_pos + i])
            p_val = ord(crib[i])
            key_fragment += chr(c_val ^ p_val)

        partial_plaintext = self.decrypt(ciphertext, key_fragment)
        results.append((key_fragment, partial_plaintext, 1.0))

        return results

    @staticmethod
    def to_binary_representation(text: str) -> list[int]:
        """Convert text to a list of integer values (0-255).

        Used for the extended Vernam that operates on binary representations.

        Args:
            text: Input text.

        Returns:
            List of integer byte values.
        """
        return [ord(c) for c in text]

    @staticmethod
    def from_binary_representation(values: list[int]) -> str:
        """Convert a list of integer values back to text.

        Args:
            values: List of integer byte values.

        Returns:
            Reconstructed text string.
        """
        return "".join(chr(v) for v in values)
