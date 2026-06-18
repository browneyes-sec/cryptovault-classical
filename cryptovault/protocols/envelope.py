"""Encrypt-then-MAC envelope for secure message packaging.

Combines encryption and authentication into a single envelope format:
  [ciphertext_length][ciphertext][mac_tag]

This follows the Encrypt-then-MAC paradigm which is provably secure
under standard assumptions.
"""

from __future__ import annotations

import os
import struct

from cryptovault.protocols.mac import HMAC, create_mac, verify_mac


class SecureEnvelope:
    """Encrypt-then-MAC envelope for message protection.

    Combines a cipher with HMAC authentication.

    Args:
        cipher: Cipher instance with encrypt/decrypt methods.
        mac_key: Key for HMAC authentication.
    """

    def __init__(self, cipher: object, mac_key: bytes | None = None) -> None:
        self._cipher = cipher
        self._hmac = HMAC(mac_key)

    @property
    def mac_key(self) -> bytes:
        """Get the MAC key."""
        return self._hmac.key

    def seal(self, plaintext: str, cipher_key: str) -> bytes:
        """Encrypt and authenticate a message.

        Args:
            plaintext: Message to protect.
            cipher_key: Key for the cipher.

        Returns:
            Envelope bytes: [4-byte len][ciphertext][32-byte MAC].
        """
        ciphertext = self._cipher.encrypt(plaintext, cipher_key)
        ct_bytes = ciphertext.encode("utf-8")

        length_prefix = struct.pack("!I", len(ct_bytes))
        mac_input = length_prefix + ct_bytes
        mac_tag = self._hmac.compute(mac_input)

        return length_prefix + ct_bytes + mac_tag

    def open(self, envelope: bytes, cipher_key: str) -> str | None:
        """Verify and decrypt an envelope.

        Args:
            envelope: Envelope bytes.
            cipher_key: Key for the cipher.

        Returns:
            Decrypted plaintext, or None if MAC verification fails.
        """
        if len(envelope) < 4 + 32:
            return None

        ct_len = struct.unpack("!I", envelope[:4])[0]
        if len(envelope) < 4 + ct_len + 32:
            return None

        ct_bytes = envelope[4 : 4 + ct_len]
        mac_tag = envelope[4 + ct_len : 4 + ct_len + 32]

        mac_input = envelope[: 4 + ct_len]
        if not self._hmac.verify(mac_input, mac_tag):
            return None

        ciphertext = ct_bytes.decode("utf-8")
        return self._cipher.decrypt(ciphertext, cipher_key)

    def seal_raw(self, plaintext: str, cipher_key: str) -> tuple[str, bytes]:
        """Encrypt and return ciphertext + MAC separately.

        Args:
            plaintext: Message to protect.
            cipher_key: Key for the cipher.

        Returns:
            Tuple of (ciphertext_string, mac_tag_bytes).
        """
        ciphertext = self._cipher.encrypt(plaintext, cipher_key)
        ct_bytes = ciphertext.encode("utf-8")
        mac_tag = self._hmac.compute(ct_bytes)
        return ciphertext, mac_tag

    def open_raw(self, ciphertext: str, cipher_key: str, mac_tag: bytes) -> str | None:
        """Verify MAC and decrypt.

        Args:
            ciphertext: Ciphertext string.
            cipher_key: Key for the cipher.
            mac_tag: MAC tag bytes.

        Returns:
            Decrypted plaintext, or None if MAC verification fails.
        """
        ct_bytes = ciphertext.encode("utf-8")
        if not self._hmac.verify(ct_bytes, mac_tag):
            return None
        return self._cipher.decrypt(ciphertext, cipher_key)


class SimpleEnvelope:
    """Simplified envelope using XOR encryption + HMAC.

    For educational purposes; combines Vernam XOR with HMAC.

    Args:
        mac_key: Key for HMAC authentication.
    """

    def __init__(self, mac_key: bytes | None = None) -> None:
        self._hmac = HMAC(mac_key)

    def seal(self, plaintext: str, encryption_key: bytes) -> bytes:
        """Encrypt with XOR and add HMAC.

        Args:
            plaintext: Message to protect.
            encryption_key: XOR encryption key.

        Returns:
            Envelope bytes.
        """
        pt_bytes = plaintext.encode("utf-8")
        ct_bytes = bytes(p ^ k for p, k in zip(pt_bytes, encryption_key * (len(pt_bytes) // len(encryption_key) + 1)))

        length_prefix = struct.pack("!I", len(ct_bytes))
        mac_input = length_prefix + ct_bytes
        mac_tag = self._hmac.compute(mac_input)

        return length_prefix + ct_bytes + mac_tag

    def open(self, envelope: bytes, encryption_key: bytes) -> str | None:
        """Verify HMAC and decrypt XOR.

        Args:
            envelope: Envelope bytes.
            encryption_key: XOR decryption key.

        Returns:
            Decrypted plaintext, or None if MAC verification fails.
        """
        if len(envelope) < 4 + 32:
            return None

        ct_len = struct.unpack("!I", envelope[:4])[0]
        if len(envelope) < 4 + ct_len + 32:
            return None

        ct_bytes = envelope[4 : 4 + ct_len]
        mac_tag = envelope[4 + ct_len : 4 + ct_len + 32]

        mac_input = envelope[: 4 + ct_len]
        if not self._hmac.verify(mac_input, mac_tag):
            return None

        pt_bytes = bytes(c ^ k for c, k in zip(ct_bytes, encryption_key * (len(ct_bytes) // len(encryption_key) + 1)))
        return pt_bytes.decode("utf-8")
