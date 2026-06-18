"""Bacon cipher — steganographic encoding using binary-coded letters.

Vulnerability: Visual inspection reveals pattern; low information density.

The Bacon cipher encodes each letter as a 5-bit binary string using
two distinct symbols (e.g., A/B or uppercase/lowercase). It can be
embedded in any text by marking two "types" of characters.
"""

from __future__ import annotations

from cryptovault.ciphers.base import CipherBase

# Standard 24-letter Bacon alphabet (I=J, U=V merged)
_BACON_ALPHABET: dict[str, str] = {}
for _i, _ch in enumerate("ABCDEFGHIKLMNOPQRSTUWXYZ"):
    _BACON_ALPHABET[_ch] = format(_i, "05b")
_BACON_DECODE: dict[str, str] = {v: k for k, v in _BACON_ALPHABET.items()}


class BaconCipher(CipherBase):
    """Bacon cipher — encode letters as 5-bit binary sequences.

    Uses the standard 24-letter Bacon alphabet (I/J and U/V merged).
    """

    @property
    def name(self) -> str:
        return "Bacon Cipher"

    def encrypt(self, plaintext: str, key: str = "") -> str:
        """Encode plaintext as Bacon cipher.

        Each letter becomes 5 characters: A=0, B=1.
        Non-alpha characters are stripped.

        Args:
            plaintext: Text to encode.
            key: Ignored.

        Returns:
            Binary string using A/B characters.
        """
        result: list[str] = []
        for ch in plaintext.upper():
            if ch == "J":
                ch = "I"
            elif ch == "V":
                ch = "U"
            if ch in _BACON_ALPHABET:
                bits = _BACON_ALPHABET[ch]
                result.append(bits.replace("0", "A").replace("1", "B"))
        return "".join(result)

    def decrypt(self, ciphertext: str, key: str = "") -> str:
        """Decode Bacon cipher back to plaintext.

        Args:
            ciphertext: Binary string of A/B characters.
            key: Ignored.

        Returns:
            Decoded plaintext (uppercase, I/J and U/V merged).
        """
        cleaned = "".join(c.upper() for c in ciphertext if c.upper() in "AB")
        result: list[str] = []
        for i in range(0, len(cleaned) - 4, 5):
            bits = cleaned[i : i + 5].replace("A", "0").replace("B", "1")
            if bits in _BACON_DECODE:
                result.append(_BACON_DECODE[bits])
        return "".join(result)

    def embed(self, plaintext: str, cover: str) -> str:
        """Embed Bacon-encoded message into cover text.

        Uses case to encode: lowercase=0, uppercase=1 for each letter.

        Args:
            plaintext: Message to hide.
            cover: Cover text to embed into.

        Returns:
            Cover text with hidden message.
        """
        encoded = self.encrypt(plaintext)
        cover_letters = [c for c in cover if c.isalpha()]

        if len(encoded) > len(cover_letters):
            msg = f"Cover text too short: need {len(encoded)} letters, have {len(cover_letters)}"
            raise ValueError(msg)

        result: list[str] = []
        enc_idx = 0
        for ch in cover:
            if ch.isalpha():
                if enc_idx < len(encoded):
                    bit = encoded[enc_idx]
                    if bit == "A":
                        result.append(ch.lower())
                    else:
                        result.append(ch.upper())
                    enc_idx += 1
                else:
                    result.append(ch)
            else:
                result.append(ch)
        return "".join(result)

    def extract(self, stego: str) -> str:
        """Extract hidden message from stego text.

        Reads case of each letter: lowercase=0, uppercase=1.

        Args:
            stego: Text with hidden message.

        Returns:
            Extracted plaintext.
        """
        bits: list[str] = []
        for ch in stego:
            if ch.isalpha():
                bits.append("0" if ch.islower() else "1")

        result: list[str] = []
        for i in range(0, len(bits) - 4, 5):
            word = "".join(bits[i : i + 5])
            if word in _BACON_DECODE:
                result.append(_BACON_DECODE[word])
        return "".join(result)
