"""Tests for all cipher implementations — Known Answer Tests (KATs) and roundtrips."""

from __future__ import annotations

import pytest

from cryptovault.ciphers.caesar import CaesarCipher, brute_force_caesar
from cryptovault.ciphers.vigenere import VigenereCipher
from cryptovault.ciphers.vernam import VernamCipher
from cryptovault.ciphers.transposition import (
    ColumnarTransposition,
    InvertedColumnarTransposition,
    SymmetricColumnarTransposition,
)
from cryptovault.ciphers.binary_utils import bin_to_dec, dec_to_bin, xor_bits, xor_bytes


# ============================================================
# Caesar Cipher Tests
# ============================================================


class TestCaesarCipher:
    """Test Caesar cipher encrypt, decrypt, and brute-force."""

    def test_encrypt_shift_3(self) -> None:
        c = CaesarCipher(3)
        assert c.encrypt("abc") == "def"
        assert c.encrypt("xyz") == "abc"
        assert c.encrypt("Hello, World!") == "Khoor, Zruog!"

    def test_decrypt_shift_3(self) -> None:
        c = CaesarCipher(3)
        assert c.decrypt("def") == "abc"
        assert c.decrypt("abc") == "xyz"
        assert c.decrypt("Khoor, Zruog!") == "Hello, World!"

    def test_roundtrip_all_shifts(self) -> None:
        plaintext = "The quick brown fox jumps over the lazy dog"
        for shift in range(26):
            c = CaesarCipher(shift)
            ciphertext = c.encrypt(plaintext)
            recovered = c.decrypt(ciphertext)
            assert recovered == plaintext, f"Failed for shift={shift}"

    def test_encrypt_with_key_override(self) -> None:
        c = CaesarCipher(3)
        assert c.encrypt("abc", key=5) == "fgh"
        assert c.decrypt("fgh", key=5) == "abc"

    def test_invalid_shift_raises(self) -> None:
        with pytest.raises(ValueError, match="Shift must be 0-25"):
            CaesarCipher(26)
        with pytest.raises(ValueError, match="Shift must be 0-25"):
            CaesarCipher(-1)

    def test_preserves_non_alpha(self) -> None:
        c = CaesarCipher(3)
        assert c.encrypt("a b c") == "d e f"
        assert c.encrypt("123!@#") == "123!@#"

    def test_brute_force_returns_26_results(self) -> None:
        ciphertext = CaesarCipher(7).encrypt("attack at dawn")
        results = brute_force_caesar(ciphertext)
        assert len(results) == 26

    def test_brute_force_finds_correct_shift(self) -> None:
        plaintext = "the enemy attacks at midnight"
        shift = 13
        ciphertext = CaesarCipher(shift).encrypt(plaintext)
        results = brute_force_caesar(ciphertext)
        best_shift, best_text, _ = results[0]
        assert best_shift == shift
        assert best_text == plaintext

    def test_crack_method(self) -> None:
        plaintext = "this is a secret message"
        ciphertext = CaesarCipher(5).encrypt(plaintext)
        results = CaesarCipher().crack(ciphertext)
        assert len(results) > 0
        assert results[0][1] == plaintext


# ============================================================
# Vigenère Cipher Tests
# ============================================================


class TestVigenereCipher:
    """Test Vigenère cipher encrypt and decrypt."""

    def test_encrypt_basic(self) -> None:
        v = VigenereCipher()
        result = v.encrypt("hello", "key")
        assert result != "hello"
        assert len(result) == 5

    def test_decrypt_basic(self) -> None:
        v = VigenereCipher()
        plaintext = "hello"
        key = "key"
        ciphertext = v.encrypt(plaintext, key)
        recovered = v.decrypt(ciphertext, key)
        assert recovered == plaintext

    def test_roundtrip_various_keys(self) -> None:
        v = VigenereCipher()
        plaintext = "Attack at dawn!"
        keys = ["A", "KEY", "SECRET", "a", "abc"]
        for key in keys:
            ciphertext = v.encrypt(plaintext, key)
            recovered = v.decrypt(ciphertext, key)
            assert recovered == plaintext, f"Failed for key={key!r}"

    def test_empty_key_raises(self) -> None:
        v = VigenereCipher()
        with pytest.raises(ValueError, match="Key cannot be empty"):
            v.encrypt("hello", "")
        with pytest.raises(ValueError, match="Key cannot be empty"):
            v.decrypt("hello", "")

    def test_encrypt_produces_different_output(self) -> None:
        v = VigenereCipher()
        assert v.encrypt("aaa", "key") != v.encrypt("aaa", "abc")

    def test_key_expansion(self) -> None:
        # Key is repeated to match letter count in text
        assert VigenereCipher._expand_key("hello", "key") == "keyke"
        assert VigenereCipher._expand_key("hi", "abc") == "ab"
        # Non-alpha chars don't consume key positions
        assert len(VigenereCipher._expand_key("a b c", "key")) == 5

    def test_non_alpha_preserved(self) -> None:
        v = VigenereCipher()
        # a+k=k, b+e=f, c+y=a (key consumed only for letters)
        assert v.encrypt("a b c", "key") == "k f a"
        assert v.decrypt("k f a", "key") == "a b c"


# ============================================================
# Vernam Cipher Tests
# ============================================================


class TestVernamCipher:
    """Test Vernam cipher (one-time pad) encrypt, decrypt, and validation."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        v = VernamCipher()
        plaintext = "hello"
        key = "world"
        ciphertext = v.encrypt(plaintext, key)
        recovered = v.decrypt(ciphertext, key)
        assert recovered == plaintext

    def test_different_keys_different_output(self) -> None:
        v = VernamCipher()
        plaintext = "hello"
        c1 = v.encrypt(plaintext, "key1")
        c2 = v.encrypt(plaintext, "key2")
        assert c1 != c2

    def test_empty_key_raises(self) -> None:
        v = VernamCipher()
        with pytest.raises(ValueError, match="Key cannot be empty"):
            v.encrypt("hello", "")

    def test_short_key_raises(self) -> None:
        v = VernamCipher()
        with pytest.raises(ValueError, match="Key length"):
            v.encrypt("hello", "ab")

    def test_validate_key_success(self) -> None:
        VernamCipher.validate_key("hello", "hi")

    def test_validate_key_too_short(self) -> None:
        with pytest.raises(ValueError, match="Key length"):
            VernamCipher.validate_key("ab", "hello")

    def test_xor_property(self) -> None:
        v = VernamCipher()
        plaintext = "test"
        key = "key!"
        ciphertext = v.encrypt(plaintext, key)
        recovered = v.decrypt(ciphertext, key)
        assert recovered == plaintext

    def test_crib_drag(self) -> None:
        v = VernamCipher()
        plaintext = "hello world"
        key = "abcdefghijklmnopqrs"
        ciphertext = v.encrypt(plaintext, key)
        results = v.crack(ciphertext, crib="hello", crib_position=0)
        assert len(results) == 1
        assert results[0][0] == key[:5]

    def test_binary_representation(self) -> None:
        text = "abc"
        values = VernamCipher.to_binary_representation(text)
        assert values == [97, 98, 99]
        assert VernamCipher.from_binary_representation(values) == text


# ============================================================
# Transposition Cipher Tests
# ============================================================


class TestColumnarTransposition:
    """Test columnar transposition cipher."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        ct = ColumnarTransposition()
        plaintext = "HELLOWORLD"
        key = "KEY"
        ciphertext = ct.encrypt(plaintext, key)
        recovered = ct.decrypt(ciphertext, key)
        assert recovered.replace(" ", "") == plaintext

    def test_encrypt_produces_output(self) -> None:
        ct = ColumnarTransposition()
        result = ct.encrypt("HELLO", "KEY")
        assert len(result) > 0

    def test_empty_key_raises(self) -> None:
        ct = ColumnarTransposition()
        with pytest.raises(ValueError, match="Key cannot be empty"):
            ct.encrypt("HELLO", "")

    def test_different_keys_different_output(self) -> None:
        ct = ColumnarTransposition()
        text = "HELLOWORLD"
        # KEY and ABC have different orderings
        c1 = ct.encrypt(text, "KEY")
        c2 = ct.encrypt(text, "ABC")
        assert c1 != c2

    def test_longer_text(self) -> None:
        ct = ColumnarTransposition()
        plaintext = "ATTACKATDAWN"
        key = "LEMON"
        ciphertext = ct.encrypt(plaintext, key)
        recovered = ct.decrypt(ciphertext, key)
        assert recovered.replace(" ", "") == plaintext


class TestInvertedColumnarTransposition:
    """Test inverted columnar transposition cipher."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        ct = InvertedColumnarTransposition()
        plaintext = "HELLOWORLD"
        key = "KEY"
        ciphertext = ct.encrypt(plaintext, key)
        recovered = ct.decrypt(ciphertext, key)
        assert recovered.replace(" ", "") == plaintext

    def test_different_from_standard(self) -> None:
        std = ColumnarTransposition()
        inv = InvertedColumnarTransposition()
        text = "HELLOWORLD"
        key = "KEY"
        assert std.encrypt(text, key) != inv.encrypt(text, key)


class TestSymmetricColumnarTransposition:
    """Test symmetric columnar transposition cipher."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        ct = SymmetricColumnarTransposition()
        plaintext = "HELLOWORLD"
        key = "KEY"
        ciphertext = ct.encrypt(plaintext, key)
        recovered = ct.decrypt(ciphertext, key)
        assert recovered.replace(" ", "") == plaintext


# ============================================================
# Binary Utils Tests
# ============================================================


class TestBinaryUtils:
    """Test binary/decimal conversion and XOR operations."""

    @pytest.mark.parametrize(
        ("binary", "expected"),
        [
            ("0", 0),
            ("1", 1),
            ("10", 2),
            ("1011", 11),
            ("11111111", 255),
        ],
    )
    def test_bin_to_dec(self, binary: str, expected: int) -> None:
        assert bin_to_dec(binary) == expected

    @pytest.mark.parametrize(
        ("decimal", "expected"),
        [
            (0, "0"),
            (1, "1"),
            (2, "10"),
            (11, "1011"),
            (255, "11111111"),
        ],
    )
    def test_dec_to_bin(self, decimal: int, expected: str) -> None:
        assert dec_to_bin(decimal) == expected

    def test_bin_dec_roundtrip(self) -> None:
        for n in range(100):
            assert bin_to_dec(dec_to_bin(n)) == n

    def test_xor_bits(self) -> None:
        assert xor_bits("1100", "1010") == "0110"
        assert xor_bits("0000", "1111") == "1111"
        assert xor_bits("1010", "1010") == "0000"

    def test_xor_bits_roundtrip(self) -> None:
        a = "11001010"
        b = "10101100"
        assert xor_bits(xor_bits(a, b), b) == a

    def test_xor_bytes(self) -> None:
        assert xor_bytes(b"\xff\x00", b"\x0f\x0f") == b"\xf0\x0f"

    def test_invalid_binary_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid binary"):
            bin_to_dec("102")

    def test_empty_binary_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            bin_to_dec("")

    def test_negative_decimal_raises(self) -> None:
        with pytest.raises(ValueError, match="negative"):
            dec_to_bin(-1)

    def test_xor_different_length_raises(self) -> None:
        with pytest.raises(ValueError, match="equal length"):
            xor_bits("10", "101")

    def test_xor_empty_raises(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            xor_bits("", "")

    def test_xor_bytes_different_length_raises(self) -> None:
        with pytest.raises(ValueError, match="equal length"):
            xor_bytes(b"\x01", b"\x01\x02")
