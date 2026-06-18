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
from cryptovault.ciphers.playfair import PlayfairCipher
from cryptovault.ciphers.railfence import RailFenceCipher
from cryptovault.ciphers.affine import AffineCipher
from cryptovault.ciphers.atbash import AtbashCipher
from cryptovault.ciphers.bacon import BaconCipher
from cryptovault.ciphers.hill import HillCipher
from cryptovault.ciphers.bifid import BifidCipher
from cryptovault.ciphers.trifid import TrifidCipher
from cryptovault.ciphers.foursquare import FourSquareCipher
from cryptovault.ciphers.porta import PortaCipher
from cryptovault.ciphers.adfgvx import ADFGVXCipher
from cryptovault.ciphers.monoalphabetic import MonoalphabeticCipher
from cryptovault.ciphers.myszkowski import MyszkowskiCipher


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
        assert VigenereCipher._expand_key("hello", "key") == "keyke"
        assert VigenereCipher._expand_key("hi", "abc") == "ab"
        assert len(VigenereCipher._expand_key("a b c", "key")) == 5

    def test_non_alpha_preserved(self) -> None:
        v = VigenereCipher()
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


# ============================================================
# Playfair Cipher Tests
# ============================================================


class TestPlayfairCipher:
    """Test Playfair cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        pf = PlayfairCipher("KEYWORD")
        plaintext = "HELLO"
        ciphertext = pf.encrypt(plaintext)
        recovered = pf.decrypt(ciphertext)
        assert recovered == plaintext

    def test_encrypt_produces_output(self) -> None:
        pf = PlayfairCipher("SECRET")
        result = pf.encrypt("ATTACK")
        assert len(result) > 0
        assert result.isalpha()

    def test_different_keys_different_output(self) -> None:
        plaintext = "HELLO"
        c1 = PlayfairCipher("KEY").encrypt(plaintext)
        c2 = PlayfairCipher("CAT").encrypt(plaintext)
        assert c1 != c2

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="Key cannot be empty"):
            PlayfairCipher("")


# ============================================================
# Rail Fence Cipher Tests
# ============================================================


class TestRailFenceCipher:
    """Test Rail Fence cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip_2_rails(self) -> None:
        rf = RailFenceCipher(2)
        plaintext = "WEAREDISCOVEREDFLEEATONCE"
        ciphertext = rf.encrypt(plaintext)
        recovered = rf.decrypt(ciphertext)
        assert recovered == plaintext

    def test_encrypt_decrypt_roundtrip_3_rails(self) -> None:
        rf = RailFenceCipher(3)
        plaintext = "HELLO WORLD"
        ciphertext = rf.encrypt(plaintext)
        recovered = rf.decrypt(ciphertext)
        assert recovered == plaintext

    def test_invalid_rails_raises(self) -> None:
        with pytest.raises(ValueError, match="Rails must be >= 2"):
            RailFenceCipher(1)

    def test_key_override(self) -> None:
        rf = RailFenceCipher(2)
        plaintext = "HELLO"
        ciphertext = rf.encrypt(plaintext, key="3")
        recovered = rf.decrypt(ciphertext, key="3")
        assert recovered == plaintext


# ============================================================
# Affine Cipher Tests
# ============================================================


class TestAffineCipher:
    """Test Affine cipher encrypt, decrypt, and brute-force."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        ac = AffineCipher(5, 8)
        plaintext = "HELLO"
        ciphertext = ac.encrypt(plaintext)
        recovered = ac.decrypt(ciphertext)
        assert recovered == plaintext

    def test_invalid_a_raises(self) -> None:
        with pytest.raises(ValueError, match="not coprime"):
            AffineCipher(2, 0)

    def test_brute_force_finds_key(self) -> None:
        ac = AffineCipher(5, 8)
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        ciphertext = ac.encrypt(plaintext)
        results = ac.crack(ciphertext)
        assert len(results) == 12 * 26
        best_key, best_text, _ = results[0]
        assert best_text == plaintext

    def test_preserves_non_alpha(self) -> None:
        ac = AffineCipher(3, 5)
        assert ac.encrypt("123!@#") == "123!@#"

    def test_crack_with_longer_text(self) -> None:
        ac = AffineCipher(7, 3)
        plaintext = "Attack at dawn is a good plan of action for the army"
        ciphertext = ac.encrypt(plaintext)
        results = ac.crack(ciphertext)
        best_key, best_text, _ = results[0]
        assert best_text == plaintext


# ============================================================
# Atbash Cipher Tests
# ============================================================


class TestAtbashCipher:
    """Test Atbash cipher is an involution."""

    def test_encrypt_decrypt_same(self) -> None:
        ac = AtbashCipher()
        plaintext = "HELLO"
        ciphertext = ac.encrypt(plaintext)
        assert ac.decrypt(ciphertext) == plaintext

    def test_involution(self) -> None:
        ac = AtbashCipher()
        text = "TEST"
        assert ac.encrypt(ac.encrypt(text)) == text

    def test_known_mapping(self) -> None:
        ac = AtbashCipher()
        assert ac.encrypt("A") == "Z"
        assert ac.encrypt("B") == "Y"
        assert ac.encrypt("Z") == "A"


# ============================================================
# Bacon Cipher Tests
# ============================================================


class TestBaconCipher:
    """Test Bacon cipher encoding and steganography."""

    def test_encode_decode_roundtrip(self) -> None:
        bc = BaconCipher()
        plaintext = "HELLO"
        encoded = bc.encrypt(plaintext)
        decoded = bc.decrypt(encoded)
        assert decoded == plaintext

    def test_embed_extract(self) -> None:
        bc = BaconCipher()
        message = "HI"
        cover = "This is a simple test cover text for embedding"
        stego = bc.embed(message, cover)
        extracted = bc.extract(stego)
        assert extracted == message

    def test_cover_too_short_raises(self) -> None:
        bc = BaconCipher()
        with pytest.raises(ValueError, match="Cover text too short"):
            bc.embed("HELLO", "AB")


# ============================================================
# Hill Cipher Tests
# ============================================================


class TestHillCipher:
    """Test Hill cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip_3x3(self) -> None:
        hc = HillCipher()
        plaintext = "ACT"
        ciphertext = hc.encrypt(plaintext)
        recovered = hc.decrypt(ciphertext)
        assert recovered == plaintext

    def test_encrypt_decrypt_roundtrip_2x2(self) -> None:
        matrix = [[3, 3], [2, 5]]
        hc = HillCipher(matrix)
        plaintext = "HELP"
        ciphertext = hc.encrypt(plaintext)
        recovered = hc.decrypt(ciphertext)
        assert recovered == plaintext

    def test_non_invertible_raises(self) -> None:
        with pytest.raises(ValueError, match="not invertible"):
            HillCipher([[1, 2], [3, 4]])


# ============================================================
# Bifid Cipher Tests
# ============================================================


class TestBifidCipher:
    """Test Bifid cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        bc = BifidCipher("KEYWORD")
        plaintext = "HELLO"
        ciphertext = bc.encrypt(plaintext)
        recovered = bc.decrypt(ciphertext)
        assert recovered == plaintext


# ============================================================
# Trifid Cipher Tests
# ============================================================


class TestTrifidCipher:
    """Test Trifid cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        tc = TrifidCipher("SECRET")
        plaintext = "HELLO"
        ciphertext = tc.encrypt(plaintext)
        recovered = tc.decrypt(ciphertext)
        assert recovered == plaintext

    def test_encrypt_decrypt_longer(self) -> None:
        tc = TrifidCipher("KEYWORD")
        plaintext = "ATTACK"
        ciphertext = tc.encrypt(plaintext)
        assert tc.decrypt(ciphertext) == plaintext


# ============================================================
# Four-Square Cipher Tests
# ============================================================


class TestFourSquareCipher:
    """Test Four-Square cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        fsc = FourSquareCipher("EXAMPLE", "KEYWORD")
        plaintext = "HELLO"
        ciphertext = fsc.encrypt(plaintext)
        recovered = fsc.decrypt(ciphertext)
        assert recovered == plaintext


# ============================================================
# Porta Cipher Tests
# ============================================================


class TestPortaCipher:
    """Test Porta cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        pc = PortaCipher("KEY")
        plaintext = "HELLO"
        ciphertext = pc.encrypt(plaintext)
        recovered = pc.decrypt(ciphertext)
        assert recovered == plaintext

    def test_reciprocal(self) -> None:
        pc = PortaCipher("SECRET")
        plaintext = "ATTACK"
        ciphertext = pc.encrypt(plaintext)
        assert pc.decrypt(ciphertext) == plaintext

    def test_longer_text(self) -> None:
        pc = PortaCipher("KEY")
        plaintext = "THEQUICKBROWNFOX"
        ciphertext = pc.encrypt(plaintext)
        assert pc.decrypt(ciphertext) == plaintext


# ============================================================
# ADFGVX Cipher Tests
# ============================================================


class TestADFGVXCipher:
    """Test ADFGVX cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        ac = ADFGVXCipher("SECRET", "CARGO")
        plaintext = "HELLO123"
        ciphertext = ac.encrypt(plaintext)
        recovered = ac.decrypt(ciphertext)
        assert recovered == plaintext

    def test_encrypt_decrypt_longer(self) -> None:
        ac = ADFGVXCipher("SECRET", "CARGO")
        plaintext = "ATTACKATDAWN007"
        ciphertext = ac.encrypt(plaintext)
        recovered = ac.decrypt(ciphertext)
        assert recovered == plaintext

    def test_output_uses_adfgvx_chars(self) -> None:
        ac = ADFGVXCipher()
        ciphertext = ac.encrypt("ATTACK")
        assert all(c in "ADFGVX" for c in ciphertext)


# ============================================================
# Monoalphabetic Cipher Tests
# ============================================================


class TestMonoalphabeticCipher:
    """Test Monoalphabetic substitution cipher."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        mc = MonoalphabeticCipher()
        plaintext = "HELLO"
        ciphertext = mc.encrypt(plaintext)
        recovered = mc.decrypt(ciphertext)
        assert recovered == plaintext

    def test_crack(self) -> None:
        mc = MonoalphabeticCipher()
        plaintext = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
        ciphertext = mc.encrypt(plaintext)
        results = mc.crack(ciphertext, iterations=500)
        assert len(results) == 1
        _, best_text, _ = results[0]
        assert best_text == plaintext

    def test_invalid_alphabet_raises(self) -> None:
        with pytest.raises(ValueError, match="permutation"):
            MonoalphabeticCipher("TOO_SHORT")
        with pytest.raises(ValueError, match="permutation"):
            MonoalphabeticCipher("ABCDEFGHIJKLMNOPQRSTUVWXYZA")


# ============================================================
# Myszkowski Cipher Tests
# ============================================================


class TestMyszkowskiCipher:
    """Test Myszkowski cipher encrypt and decrypt."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        mc = MyszkowskiCipher("SECRET")
        plaintext = "HELLOWORLD"
        ciphertext = mc.encrypt(plaintext)
        recovered = mc.decrypt(ciphertext)
        assert recovered == plaintext

    def test_different_from_standard_columnar(self) -> None:
        std = ColumnarTransposition()
        mys = MyszkowskiCipher("SECRET")
        plaintext = "HELLOWORLD"
        c1 = std.encrypt(plaintext, "SECRET")
        c2 = mys.encrypt(plaintext, "SECRET")
        assert c1 != c2

    def test_empty_key_raises(self) -> None:
        with pytest.raises(ValueError, match="Key cannot be empty"):
            MyszkowskiCipher("")
