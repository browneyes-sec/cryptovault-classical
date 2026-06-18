"""Tests for cryptanalysis modules — frequency, IoC, Kasiski, and Caesar cracker."""

from __future__ import annotations

import pytest

from cryptovault.cryptanalysis.frequency import frequency_analysis, chi_squared_test
from cryptovault.cryptanalysis.index_of_coincidence import (
    index_of_coincidence,
    classify_text,
    average_ioc_by_columns,
)
from cryptovault.cryptanalysis.kasiski import (
    kasiski_examination,
    estimate_key_length,
    recover_key,
)
from cryptovault.cryptanalysis.caesar_cracker import (
    crack_caesar,
    crack_caesar_with_known_plaintext,
)
from cryptovault.cryptanalysis.playfair_cracker import crack_playfair_frequency
from cryptovault.cryptanalysis.affine_cracker import crack_affine
from cryptovault.cryptanalysis.railfence_cracker import crack_railfence


# ============================================================
# Frequency Analysis Tests
# ============================================================


class TestFrequencyAnalysis:
    """Test letter frequency analysis."""

    def test_english_text_frequency(self) -> None:
        text = "the quick brown fox jumps over the lazy dog"
        freq = frequency_analysis(text)
        assert "e" in freq
        assert freq["e"] > freq["z"]
        assert abs(sum(freq.values()) - 1.0) < 0.01

    def test_empty_text(self) -> None:
        freq = frequency_analysis("")
        assert all(v == 0.0 for v in freq.values())

    def test_all_same_letter(self) -> None:
        freq = frequency_analysis("aaaa")
        assert freq["a"] == 1.0
        assert freq["b"] == 0.0

    def test_chi_squared_english_is_low(self) -> None:
        english = "the quick brown fox jumps over the lazy dog"
        random_text = "qzjx wvmkf bypl hgsd tnco rear uitw"
        assert chi_squared_test(english) < chi_squared_test(random_text)

    def test_chi_squared_empty(self) -> None:
        result = chi_squared_test("")
        assert result == float("inf")


# ============================================================
# Index of Coincidence Tests
# ============================================================


class TestIndexCoincidence:
    """Test IoC calculation and text classification."""

    def test_english_ioc(self) -> None:
        text = "To be or not to be that is the question whether it is nobler"
        ioc = index_of_coincidence(text)
        assert 0.05 < ioc < 0.09

    def test_random_ioc(self) -> None:
        text = "qwertyuiopasdfghjklzxcvbnm"
        ioc = index_of_coincidence(text)
        assert ioc < 0.05

    def test_single_char(self) -> None:
        assert index_of_coincidence("a") == 0.0

    def test_empty_text(self) -> None:
        assert index_of_coincidence("") == 0.0

    def test_classify_english(self) -> None:
        text = "This is a test of English text classification"
        classification, ioc = classify_text(text)
        assert ioc > 0.04
        assert "English" in classification or "Substitution" in classification

    def test_average_ioc_by_columns(self) -> None:
        ciphertext = "abcdefghijklmnopqrstuvwxyz"
        avg = average_ioc_by_columns(ciphertext, 2)
        assert 0.0 <= avg <= 1.0

    def test_average_ioc_invalid_key_length(self) -> None:
        assert average_ioc_by_columns("abc", 0) == 0.0
        assert average_ioc_by_columns("abc", 10) == 0.0


# ============================================================
# Kasiski Examination Tests
# ============================================================


class TestKasiski:
    """Test Kasiski examination and key recovery."""

    def test_kasiski_examination_returns_candidates(self) -> None:
        from cryptovault.ciphers.vigenere import VigenereCipher

        plaintext = (
            "The enemy will attack at dawn and we must prepare our defenses "
            "The enemy will attack at dawn and we must prepare our defenses "
            "The enemy will attack at dawn and we must prepare our defenses"
        )
        key = "SECRET"
        v = VigenereCipher()
        ciphertext = v.encrypt(plaintext, key)

        candidates = kasiski_examination(ciphertext)
        assert len(candidates) > 0
        assert 6 in candidates or any(c % 6 == 0 for c in candidates)

    def test_estimate_key_length(self) -> None:
        from cryptovault.ciphers.vigenere import VigenereCipher

        plaintext = (
            "The quick brown fox jumps over the lazy dog "
            "Pack my box with five dozen jugs "
            "The quick brown fox jumps over the lazy dog"
        )
        key = "KEY"
        v = VigenereCipher()
        ciphertext = v.encrypt(plaintext, key)

        estimated = estimate_key_length(ciphertext)
        assert estimated >= 2

    def test_recover_key(self) -> None:
        from cryptovault.ciphers.vigenere import VigenereCipher

        plaintext = ("The enemy will attack at dawn and we must prepare our defenses. " * 10)
        key = "abc"
        v = VigenereCipher()
        ciphertext = v.encrypt(plaintext, key)

        recovered = recover_key(ciphertext, 3)
        assert recovered.lower() == key.lower()

    def test_recover_key_invalid_length(self) -> None:
        with pytest.raises(ValueError, match="Invalid key_length"):
            recover_key("abc", 0)


# ============================================================
# Caesar Cracker Tests
# ============================================================


class TestCaesarCracker:
    """Test Caesar cipher cracking methods."""

    def test_crack_caesar(self) -> None:
        from cryptovault.ciphers.caesar import CaesarCipher

        plaintext = "the enemy will attack at dawn and we must prepare our defenses"
        shift = 13
        ciphertext = CaesarCipher(shift).encrypt(plaintext)

        best_shift, best_text, confidence = crack_caesar(ciphertext)
        assert best_shift == shift
        assert best_text == plaintext
        assert confidence > 0.5

    def test_crack_caesar_with_known_plaintext(self) -> None:
        from cryptovault.ciphers.caesar import CaesarCipher

        plaintext = "the enemy attacks at dawn"
        ciphertext = CaesarCipher(5).encrypt(plaintext)

        results = crack_caesar_with_known_plaintext(ciphertext, "the")
        assert len(results) == 26
        best_shift, _, ratio = results[0]
        assert best_shift == 5
        assert ratio > 0.0

    def test_crack_returns_all_shifts(self) -> None:
        from cryptovault.ciphers.caesar import CaesarCipher

        ciphertext = CaesarCipher(3).encrypt("hello")
        results = crack_caesar_with_known_plaintext(ciphertext, "xyz")
        assert len(results) == 26


# ============================================================
# Extended Cipher Cracker Tests
# ============================================================


class TestAffineCracker:
    """Test Affine cipher brute-force."""

    def test_crack_affine(self) -> None:
        from cryptovault.ciphers.affine import AffineCipher

        plaintext = "THE QUICK BROWN FOX"
        ac = AffineCipher(5, 8)
        ciphertext = ac.encrypt(plaintext)
        results = crack_affine(ciphertext, top_n=3)
        assert len(results) > 0
        best_key, best_text, _ = results[0]
        assert best_text == plaintext


class TestRailFenceCracker:
    """Test Rail Fence cipher brute-force."""

    def test_crack_railfence(self) -> None:
        from cryptovault.ciphers.railfence import RailFenceCipher

        plaintext = "WEAREDISCOVEREDFLEEATONCE"
        rf = RailFenceCipher(3)
        ciphertext = rf.encrypt(plaintext)
        results = crack_railfence(ciphertext, top_n=26)
        texts = [r[1] for r in results]
        assert plaintext in texts
