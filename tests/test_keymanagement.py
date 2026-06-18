"""Tests for key management and communication protocols."""

from __future__ import annotations

import time
import pytest

from cryptovault.keymanagement.generator import (
    generate_caesar_key,
    generate_vigenere_key,
    generate_affine_key,
    generate_playfair_key,
    generate_hill_key,
    generate_columnar_key,
    generate_monoalphabetic_key,
    generate_vernam_key,
    derive_key_from_password,
)
from cryptovault.keymanagement.keystore import KeyStore
from cryptovault.keymanagement.rotation import (
    KeyRotationManager,
    KeyRotationPolicy,
)
from cryptovault.keymanagement.diffie_hellman import (
    DiffieHellman,
    verify_dh_exchange,
)
from cryptovault.protocols.mac import HMAC, create_mac, verify_mac, mac_to_hex, mac_from_hex
from cryptovault.protocols.signing import SignatureKeyPair, sign_message, verify_signature
from cryptovault.protocols.envelope import SecureEnvelope, SimpleEnvelope
from cryptovault.protocols.channel import establish_secure_channel
from cryptovault.ciphers.caesar import CaesarCipher


# ============================================================
# Key Generation Tests
# ============================================================


class TestKeyGeneration:
    """Test key generation for all cipher types."""

    def test_caesar_key(self) -> None:
        for _ in range(10):
            key = generate_caesar_key()
            assert 0 <= key <= 25

    def test_vigenere_key(self) -> None:
        key = generate_vigenere_key(6)
        assert len(key) == 6
        assert key.isalpha()

    def test_affine_key(self) -> None:
        import math
        for _ in range(10):
            a, b = generate_affine_key()
            assert math.gcd(a, 26) == 1
            assert 0 <= b <= 25

    def test_playfair_key(self) -> None:
        key = generate_playfair_key(8)
        assert len(key) == 8
        assert key.isalpha()

    def test_hill_key(self) -> None:
        matrix = generate_hill_key(3)
        assert len(matrix) == 3
        assert all(len(row) == 3 for row in matrix)

    def test_columnar_key(self) -> None:
        key = generate_columnar_key(6)
        assert len(key) == 6
        assert key.isalpha()

    def test_monoalphabetic_key(self) -> None:
        key = generate_monoalphabetic_key()
        assert len(key) == 26
        assert set(key) == set("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

    def test_vernam_key(self) -> None:
        key = generate_vernam_key(32)
        assert len(key) == 32

    def test_derive_key_from_password(self) -> None:
        key1, salt1 = derive_key_from_password("password123")
        key2, _ = derive_key_from_password("password123", salt=salt1)
        assert key1 == key2
        assert len(key1) == 32


# ============================================================
# KeyStore Tests
# ============================================================


class TestKeyStore:
    """Test encrypted key storage."""

    def test_store_retrieve(self, tmp_path: object) -> None:
        ks = KeyStore(tmp_path / "test_keystore.json")  # type: ignore[arg-type]
        ks.store_key("caesar_key", "5", "masterpass", {"cipher": "caesar"})
        retrieved = ks.retrieve_key("caesar_key", "masterpass")
        assert retrieved == "5"

    def test_wrong_password(self, tmp_path: object) -> None:
        ks = KeyStore(tmp_path / "test_keystore.json")  # type: ignore[arg-type]
        ks.store_key("caesar_key", "5", "masterpass")
        retrieved = ks.retrieve_key("caesar_key", "wrongpass")
        assert retrieved is None

    def test_list_keys(self, tmp_path: object) -> None:
        ks = KeyStore(tmp_path / "test_keystore.json")  # type: ignore[arg-type]
        ks.store_key("key1", "val1", "pass")
        ks.store_key("key2", "val2", "pass")
        keys = ks.list_keys()
        assert len(keys) == 2

    def test_delete_key(self, tmp_path: object) -> None:
        ks = KeyStore(tmp_path / "test_keystore.json")  # type: ignore[arg-type]
        ks.store_key("key1", "val1", "pass")
        assert ks.delete_key("key1") is True
        assert ks.delete_key("key1") is False

    def test_update_key(self, tmp_path: object) -> None:
        ks = KeyStore(tmp_path / "test_keystore.json")  # type: ignore[arg-type]
        ks.store_key("key1", "val1", "pass")
        assert ks.update_key("key1", "val2", "pass") is True
        assert ks.retrieve_key("key1", "pass") == "val2"


# ============================================================
# Key Rotation Tests
# ============================================================


class TestKeyRotation:
    """Test key rotation management."""

    def test_register_and_get(self) -> None:
        km = KeyRotationManager()
        km.register_key("k1", "secret_key")
        assert km.get_key("k1") == "secret_key"

    def test_needs_rotation_by_uses(self) -> None:
        policy = KeyRotationPolicy(max_uses=3, max_age_seconds=999999)
        km = KeyRotationManager()
        km.register_key("k1", "key_value", policy)

        for _ in range(3):
            km.get_key("k1")
        assert km.needs_rotation("k1") is True

    def test_rotate_key(self) -> None:
        km = KeyRotationManager(lambda: "new_key_value")
        km.register_key("k1", "old_key")
        state = km.rotate_key("k1")
        assert state is not None
        assert km.get_key("k1") == "new_key_value"
        assert len(km.get_rotation_log()) == 1


# ============================================================
# Diffie-Hellman Tests
# ============================================================


class TestDiffieHellman:
    """Test Diffie-Hellman key exchange."""

    def test_key_exchange(self) -> None:
        dh = DiffieHellman(256)
        alice = dh.generate_keypair()
        bob = dh.generate_keypair()

        alice_shared = dh.exchange(alice, bob.public_key)
        bob_shared = dh.exchange(bob, alice.public_key)

        assert alice_shared.derived_key == bob_shared.derived_key

    def test_verify_exchange(self) -> None:
        dh = DiffieHellman(256)
        alice = dh.generate_keypair()
        bob = dh.generate_keypair()

        assert verify_dh_exchange(
            dh, alice.private_key, alice.public_key,
            bob.private_key, bob.public_key
        )


# ============================================================
# MAC Tests
# ============================================================


class TestMAC:
    """Test HMAC message authentication."""

    def test_compute_verify(self) -> None:
        hmac = HMAC(b"secret_key")
        message = b"hello world"
        tag = hmac.compute(message)
        assert hmac.verify(message, tag) is True

    def test_verify_wrong_tag(self) -> None:
        hmac = HMAC(b"secret_key")
        message = b"hello world"
        assert hmac.verify(message, b"\x00" * 32) is False

    def test_create_verify_mac(self) -> None:
        key = b"key123"
        message = b"test message"
        tag = create_mac(message, key)
        assert verify_mac(message, key, tag) is True
        assert verify_mac(b"wrong", key, tag) is False

    def test_mac_hex_roundtrip(self) -> None:
        tag = b"\x01\x02\x03\x04"
        hex_str = mac_to_hex(tag)
        assert mac_from_hex(hex_str) == tag


# ============================================================
# Signing Tests
# ============================================================


class TestSigning:
    """Test digital signature operations."""

    def test_sign_verify(self) -> None:
        kp = SignatureKeyPair(512)
        message = b"important message"
        sig = kp.sign(message)
        assert kp.verify(message, sig) is True

    def test_verify_wrong_message(self) -> None:
        kp = SignatureKeyPair(512)
        sig = kp.sign(b"real message")
        assert kp.verify(b"fake message", sig) is False

    def test_sign_verify_functions(self) -> None:
        kp = SignatureKeyPair(512)
        message = b"test data"
        sig = sign_message(message, kp.private_key)
        assert verify_signature(message, kp.public_key, sig) is True


# ============================================================
# Envelope Tests
# ============================================================


class TestEnvelope:
    """Test SecureEnvelope encryption + MAC."""

    def test_seal_open_roundtrip(self) -> None:
        cipher = CaesarCipher(3)
        envelope = SecureEnvelope(cipher)

        plaintext = "HELLO WORLD"
        sealed = envelope.seal(plaintext, "3")
        opened = envelope.open(sealed, "3")
        assert opened == plaintext

    def test_tampered_envelope_fails(self) -> None:
        cipher = CaesarCipher(3)
        envelope = SecureEnvelope(cipher)

        sealed = envelope.seal("HELLO", "3")
        tampered = bytearray(sealed)
        tampered[4] ^= 0xFF
        assert envelope.open(bytes(tampered), "3") is None


class TestSimpleEnvelope:
    """Test SimpleEnvelope XOR + MAC."""

    def test_seal_open_roundtrip(self) -> None:
        envelope = SimpleEnvelope()
        key = b"key1234567890123"

        plaintext = "HELLO"
        sealed = envelope.seal(plaintext, key)
        opened = envelope.open(sealed, key)
        assert opened == plaintext


# ============================================================
# Secure Channel Tests
# ============================================================


class TestSecureChannel:
    """Test secure channel key exchange."""

    def test_establish_channel(self) -> None:
        dh = DiffieHellman(256)
        alice_signing = SignatureKeyPair(512)
        bob_signing = SignatureKeyPair(512)

        alice_channel, bob_channel = establish_secure_channel(
            dh, alice_signing, bob_signing
        )

        assert alice_channel.session is not None
        assert bob_channel.session is not None
        assert alice_channel.session.session_key == bob_channel.session.session_key

    def test_encrypt_decrypt_in_channel(self) -> None:
        dh = DiffieHellman(256)
        alice_signing = SignatureKeyPair(512)
        bob_signing = SignatureKeyPair(512)

        alice_channel, bob_channel = establish_secure_channel(
            dh, alice_signing, bob_signing
        )

        message = "Secret message from Alice"
        encrypted = alice_channel.encrypt_message(message)
        decrypted = bob_channel.decrypt_message(encrypted)
        assert decrypted == message
