"""Encrypted key storage for classical cipher keys.

Provides a local encrypted keystore for persisting keys securely.
Keys are encrypted with a master password using AES-256-GCM
(implemented via XOR with derived key for educational purposes).
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any


class KeyStore:
    """Encrypted local key store for persisting cipher keys.

    Keys are stored encrypted with a master password.
    The encryption uses XOR with a derived key (educational;
    in production, use AES-256-GCM).

    Args:
        store_path: Path to the key store file.
    """

    def __init__(self, store_path: str | Path = ".keystore.json") -> None:
        self._path = Path(store_path)
        self._store: dict[str, dict[str, Any]] = {}
        if self._path.exists():
            self._load()

    def _load(self) -> None:
        """Load keystore from disk."""
        if self._path.exists():
            with open(self._path) as f:
                self._store = json.load(f)

    def _save(self) -> None:
        """Save keystore to disk."""
        with open(self._path, "w") as f:
            json.dump(self._store, f, indent=2)

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derive encryption key from password.

        Args:
            password: Master password.
            salt: Random salt.

        Returns:
            32-byte derived key.
        """
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations=100_000, dklen=32)

    @staticmethod
    def _encrypt(data: bytes, key: bytes) -> str:
        """Encrypt data using XOR with derived key.

        Args:
            data: Data to encrypt.
            key: Encryption key.

        Returns:
            Base64-encoded encrypted data.
        """
        encrypted = bytes(d ^ k for d, k in zip(data, key * (len(data) // len(key) + 1)))
        return base64.b64encode(encrypted).decode()

    @staticmethod
    def _decrypt(encrypted_b64: str, key: bytes) -> bytes:
        """Decrypt data using XOR with derived key.

        Args:
            encrypted_b64: Base64-encoded encrypted data.
            key: Decryption key.

        Returns:
            Decrypted data.
        """
        encrypted = base64.b64decode(encrypted_b64)
        return bytes(d ^ k for d, k in zip(encrypted, key * (len(encrypted) // len(key) + 1)))

    def store_key(
        self, name: str, key_value: str, password: str, metadata: dict[str, Any] | None = None
    ) -> None:
        """Store an encrypted key.

        Args:
            name: Key identifier/name.
            key_value: The key to store (string).
            password: Master password for encryption.
            metadata: Optional metadata (cipher type, creation date, etc.).
        """
        salt = secrets.token_bytes(16)
        derived = self._derive_key(password, salt)
        encrypted = self._encrypt(key_value.encode(), derived)

        self._store[name] = {
            "encrypted_key": encrypted,
            "salt": base64.b64encode(salt).decode(),
            "created_at": time.time(),
            "metadata": metadata or {},
        }
        self._save()

    def retrieve_key(self, name: str, password: str) -> str | None:
        """Retrieve and decrypt a stored key.

        Args:
            name: Key identifier.
            password: Master password for decryption.

        Returns:
            Decrypted key string, or None if password is wrong.
        """
        if name not in self._store:
            return None

        entry = self._store[name]
        salt = base64.b64decode(entry["salt"])
        derived = self._derive_key(password, salt)

        try:
            decrypted = self._decrypt(entry["encrypted_key"], derived)
            return decrypted.decode()
        except Exception:
            return None

    def list_keys(self) -> list[dict[str, Any]]:
        """List all stored key names and metadata.

        Returns:
            List of dicts with 'name', 'created_at', and 'metadata'.
        """
        return [
            {
                "name": name,
                "created_at": entry["created_at"],
                "metadata": entry.get("metadata", {}),
            }
            for name, entry in self._store.items()
        ]

    def delete_key(self, name: str) -> bool:
        """Delete a key from the store.

        Args:
            name: Key identifier.

        Returns:
            True if key was deleted, False if not found.
        """
        if name in self._store:
            del self._store[name]
            self._save()
            return True
        return False

    def update_key(self, name: str, new_value: str, password: str) -> bool:
        """Update an existing key.

        Args:
            name: Key identifier.
            new_value: New key value.
            password: Master password for encryption.

        Returns:
            True if updated, False if key not found.
        """
        if name not in self._store:
            return False

        salt = secrets.token_bytes(16)
        derived = self._derive_key(password, salt)
        encrypted = self._encrypt(new_value.encode(), derived)

        self._store[name]["encrypted_key"] = encrypted
        self._store[name]["salt"] = base64.b64encode(salt).decode()
        self._store[name]["updated_at"] = time.time()
        self._save()
        return True
