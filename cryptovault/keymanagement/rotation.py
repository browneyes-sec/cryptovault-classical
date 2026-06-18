"""Key rotation management for classical ciphers.

Implements time-based key rotation policies following
NIST SP 800-57 key management best practices.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class KeyRotationPolicy:
    """Key rotation policy definition.

    Attributes:
        max_age_seconds: Maximum key lifetime in seconds.
        max_uses: Maximum number of uses before rotation required.
        pre_rotation_warning: Seconds before expiry to warn.
        auto_rotate: Whether to auto-generate new keys.
    """

    max_age_seconds: int = 86400  # 24 hours default
    max_uses: int = 1000
    pre_rotation_warning: int = 3600  # 1 hour
    auto_rotate: bool = False


@dataclass
class KeyState:
    """State of a managed key.

    Attributes:
        key_id: Unique identifier.
        key_value: The current key value.
        created_at: Creation timestamp.
        last_used_at: Last use timestamp.
        use_count: Number of times used.
        rotation_policy: Associated policy.
        metadata: Additional metadata.
    """

    key_id: str
    key_value: str
    created_at: float = field(default_factory=time.time)
    last_used_at: float = field(default_factory=time.time)
    use_count: int = 0
    rotation_policy: KeyRotationPolicy = field(default_factory=KeyRotationPolicy)
    metadata: dict[str, Any] = field(default_factory=dict)


class KeyRotationManager:
    """Manages key rotation for multiple keys.

    Tracks key state and enforces rotation policies.

    Args:
        key_generator: Callable that generates a new key value.
    """

    def __init__(self, key_generator: Callable[[], str] | None = None) -> None:
        self._keys: dict[str, KeyState] = {}
        self._generator = key_generator or (lambda: "DEFAULT_KEY")
        self._rotation_log: list[dict[str, Any]] = []

    def register_key(
        self,
        key_id: str,
        key_value: str,
        policy: KeyRotationPolicy | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> KeyState:
        """Register a key for rotation management.

        Args:
            key_id: Unique identifier for the key.
            key_value: The key value.
            policy: Rotation policy (default if None).
            metadata: Additional metadata.

        Returns:
            The created KeyState.
        """
        state = KeyState(
            key_id=key_id,
            key_value=key_value,
            rotation_policy=policy or KeyRotationPolicy(),
            metadata=metadata or {},
        )
        self._keys[key_id] = state
        return state

    def get_key(self, key_id: str) -> str | None:
        """Get a key value, recording usage.

        Args:
            key_id: Key identifier.

        Returns:
            Key value, or None if not found.
        """
        state = self._keys.get(key_id)
        if state is None:
            return None

        state.last_used_at = time.time()
        state.use_count += 1
        return state.key_value

    def needs_rotation(self, key_id: str) -> bool:
        """Check if a key needs rotation.

        Args:
            key_id: Key identifier.

        Returns:
            True if rotation is needed.
        """
        state = self._keys.get(key_id)
        if state is None:
            return False

        now = time.time()
        age = now - state.created_at
        if age > state.rotation_policy.max_age_seconds:
            return True
        if state.use_count >= state.rotation_policy.max_uses:
            return True
        return False

    def is_near_expiry(self, key_id: str) -> bool:
        """Check if a key is near its expiry (within warning window).

        Args:
            key_id: Key identifier.

        Returns:
            True if within pre-rotation warning window.
        """
        state = self._keys.get(key_id)
        if state is None:
            return False

        now = time.time()
        age = now - state.created_at
        remaining = state.rotation_policy.max_age_seconds - age
        return 0 < remaining <= state.rotation_policy.pre_rotation_warning

    def rotate_key(self, key_id: str) -> KeyState | None:
        """Rotate a key, generating a new value.

        Args:
            key_id: Key identifier.

        Returns:
            Updated KeyState, or None if key not found.
        """
        state = self._keys.get(key_id)
        if state is None:
            return None

        old_value = state.key_value
        new_value = self._generator()

        state.key_value = new_value
        state.created_at = time.time()
        state.last_used_at = time.time()
        state.use_count = 0

        self._rotation_log.append({
            "key_id": key_id,
            "rotated_at": time.time(),
            "old_key_hash": _hash_key(old_value),
            "new_key_hash": _hash_key(new_value),
        })

        return state

    def get_expired_keys(self) -> list[str]:
        """Get all key IDs that have expired.

        Returns:
            List of expired key IDs.
        """
        return [kid for kid in self._keys if self.needs_rotation(kid)]

    def get_rotation_log(self) -> list[dict[str, Any]]:
        """Get the rotation history.

        Returns:
            List of rotation events.
        """
        return list(self._rotation_log)

    def remove_key(self, key_id: str) -> bool:
        """Remove a key from management.

        Args:
            key_id: Key identifier.

        Returns:
            True if removed, False if not found.
        """
        if key_id in self._keys:
            del self._keys[key_id]
            return True
        return False


def _hash_key(key: str) -> str:
    """Create a truncated hash of a key for logging.

    Args:
        key: Key value to hash.

    Returns:
        Truncated hex digest.
    """
    import hashlib
    return hashlib.sha256(key.encode()).hexdigest()[:16]
