"""Diffie-Hellman key exchange protocol.

Implements the Diffie-Hellman key agreement protocol for secure
key exchange over an insecure channel. Uses safe prime groups
for educational demonstration.

Security note: This is an educational implementation. Production
systems should use established libraries (e.g., cryptography).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass


def _int_from_hex(hex_str: str) -> int:
    """Convert a hex string (possibly with spaces) to int."""
    return int(hex_str.replace(" ", "").replace("\n", ""), 16)


# Safe primes for DH key exchange (educational sizes)
# In production, use 2048+ bit primes
PRIMES: dict[int, tuple[int, int]] = {
    256: (
        _int_from_hex(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D6"
            "70C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF"
        ),
        2,
    ),
}


@dataclass
class DHParameters:
    """Diffie-Hellman parameters.

    Attributes:
        prime: The safe prime p.
        generator: The generator g (usually 2).
        bit_length: Bit length of the prime.
    """

    prime: int
    generator: int
    bit_length: int


@dataclass
class DHKeyPair:
    """A Diffie-Hellman key pair.

    Attributes:
        private_key: The private exponent.
        public_key: The public value g^private mod p.
    """

    private_key: int
    public_key: int


@dataclass
class DHSharedSecret:
    """Result of Diffie-Hellman key exchange.

    Attributes:
        shared_secret: The raw shared secret.
        derived_key: SHA-256 derived key from the shared secret.
        key_id: Identifier for this shared secret.
    """

    shared_secret: int
    derived_key: bytes
    key_id: str


class DiffieHellman:
    """Diffie-Hellman key exchange implementation.

    Args:
        bit_length: Bit length for the prime (256).
        custom_params: Optional custom (prime, generator) tuple.
    """

    def __init__(
        self, bit_length: int = 256, custom_params: tuple[int, int] | None = None
    ) -> None:
        if custom_params:
            self._params = DHParameters(
                prime=custom_params[0],
                generator=custom_params[1],
                bit_length=custom_params[0].bit_length(),
            )
        else:
            if bit_length not in PRIMES:
                msg = f"Unsupported bit length: {bit_length}. Available: {list(PRIMES.keys())}"
                raise ValueError(msg)
            p, g = PRIMES[bit_length]
            self._params = DHParameters(prime=p, generator=g, bit_length=bit_length)

    @property
    def parameters(self) -> DHParameters:
        """Get DH parameters."""
        return self._params

    def generate_keypair(self) -> DHKeyPair:
        """Generate a DH key pair.

        Returns:
            DHKeyPair with private and public values.
        """
        private_key = secrets.randbelow(self._params.prime - 2) + 1
        public_key = pow(self._params.generator, private_key, self._params.prime)
        return DHKeyPair(private_key=private_key, public_key=public_key)

    def compute_shared_secret(
        self, private_key: int, other_public: int, key_id: str = ""
    ) -> DHSharedSecret:
        """Compute the shared secret from a private key and other party's public key.

        Args:
            private_key: Your private key.
            other_public: Other party's public key.
            key_id: Identifier for this shared secret.

        Returns:
            DHSharedSecret with the shared secret and derived key.
        """
        shared = pow(other_public, private_key, self._params.prime)
        derived = hashlib.sha256(str(shared).encode()).digest()
        return DHSharedSecret(
            shared_secret=shared,
            derived_key=derived,
            key_id=key_id or f"shared_{hash(shared) % 10000:04d}",
        )

    def exchange(
        self, my_keypair: DHKeyPair, other_public: int, key_id: str = ""
    ) -> DHSharedSecret:
        """Perform full key exchange.

        Args:
            my_keypair: Your key pair.
            other_public: Other party's public key.
            key_id: Identifier for this shared secret.

        Returns:
            DHSharedSecret.
        """
        return self.compute_shared_secret(
            my_keypair.private_key, other_public, key_id
        )


def verify_dh_exchange(
    dh: DiffieHellman,
    alice_private: int,
    alice_public: int,
    bob_private: int,
    bob_public: int,
) -> bool:
    """Verify that both parties compute the same shared secret.

    Args:
        dh: DH instance.
        alice_private: Alice's private key.
        alice_public: Alice's public key.
        bob_private: Bob's private key.
        bob_public: Bob's public key.

    Returns:
        True if both parties compute the same shared secret.
    """
    alice_shared = dh.compute_shared_secret(alice_private, bob_public)
    bob_shared = dh.compute_shared_secret(bob_private, alice_public)
    return alice_shared.derived_key == bob_shared.derived_key
