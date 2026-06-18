"""Secure channel protocol for session key negotiation and exchange.

Implements a simplified TLS-like handshake using Diffie-Hellman
key exchange combined with digital signatures for authentication.
"""

from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field

from cryptovault.keymanagement.diffie_hellman import DiffieHellman, DHKeyPair
from cryptovault.protocols.mac import HMAC, create_mac, verify_mac
from cryptovault.protocols.signing import SignatureKeyPair


@dataclass
class SessionState:
    """State of a secure channel session.

    Attributes:
        session_id: Unique session identifier.
        session_key: Derived shared key.
        established_at: Timestamp of session establishment.
        messages_sent: Count of messages sent.
        messages_received: Count of messages received.
    """

    session_id: str
    session_key: bytes
    established_at: float = field(default_factory=time.time)
    messages_sent: int = 0
    messages_received: int = 0


@dataclass
class HandshakeMessage:
    """A handshake message in the secure channel protocol.

    Attributes:
        sender_id: Sender's identifier.
        public_key: DH public value.
        signature: Signature of the public key.
        timestamp: Message timestamp.
    """

    sender_id: str
    public_key: int
    signature: int
    timestamp: float


class SecureChannel:
    """Secure channel for authenticated key exchange.

    Implements a simplified handshake protocol:
    1. Both parties generate DH key pairs.
    2. Each signs their public key with their long-term signing key.
    3. Exchange public keys and signatures.
    4. Verify signatures and compute shared secret.
    5. Derive session key from shared secret.

    Args:
        dh: Diffie-Hellman instance.
        signing_key: Long-term signing key pair.
        peer_id: Identifier of the peer.
    """

    def __init__(
        self,
        dh: DiffieHellman,
        signing_key: SignatureKeyPair,
        peer_id: str = "peer",
    ) -> None:
        self._dh = dh
        self._signing_key = signing_key
        self._peer_id = peer_id
        self._session: SessionState | None = None
        self._dh_keypair: DHKeyPair | None = None

    @property
    def session(self) -> SessionState | None:
        """Get the current session state."""
        return self._session

    def initiate_handshake(self) -> HandshakeMessage:
        """Initiate the handshake by generating a DH key pair.

        Returns:
            HandshakeMessage with public key and signature.
        """
        self._dh_keypair = self._dh.generate_keypair()
        pub_bytes = str(self._dh_keypair.public_key).encode()
        signature = self._signing_key.sign(pub_bytes)

        return HandshakeMessage(
            sender_id="initiator",
            public_key=self._dh_keypair.public_key,
            signature=signature,
            timestamp=time.time(),
        )

    def respond_to_handshake(
        self, peer_message: HandshakeMessage, peer_signing_key: SignatureKeyPair
    ) -> HandshakeMessage:
        """Respond to a handshake and compute shared secret.

        Args:
            peer_message: The initiator's handshake message.
            peer_signing_key: The initiator's long-term signing key.

        Returns:
            Responder's HandshakeMessage.

        Raises:
            ValueError: If the peer's signature is invalid.
        """
        pub_bytes = str(peer_message.public_key).encode()
        if not peer_signing_key.verify(pub_bytes, peer_message.signature):
            msg = "Invalid peer signature in handshake"
            raise ValueError(msg)

        self._dh_keypair = self._dh.generate_keypair()
        my_sig = self._signing_key.sign(str(self._dh_keypair.public_key).encode())

        shared = self._dh.exchange(
            self._dh_keypair, peer_message.public_key, "session"
        )

        self._session = SessionState(
            session_id=shared.key_id,
            session_key=shared.derived_key,
        )

        return HandshakeMessage(
            sender_id="responder",
            public_key=self._dh_keypair.public_key,
            signature=my_sig,
            timestamp=time.time(),
        )

    def complete_handshake(
        self, peer_response: HandshakeMessage, peer_signing_key: SignatureKeyPair
    ) -> SessionState:
        """Complete the handshake as initiator.

        Args:
            peer_response: Responder's handshake message.
            peer_signing_key: Responder's long-term signing key.

        Returns:
            Established session state.

        Raises:
            ValueError: If the peer's signature is invalid.
        """
        pub_bytes = str(peer_response.public_key).encode()
        if not peer_signing_key.verify(pub_bytes, peer_response.signature):
            msg = "Invalid peer signature in handshake"
            raise ValueError(msg)

        shared = self._dh.exchange(
            self._dh_keypair, peer_response.public_key, "session"
        )

        self._session = SessionState(
            session_id=shared.key_id,
            session_key=shared.derived_key,
        )
        return self._session

    def encrypt_message(self, plaintext: str) -> bytes:
        """Encrypt a message using the session key.

        Args:
            plaintext: Message to encrypt.

        Returns:
            Encrypted message bytes with MAC.

        Raises:
            RuntimeError: If session not established.
        """
        if self._session is None:
            msg = "Session not established"
            raise RuntimeError(msg)

        pt_bytes = plaintext.encode("utf-8")
        key = self._session.session_key
        ct_bytes = bytes(p ^ k for p, k in zip(pt_bytes, key * (len(pt_bytes) // len(key) + 1)))

        mac_tag = create_mac(ct_bytes, self._session.session_key)
        self._session.messages_sent += 1

        length = len(ct_bytes).to_bytes(4, "big")
        return length + ct_bytes + mac_tag

    def decrypt_message(self, ciphertext: bytes) -> str | None:
        """Decrypt and verify a message.

        Args:
            ciphertext: Encrypted message bytes.

        Returns:
            Decrypted plaintext, or None if MAC verification fails.

        Raises:
            RuntimeError: If session not established.
        """
        if self._session is None:
            msg = "Session not established"
            raise RuntimeError(msg)

        if len(ciphertext) < 4 + 32:
            return None

        ct_len = int.from_bytes(ciphertext[:4], "big")
        ct_bytes = ciphertext[4 : 4 + ct_len]
        mac_tag = ciphertext[4 + ct_len : 4 + ct_len + 32]

        if not verify_mac(ct_bytes, self._session.session_key, mac_tag):
            return None

        key = self._session.session_key
        pt_bytes = bytes(c ^ k for c, k in zip(ct_bytes, key * (len(ct_bytes) // len(key) + 1)))
        self._session.messages_received += 1
        return pt_bytes.decode("utf-8")


def establish_secure_channel(
    dh: DiffieHellman,
    alice_signing: SignatureKeyPair,
    bob_signing: SignatureKeyPair,
    alice_id: str = "Alice",
    bob_id: str = "Bob",
) -> tuple[SecureChannel, SecureChannel]:
    """Establish a secure channel between two parties.

    Args:
        dh: Diffie-Hellman instance.
        alice_signing: Alice's signing key pair.
        bob_signing: Bob's signing key pair.
        alice_id: Alice's identifier.
        bob_id: Bob's identifier.

    Returns:
        Tuple of (Alice's channel, Bob's channel).
    """
    alice_channel = SecureChannel(dh, alice_signing, bob_id)
    bob_channel = SecureChannel(dh, bob_signing, alice_id)

    alice_hello = alice_channel.initiate_handshake()
    bob_response = bob_channel.respond_to_handshake(alice_hello, alice_signing)
    alice_channel.complete_handshake(bob_response, bob_signing)

    return alice_channel, bob_channel
