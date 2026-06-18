"""Communication protocols — MAC, signing, envelope, and secure channel."""

from cryptovault.protocols.mac import HMAC, create_mac, verify_mac, mac_to_hex, mac_from_hex
from cryptovault.protocols.signing import (
    SignatureKeyPair,
    sign_message,
    verify_signature,
)
from cryptovault.protocols.envelope import SecureEnvelope, SimpleEnvelope
from cryptovault.protocols.channel import (
    SecureChannel,
    SessionState,
    HandshakeMessage,
    establish_secure_channel,
)

__all__ = [
    "HMAC",
    "create_mac",
    "verify_mac",
    "mac_to_hex",
    "mac_from_hex",
    "SignatureKeyPair",
    "sign_message",
    "verify_signature",
    "SecureEnvelope",
    "SimpleEnvelope",
    "SecureChannel",
    "SessionState",
    "HandshakeMessage",
    "establish_secure_channel",
]
