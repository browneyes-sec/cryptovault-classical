"""Binary and bitwise utility functions.

Provides conversion between binary and decimal representations,
and bitwise XOR operations on bit strings.
"""

from __future__ import annotations


def bin_to_dec(binary_str: str) -> int:
    """Convert a binary string to a decimal integer.

    Args:
        binary_str: String of '0' and '1' characters (e.g., "1011").

    Returns:
        The decimal integer value.

    Raises:
        ValueError: If binary_str contains non-binary characters.
    """
    if not binary_str:
        msg = "Binary string cannot be empty"
        raise ValueError(msg)
    if not all(c in "01" for c in binary_str):
        msg = f"Invalid binary string: {binary_str!r}"
        raise ValueError(msg)
    return int(binary_str, 2)


def dec_to_bin(decimal: int) -> str:
    """Convert a decimal integer to a binary string.

    Args:
        decimal: Non-negative integer to convert.

    Returns:
        Binary string representation (no '0b' prefix).

    Raises:
        ValueError: If decimal is negative.
    """
    if decimal < 0:
        msg = f"Cannot convert negative number: {decimal}"
        raise ValueError(msg)
    if decimal == 0:
        return "0"
    return bin(decimal)[2:]


def xor_bits(bits_a: str, bits_b: str) -> str:
    """Compute bitwise XOR of two equal-length bit strings.

    Args:
        bits_a: First bit string.
        bits_b: Second bit string (must be same length as bits_a).

    Returns:
        Bit string result of XOR operation.

    Raises:
        ValueError: If bit strings have different lengths or contain invalid chars.
    """
    if not bits_a or not bits_b:
        msg = "Bit strings cannot be empty"
        raise ValueError(msg)
    if len(bits_a) != len(bits_b):
        msg = f"Bit strings must be equal length: {len(bits_a)} != {len(bits_b)}"
        raise ValueError(msg)
    if not all(c in "01" for c in bits_a + bits_b):
        msg = "Bit strings must contain only '0' and '1'"
        raise ValueError(msg)

    result: list[str] = []
    for a, b in zip(bits_a, bits_b):
        result.append("1" if a != b else "0")
    return "".join(result)


def xor_bytes(data_a: bytes, data_b: bytes) -> bytes:
    """Compute bitwise XOR of two byte sequences.

    Used internally by the Vernam cipher for efficient XOR operations.

    Args:
        data_a: First byte sequence.
        data_b: Second byte sequence (must be same length).

    Returns:
        Byte sequence result of XOR operation.

    Raises:
        ValueError: If byte sequences have different lengths.
    """
    if len(data_a) != len(data_b):
        msg = f"Byte sequences must be equal length: {len(data_a)} != {len(data_b)}"
        raise ValueError(msg)
    return bytes(a ^ b for a, b in zip(data_a, data_b))
