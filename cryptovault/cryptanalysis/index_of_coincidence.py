"""Index of Coincidence (IoC) calculation.

IoC measures the probability that two randomly selected letters
from a text are the same. For English text, IoC ≈ 0.065.
For random text, IoC ≈ 0.038 (1/26).

Used to:
- Detect cipher type (substitution vs transposition vs random)
- Estimate Vigenère key length
- Assess text entropy
"""

from __future__ import annotations

from collections import Counter


def index_of_coincidence(text: str) -> float:
    """Calculate the Index of Coincidence for a text.

    IoC = Σ(n_i * (n_i - 1)) / (N * (N - 1))

    where n_i is the count of letter i and N is total letter count.

    Typical values:
    - English text: ~0.065
    - Random text:  ~0.038 (1/26)
    - Uniform text: ~0.0

    Args:
        text: Input text (case-insensitive, non-alpha chars ignored).

    Returns:
        IoC value between 0.0 and 1.0.
    """
    lower = text.lower()
    alpha_chars = [c for c in lower if c.isalpha()]
    n = len(alpha_chars)

    if n <= 1:
        return 0.0

    counts = Counter(alpha_chars)
    numerator = sum(count * (count - 1) for count in counts.values())
    denominator = n * (n - 1)

    return numerator / denominator


def classify_text(text: str) -> tuple[str, float]:
    """Classify text based on IoC value.

    Args:
        text: Input text to classify.

    Returns:
        Tuple of (classification, ioc_value).
    """
    ioc = index_of_coincidence(text)

    if ioc >= 0.060:
        return ("English-like", ioc)
    elif ioc >= 0.045:
        return ("Substitution cipher", ioc)
    elif ioc >= 0.035:
        return ("Polyalphabetic cipher", ioc)
    else:
        return ("Random or transposition", ioc)


def average_ioc_by_columns(ciphertext: str, key_length: int) -> float:
    """Calculate average IoC across columns for a given key length.

    Used in Kasiski/Vigenère analysis: if key_length is correct,
    each column is monoalphabetic (high IoC ≈ 0.065).

    Args:
        ciphertext: The ciphertext to analyze.
        key_length: Suspected key length.

    Returns:
        Average IoC across all columns.
    """
    alpha_only = [c.lower() for c in ciphertext if c.isalpha()]

    if key_length <= 0 or len(alpha_only) < key_length:
        return 0.0

    columns: list[str] = [""] * key_length
    for i, ch in enumerate(alpha_only):
        columns[i % key_length] += ch

    iocs = [index_of_coincidence(col) for col in columns if len(col) > 1]
    return sum(iocs) / len(iocs) if iocs else 0.0
