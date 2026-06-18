"""Cryptanalysis tools for classical ciphers."""

from cryptovault.cryptanalysis.frequency import frequency_analysis, chi_squared_test
from cryptovault.cryptanalysis.index_of_coincidence import index_of_coincidence, classify_text
from cryptovault.cryptanalysis.kasiski import kasiski_examination, estimate_key_length, recover_key
from cryptovault.cryptanalysis.caesar_cracker import crack_caesar, crack_caesar_with_known_plaintext
from cryptovault.cryptanalysis.playfair_cracker import (
    crack_playfair_crib,
    crack_playfair_frequency,
)
from cryptovault.cryptanalysis.affine_cracker import (
    crack_affine,
    crack_affine_with_known_plaintext,
)
from cryptovault.cryptanalysis.railfence_cracker import (
    crack_railfence,
    crack_railfence_by_ioc,
)
from cryptovault.cryptanalysis.hill_cracker import (
    crack_hill_known_plaintext,
    crack_hill_brute_force_2x2,
)
from cryptovault.cryptanalysis.bifid_cracker import crack_bifid, crack_trifid
from cryptovault.cryptanalysis.adfgvx_cracker import (
    crack_adfgvx_crib,
    crack_adfgvx_frequency,
)

__all__ = [
    "frequency_analysis",
    "chi_squared_test",
    "index_of_coincidence",
    "classify_text",
    "kasiski_examination",
    "estimate_key_length",
    "recover_key",
    "crack_caesar",
    "crack_caesar_with_known_plaintext",
    "crack_playfair_crib",
    "crack_playfair_frequency",
    "crack_affine",
    "crack_affine_with_known_plaintext",
    "crack_railfence",
    "crack_railfence_by_ioc",
    "crack_hill_known_plaintext",
    "crack_hill_brute_force_2x2",
    "crack_bifid",
    "crack_trifid",
    "crack_adfgvx_crib",
    "crack_adfgvx_frequency",
]
