"""Unified CLI for CryptoVault Classical.

Usage:
    cryptovault encrypt --cipher caesar --key 3 --input "hello"
    cryptovault decrypt --cipher vigenere --key "SECRET" --input "ciphertext"
    cryptovault crack --cipher caesar --input "ciphertext"
    cryptovault analyze --input "ciphertext"
    cryptovault keygen --cipher caesar
    cryptovault dh-demo
"""

from __future__ import annotations

import click

from cryptovault import __version__

CIPHERS = [
    "caesar", "vigenere", "vernam", "transposition",
    "playfair", "railfence", "affine", "atbash",
    "bacon", "hill", "bifid", "trifid",
    "foursquare", "porta", "adfgvx", "monoalphabetic", "myszkowski",
]

CRACKABLE = ["caesar", "vigenere", "affine", "railfence"]


@click.group()
@click.version_option(version=__version__, prog_name="cryptovault")
def main() -> None:
    """CryptoVault Classical — Educational cryptographic toolkit."""


@main.command()
@click.option("--cipher", "-c", required=True, type=click.Choice(CIPHERS))
@click.option("--key", "-k", required=True, help="Encryption key")
@click.option("--input", "-i", "input_text", required=True, help="Plaintext to encrypt")
@click.option("--shift", "-s", type=int, default=None, help="Shift value (Caesar only)")
def encrypt(cipher: str, key: str, input_text: str, shift: int | None) -> None:
    """Encrypt plaintext using a classical cipher."""
    result = _run_encrypt(cipher, key, input_text, shift)
    click.echo(result)


@main.command()
@click.option("--cipher", "-c", required=True, type=click.Choice(CIPHERS))
@click.option("--key", "-k", required=True, help="Decryption key")
@click.option("--input", "-i", "input_text", required=True, help="Ciphertext to decrypt")
@click.option("--shift", "-s", type=int, default=None, help="Shift value (Caesar only)")
def decrypt(cipher: str, key: str, input_text: str, shift: int | None) -> None:
    """Decrypt ciphertext using a classical cipher."""
    result = _run_decrypt(cipher, key, input_text, shift)
    click.echo(result)


@main.command()
@click.option("--cipher", "-c", required=True, type=click.Choice(CRACKABLE))
@click.option("--input", "-i", "input_text", required=True, help="Ciphertext to crack")
@click.option("--top", "-n", type=int, default=5, help="Number of top results to show")
def crack(cipher: str, input_text: str, top: int) -> None:
    """Attempt to crack a cipher without the key."""
    results = _run_crack(cipher, input_text, top)
    for rank, (key, plaintext, confidence) in enumerate(results, 1):
        click.echo(f"#{rank}  key={key!r}  confidence={confidence:.4f}  text={plaintext!r}")


@main.command()
@click.option("--input", "-i", "input_text", required=True, help="Text to analyze")
def analyze(input_text: str) -> None:
    """Analyze text: letter frequency, IoC, and cipher type detection."""
    from cryptovault.cryptanalysis.frequency import frequency_analysis, chi_squared_test
    from cryptovault.cryptanalysis.index_of_coincidence import index_of_coincidence, classify_text

    freq = frequency_analysis(input_text)
    ioc = index_of_coincidence(input_text)
    classification, _ = classify_text(input_text)
    chi_sq = chi_squared_test(input_text)

    click.echo("=== Letter Frequency ===")
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    for ch, f in sorted_freq[:10]:
        bar = "█" * int(f * 40)
        click.echo(f"  {ch}  {f:.4f}  {bar}")

    click.echo(f"\n=== Statistics ===")
    click.echo(f"  IoC:              {ioc:.4f}")
    click.echo(f"  Chi-squared:      {chi_sq:.2f}")
    click.echo(f"  Classification:   {classification}")


@main.command("keygen")
@click.option("--cipher", "-c", required=True, type=click.Choice(CIPHERS))
def keygen(cipher: str) -> None:
    """Generate a random key for a cipher."""
    from cryptovault.keymanagement.generator import (
        generate_caesar_key,
        generate_vigenere_key,
        generate_affine_key,
        generate_playfair_key,
        generate_hill_key,
        generate_columnar_key,
        generate_monoalphabetic_key,
    )

    if cipher == "caesar":
        key = generate_caesar_key()
        click.echo(f"Caesar shift: {key}")
    elif cipher == "vigenere":
        key = generate_vigenere_key(6)
        click.echo(f"Vigenère key: {key}")
    elif cipher == "affine":
        a, b = generate_affine_key()
        click.echo(f"Affine key: a={a}, b={b}")
    elif cipher == "playfair":
        key = generate_playfair_key(8)
        click.echo(f"Playfair key: {key}")
    elif cipher == "hill":
        matrix = generate_hill_key(3)
        click.echo(f"Hill key matrix:")
        for row in matrix:
            click.echo(f"  {row}")
    elif cipher in ("transposition", "myszkowski", "columnar"):
        key = generate_columnar_key(6)
        click.echo(f"Transposition key: {key}")
    elif cipher == "monoalphabetic":
        key = generate_monoalphabetic_key()
        click.echo(f"Monoalphabetic key: {key}")
    else:
        click.echo(f"Key generation not supported for: {cipher}")


@main.command("dh-demo")
def dh_demo() -> None:
    """Demonstrate Diffie-Hellman key exchange."""
    from cryptovault.keymanagement.diffie_hellman import DiffieHellman, verify_dh_exchange

    click.echo("=== Diffie-Hellman Key Exchange Demo ===\n")

    dh = DiffieHellman(256)
    click.echo(f"Parameters: {dh.parameters.bit_length}-bit prime, g={dh.parameters.generator}\n")

    alice = dh.generate_keypair()
    click.echo(f"Alice's public key: {alice.public_key}")
    bob = dh.generate_keypair()
    click.echo(f"Bob's public key:   {bob.public_key}\n")

    alice_shared = dh.exchange(alice, bob.public_key, "Alice-Bob")
    bob_shared = dh.exchange(bob, alice.public_key, "Bob-Alice")

    click.echo(f"Alice's derived key: {alice_shared.derived_key.hex()}")
    click.echo(f"Bob's derived key:   {bob_shared.derived_key.hex()}")
    click.echo(f"Keys match: {alice_shared.derived_key == bob_shared.derived_key}")
    click.echo(f"Verified:   {verify_dh_exchange(dh, alice.private_key, alice.public_key, bob.private_key, bob.public_key)}")


@main.command("list-ciphers")
def list_ciphers() -> None:
    """List all available ciphers with descriptions."""
    ciphers_info = [
        ("caesar", "Monoalphabetic substitution with fixed shift"),
        ("vigenere", "Polyalphabetic substitution using keyword"),
        ("vernam", "XOR one-time pad"),
        ("transposition", "Columnar transposition"),
        ("playfair", "Digraph substitution using 5x5 grid"),
        ("railfence", "Zigzag transposition"),
        ("affine", "Modular arithmetic substitution"),
        ("atbash", "Alphabet reversal"),
        ("bacon", "Binary-coded steganographic"),
        ("hill", "Matrix-based polygraphic substitution"),
        ("bifid", "Fractionation + transposition"),
        ("trifid", "3D fractionation"),
        ("foursquare", "Double keyed digraph substitution"),
        ("porta", "Polyalphabetic with reciprocal table"),
        ("adfgvx", "WWI field cipher (Polybius + columnar)"),
        ("monoalphabetic", "General single-alphabet replacement"),
        ("myszkowski", "Columnar with repeated-key grouping"),
    ]

    click.echo("=== Available Ciphers ===\n")
    for name, desc in ciphers_info:
        click.echo(f"  {name:<20s} {desc}")


def _run_encrypt(cipher: str, key: str, plaintext: str, shift: int | None) -> str:
    """Route encryption to the appropriate cipher module."""
    if cipher == "caesar":
        from cryptovault.ciphers.caesar import CaesarCipher
        s = shift if shift is not None else int(key)
        return CaesarCipher(s).encrypt(plaintext)
    elif cipher == "vigenere":
        from cryptovault.ciphers.vigenere import VigenereCipher
        return VigenereCipher().encrypt(plaintext, key)
    elif cipher == "vernam":
        from cryptovault.ciphers.vernam import VernamCipher
        return VernamCipher().encrypt(plaintext, key)
    elif cipher == "transposition":
        from cryptovault.ciphers.transposition import ColumnarTransposition
        return ColumnarTransposition().encrypt(plaintext, key)
    elif cipher == "playfair":
        from cryptovault.ciphers.playfair import PlayfairCipher
        return PlayfairCipher(key).encrypt(plaintext)
    elif cipher == "railfence":
        from cryptovault.ciphers.railfence import RailFenceCipher
        return RailFenceCipher(int(key)).encrypt(plaintext)
    elif cipher == "affine":
        from cryptovault.ciphers.affine import AffineCipher
        parts = key.split(",")
        a, b = int(parts[0]), int(parts[1])
        return AffineCipher(a, b).encrypt(plaintext)
    elif cipher == "atbash":
        from cryptovault.ciphers.atbash import AtbashCipher
        return AtbashCipher().encrypt(plaintext)
    elif cipher == "bacon":
        from cryptovault.ciphers.bacon import BaconCipher
        return BaconCipher().encrypt(plaintext)
    elif cipher == "hill":
        from cryptovault.ciphers.hill import HillCipher
        return HillCipher().encrypt(plaintext)
    elif cipher == "bifid":
        from cryptovault.ciphers.bifid import BifidCipher
        return BifidCipher(key).encrypt(plaintext)
    elif cipher == "trifid":
        from cryptovault.ciphers.trifid import TrifidCipher
        return TrifidCipher(key).encrypt(plaintext)
    elif cipher == "foursquare":
        from cryptovault.ciphers.foursquare import FourSquareCipher
        parts = key.split(",")
        k1 = parts[0] if len(parts) > 0 else "EXAMPLE"
        k2 = parts[1] if len(parts) > 1 else "KEYWORD"
        return FourSquareCipher(k1, k2).encrypt(plaintext)
    elif cipher == "porta":
        from cryptovault.ciphers.porta import PortaCipher
        return PortaCipher(key).encrypt(plaintext)
    elif cipher == "adfgvx":
        from cryptovault.ciphers.adfgvx import ADFGVXCipher
        parts = key.split(",")
        pk = parts[0] if len(parts) > 0 else "SECRET"
        tk = parts[1] if len(parts) > 1 else "CARGO"
        return ADFGVXCipher(pk, tk).encrypt(plaintext)
    elif cipher == "monoalphabetic":
        from cryptovault.ciphers.monoalphabetic import MonoalphabeticCipher
        return MonoalphabeticCipher(key).encrypt(plaintext)
    elif cipher == "myszkowski":
        from cryptovault.ciphers.myszkowski import MyszkowskiCipher
        return MyszkowskiCipher(key).encrypt(plaintext)
    else:
        msg = f"Unknown cipher: {cipher}"
        raise click.BadParameter(msg)


def _run_decrypt(cipher: str, key: str, ciphertext: str, shift: int | None) -> str:
    """Route decryption to the appropriate cipher module."""
    if cipher == "caesar":
        from cryptovault.ciphers.caesar import CaesarCipher
        s = shift if shift is not None else int(key)
        return CaesarCipher(s).decrypt(ciphertext)
    elif cipher == "vigenere":
        from cryptovault.ciphers.vigenere import VigenereCipher
        return VigenereCipher().decrypt(ciphertext, key)
    elif cipher == "vernam":
        from cryptovault.ciphers.vernam import VernamCipher
        return VernamCipher().decrypt(ciphertext, key)
    elif cipher == "transposition":
        from cryptovault.ciphers.transposition import ColumnarTransposition
        return ColumnarTransposition().decrypt(ciphertext, key)
    elif cipher == "playfair":
        from cryptovault.ciphers.playfair import PlayfairCipher
        return PlayfairCipher(key).decrypt(ciphertext)
    elif cipher == "railfence":
        from cryptovault.ciphers.railfence import RailFenceCipher
        return RailFenceCipher(int(key)).decrypt(ciphertext)
    elif cipher == "affine":
        from cryptovault.ciphers.affine import AffineCipher
        parts = key.split(",")
        a, b = int(parts[0]), int(parts[1])
        return AffineCipher(a, b).decrypt(ciphertext)
    elif cipher == "atbash":
        from cryptovault.ciphers.atbash import AtbashCipher
        return AtbashCipher().decrypt(ciphertext)
    elif cipher == "bacon":
        from cryptovault.ciphers.bacon import BaconCipher
        return BaconCipher().decrypt(ciphertext)
    elif cipher == "hill":
        from cryptovault.ciphers.hill import HillCipher
        return HillCipher().decrypt(ciphertext)
    elif cipher == "bifid":
        from cryptovault.ciphers.bifid import BifidCipher
        return BifidCipher(key).decrypt(ciphertext)
    elif cipher == "trifid":
        from cryptovault.ciphers.trifid import TrifidCipher
        return TrifidCipher(key).decrypt(ciphertext)
    elif cipher == "foursquare":
        from cryptovault.ciphers.foursquare import FourSquareCipher
        parts = key.split(",")
        k1 = parts[0] if len(parts) > 0 else "EXAMPLE"
        k2 = parts[1] if len(parts) > 1 else "KEYWORD"
        return FourSquareCipher(k1, k2).decrypt(ciphertext)
    elif cipher == "porta":
        from cryptovault.ciphers.porta import PortaCipher
        return PortaCipher(key).decrypt(ciphertext)
    elif cipher == "adfgvx":
        from cryptovault.ciphers.adfgvx import ADFGVXCipher
        parts = key.split(",")
        pk = parts[0] if len(parts) > 0 else "SECRET"
        tk = parts[1] if len(parts) > 1 else "CARGO"
        return ADFGVXCipher(pk, tk).decrypt(ciphertext)
    elif cipher == "monoalphabetic":
        from cryptovault.ciphers.monoalphabetic import MonoalphabeticCipher
        return MonoalphabeticCipher(key).decrypt(ciphertext)
    elif cipher == "myszkowski":
        from cryptovault.ciphers.myszkowski import MyszkowskiCipher
        return MyszkowskiCipher(key).decrypt(ciphertext)
    else:
        msg = f"Unknown cipher: {cipher}"
        raise click.BadParameter(msg)


def _run_crack(cipher: str, ciphertext: str, top: int) -> list[tuple[str, str, float]]:
    """Route cracking to the appropriate attack module."""
    if cipher == "caesar":
        from cryptovault.cryptanalysis.caesar_cracker import crack_caesar
        shift, plaintext, confidence = crack_caesar(ciphertext)
        return [(str(shift), plaintext, confidence)]
    elif cipher == "vigenere":
        from cryptovault.ciphers.vigenere import VigenereCipher
        results = VigenereCipher().crack(ciphertext)
        return results[:top]
    elif cipher == "affine":
        from cryptovault.cryptanalysis.affine_cracker import crack_affine
        return crack_affine(ciphertext, top)
    elif cipher == "railfence":
        from cryptovault.cryptanalysis.railfence_cracker import crack_railfence
        results = crack_railfence(ciphertext)
        return [(str(r), p, s) for r, p, s in results[:top]]
    else:
        msg = f"Cracking not supported for cipher: {cipher}"
        raise click.BadParameter(msg)


if __name__ == "__main__":
    main()
