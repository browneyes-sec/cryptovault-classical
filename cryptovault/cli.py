"""Unified CLI for CryptoVault Classical.

Usage:
    cryptovault encrypt --cipher caesar --key 3 --input "hello"
    cryptovault decrypt --cipher vigenere --key "SECRET" --input "ciphertext"
    cryptovault crack --cipher caesar --input "ciphertext"
    cryptovault analyze --input "ciphertext"
"""

from __future__ import annotations

import click

from cryptovault import __version__


@click.group()
@click.version_option(version=__version__, prog_name="cryptovault")
def main() -> None:
    """CryptoVault Classical — Educational cryptographic toolkit."""


@main.command()
@click.option("--cipher", "-c", required=True, type=click.Choice(["caesar", "vigenere", "vernam", "transposition"]))
@click.option("--key", "-k", required=True, help="Encryption key")
@click.option("--input", "-i", "input_text", required=True, help="Plaintext to encrypt")
@click.option("--shift", "-s", type=int, default=None, help="Shift value (Caesar only)")
def encrypt(cipher: str, key: str, input_text: str, shift: int | None) -> None:
    """Encrypt plaintext using a classical cipher."""
    result = _run_encrypt(cipher, key, input_text, shift)
    click.echo(result)


@main.command()
@click.option("--cipher", "-c", required=True, type=click.Choice(["caesar", "vigenere", "vernam", "transposition"]))
@click.option("--key", "-k", required=True, help="Decryption key")
@click.option("--input", "-i", "input_text", required=True, help="Ciphertext to decrypt")
@click.option("--shift", "-s", type=int, default=None, help="Shift value (Caesar only)")
def decrypt(cipher: str, key: str, input_text: str, shift: int | None) -> None:
    """Decrypt ciphertext using a classical cipher."""
    result = _run_decrypt(cipher, key, input_text, shift)
    click.echo(result)


@main.command()
@click.option("--cipher", "-c", required=True, type=click.Choice(["caesar", "vigenere"]))
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
    else:
        msg = f"Cracking not supported for cipher: {cipher}"
        raise click.BadParameter(msg)


if __name__ == "__main__":
    main()
