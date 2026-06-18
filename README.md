# CryptoVault Classical

Python refactoring of classical encryption & cryptanalysis algorithms — Caesar, Vigenère, Vernam, Transposition, Binary/Bit methods — with security assessment layer.

> **Educational Purpose Only** — These are historical ciphers with known vulnerabilities. Never use for real-world encryption.

## Algorithms

| Cipher | Type | Vulnerability | Attack |
|---|---|---|---|
| **Caesar** | Monoalphabetic substitution | Fixed shift (26 keys) | Brute-force, frequency analysis |
| **Vigenère** | Polyalphabetic substitution | Periodic key repetition | Kasiski examination, IoC |
| **Vernam** | XOR one-time pad | Key reuse / short key | XOR crib-dragging |
| **Columnar Transposition** | Permutation | Structural pattern | Anagramming |
| **Binary/Bit** | Encoding helpers | Direct reversal | N/A |

## Installation

```bash
git clone https://github.com/browneyes-sec/cryptovault-classical.git
cd cryptovault-classical
pip install -e ".[dev]"
```

## Python API

```python
from cryptovault.ciphers import CaesarCipher, VigenereCipher, VernamCipher, ColumnarTransposition

# Caesar
cipher = CaesarCipher(shift=3)
encrypted = cipher.encrypt("hello")        # "khoor"
decrypted = cipher.decrypt("khoor")        # "hello"
results = cipher.crack("khoor")            # [(3, "hello", ...), ...]

# Vigenère
cipher = VigenereCipher()
encrypted = cipher.encrypt("hello", "key")  # "rijvs"
decrypted = cipher.decrypt("rijvs", "key")  # "hello"

# Vernam (one-time pad)
cipher = VernamCipher()
encrypted = cipher.encrypt("hello", "world")  # XOR result
decrypted = cipher.decrypt(encrypted, "world") # "hello"

# Transposition
cipher = ColumnarTransposition()
encrypted = cipher.encrypt("HELLOWORLD", "KEY")
decrypted = cipher.decrypt(encrypted, "KEY")
```

## CLI

```bash
# Encrypt
cryptovault encrypt --cipher caesar --key 3 --input "hello"
cryptovault encrypt --cipher vigenere --key "SECRET" --input "hello"

# Decrypt
cryptovault decrypt --cipher caesar --key 3 --input "khoor"
cryptovault decrypt --cipher vigenere --key "SECRET" --input "rijvs"

# Crack (no key needed)
cryptovault crack --cipher caesar --input "khoor"
cryptovault crack --cipher vigenere --input "rijvs"

# Analyze text
cryptovault analyze --input "any text to analyze"
```

## Cryptanalysis

```python
from cryptovault.cryptanalysis import (
    frequency_analysis,
    index_of_coincidence,
    kasiski_examination,
    estimate_key_length,
    recover_key,
    crack_caesar,
)

# Frequency analysis
freq = frequency_analysis("hello world")

# Index of Coincidence
ioc = index_of_coincidence("hello world")

# Kasiski examination for Vigenère
candidates = kasiski_examination(ciphertext)
key_length = estimate_key_length(ciphertext)
key = recover_key(ciphertext, key_length)

# Caesar brute-force
shift, plaintext, confidence = crack_caesar("khoor")
```

## Project Structure

```
cryptovault-classical/
├── cryptovault/
│   ├── ciphers/
│   │   ├── base.py              # CipherBase ABC
│   │   ├── caesar.py            # CaesarCipher
│   │   ├── vigenere.py          # VigenereCipher
│   │   ├── vernam.py            # VernamCipher
│   │   ├── transposition.py     # ColumnarTransposition
│   │   └── binary_utils.py      # bin↔dec, xor
│   ├── cryptanalysis/
│   │   ├── frequency.py         # Frequency analysis
│   │   ├── index_of_coincidence.py
│   │   ├── kasiski.py           # Kasiski examination
│   │   └── caesar_cracker.py    # Caesar brute-force
│   └── cli.py                   # Click CLI
├── tests/
│   ├── test_ciphers.py
│   └── test_cryptanalysis.py
├── pyproject.toml
└── README.md
```

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run with coverage
pytest --cov=cryptovault --cov-report=term-missing

# Lint
ruff check cryptovault/ tests/

# Type check
mypy cryptovault/
```

## License

GPL-3.0 — See [LICENSE](LICENSE) for details.

## Author

Original C++ implementations: José Pablo Molina Ávila
Python refactoring: browneyes-sec
