# CryptoVault Classical

Python refactoring of classical encryption & cryptanalysis algorithms — with full cipher suite, key management, and communication protocols.

> **Educational Purpose Only** — These are historical ciphers with known vulnerabilities. Never use for real-world encryption.

## Algorithms

### Substitution Ciphers

| Cipher | Type | Key | Vulnerability | Attack |
|---|---|---|---|---|
| **Caesar** | Monoalphabetic | Shift (0-25) | Fixed shift (26 keys) | Brute-force, frequency analysis |
| **Affine** | Monoalphabetic | (a,b) pair | Modular math | Known-plaintext, brute-force |
| **Atbash** | Monoalphabetic | None (fixed) | Fixed mapping | Direct reversal |
| **Monoalphabetic** | Monoalphabetic | 26-char permutation | Single substitution | Frequency analysis |
| **Vigenère** | Polyalphabetic | Keyword | Periodic key repetition | Kasiski, IoC |
| **Porta** | Polyalphabetic | Keyword | Periodic table | Known-plaintext |

### Polyalphabetic / Polygraphic Ciphers

| Cipher | Type | Key | Vulnerability | Attack |
|---|---|---|---|---|
| **Playfair** | Digraph | Keyword (5×5 grid) | Digraph patterns | Crib-based, frequency |
| **Hill** | Polygraphic | n×n matrix | Known-plaintext | Matrix recovery |
| **Bifid** | Fractionation | Keyword | Period structure | Frequency scoring |
| **Trifid** | 3D Fractionation | Keyword | Period structure | Keyword brute-force |
| **Four-Square** | Digraph | Two keywords | Double substitution | Known-plaintext |

### Transposition Ciphers

| Cipher | Type | Key | Vulnerability | Attack |
|---|---|---|---|---|
| **Columnar** | Permutation | Keyword | Structural pattern | Anagramming |
| **Rail Fence** | Zigzag | Rail count | Low key space | Brute-force |
| **Myszkowski** | Columnar variant | Keyword | Repeated key groups | Pattern analysis |

### Special Ciphers

| Cipher | Type | Key | Vulnerability | Attack |
|---|---|---|---|---|
| **Vernam** | XOR OTP | Random bytes | Key reuse / short key | XOR crib-dragging |
| **Bacon** | Steganographic | None (2 types) | Visual pattern | Direct extraction |
| **ADFGVX** | Field cipher | Two keywords | Polybius + columnar | Crib-based |

### Binary / Bit Operations

| Utility | Description |
|---|---|
| **Binary Utils** | bin↔dec conversion, XOR operations |

## Installation

```bash
git clone https://github.com/browneyes-sec/cryptovault-classical.git
cd cryptovault-classical
pip install -e ".[dev]"
```

## Python API

```python
from cryptovault.ciphers import (
    CaesarCipher, VigenereCipher, VernamCipher,
    ColumnarTransposition, PlayfairCipher, AffineCipher,
    RailFenceCipher, AtbashCipher, BaconCipher,
    HillCipher, BifidCipher, TrifidCipher,
    FourSquareCipher, PortaCipher, ADFGVXCipher,
    MonoalphabeticCipher, MyszkowskiCipher,
)

# Caesar
cipher = CaesarCipher(shift=3)
encrypted = cipher.encrypt("hello")        # "khoor"
decrypted = cipher.decrypt("khoor")        # "hello"
results = cipher.crack("khoor")            # [(3, "hello", ...), ...]

# Vigenère
cipher = VigenereCipher()
encrypted = cipher.encrypt("hello", "key")
decrypted = cipher.decrypt(encrypted, "key")

# Playfair
cipher = PlayfairCipher("KEYWORD")
encrypted = cipher.encrypt("HELLO")
decrypted = cipher.decrypt(encrypted)

# Affine (a,b must be coprime with 26)
cipher = AffineCipher(a=5, b=8)
encrypted = cipher.encrypt("HELLO")
decrypted = cipher.decrypt(encrypted)
results = cipher.crack(encrypted)  # Brute-force all 312 keys

# Hill (3x3 matrix)
cipher = HillCipher()
encrypted = cipher.encrypt("ACT")
decrypted = cipher.decrypt(encrypted)

# Rail Fence
cipher = RailFenceCipher(rails=3)
encrypted = cipher.encrypt("WEAREDISCOVEREDFLEEATONCE")
decrypted = cipher.decrypt(encrypted)

# Atbash (no key needed)
cipher = AtbashCipher()
encrypted = cipher.encrypt("HELLO")  # "SVOLI"
decrypted = cipher.decrypt(encrypted)  # "HELLO"

# ADFGVX
cipher = ADFGVXCipher(polybius_key="SECRET", transposition_key="CARGO")
encrypted = cipher.encrypt("HELLO123")
decrypted = cipher.decrypt(encrypted)
```

## CLI

```bash
# List all ciphers
cryptovault list-ciphers

# Encrypt/Decrypt with any cipher
cryptovault encrypt --cipher caesar --key 3 --input "hello"
cryptovault encrypt --cipher vigenere --key "SECRET" --input "hello"
cryptovault encrypt --cipher playfair --key "KEYWORD" --input "hello"
cryptovault encrypt --cipher affine --key "5,8" --input "hello"
cryptovault encrypt --cipher railfence --key 3 --input "hello"

# Decrypt
cryptovault decrypt --cipher caesar --key 3 --input "khoor"
cryptovault decrypt --cipher vigenere --key "SECRET" --input "rijvs"

# Crack (no key needed)
cryptovault crack --cipher caesar --input "khoor"
cryptovault crack --cipher vigenere --input "ciphertext"
cryptovault crack --cipher affine --input "ciphertext"
cryptovault crack --cipher railfence --input "ciphertext"

# Analyze text
cryptovault analyze --input "any text to analyze"

# Generate keys
cryptovault keygen --cipher caesar
cryptovault keygen --cipher vigenere
cryptovault keygen --cipher affine
cryptovault keygen --cipher playfair
cryptovault keygen --cipher hill
cryptovault keygen --cipher monoalphabetic

# Diffie-Hellman key exchange demo
cryptovault dh-demo
```

## Cryptanalysis

```python
from cryptovault.cryptanalysis import (
    frequency_analysis,
    index_of_coincidence,
    classify_text,
    kasiski_examination,
    estimate_key_length,
    recover_key,
    crack_caesar,
    crack_affine,
    crack_railfence,
    crack_playfair_frequency,
)

# Frequency analysis
freq = frequency_analysis("hello world")

# Index of Coincidence + classification
ioc = index_of_coincidence("hello world")
classification, ioc_val = classify_text("hello world")

# Vigenère analysis
candidates = kasiski_examination(ciphertext)
key_length = estimate_key_length(ciphertext)
key = recover_key(ciphertext, key_length)

# Caesar brute-force
shift, plaintext, confidence = crack_caesar("khoor")

# Affine brute-force (312 keys)
results = crack_affine(ciphertext, top_n=5)

# Rail Fence brute-force
results = crack_railfence(ciphertext, top_n=5)
```

## Key Management

```python
from cryptovault.keymanagement import (
    generate_caesar_key, generate_vigenere_key,
    generate_affine_key, generate_hill_key,
    KeyStore, KeyRotationManager, KeyRotationPolicy,
    DiffieHellman, verify_dh_exchange,
)

# Key generation
caesar_key = generate_caesar_key()           # Random 0-25
vigenere_key = generate_vigenere_key(6)      # Random 6-char
affine_key = generate_affine_key()           # Random (a,b) pair
hill_matrix = generate_hill_key(3)           # Random 3x3 invertible

# Encrypted key storage
ks = KeyStore("my_keystore.json")
ks.store_key("my_caesar", "5", "master_password")
key = ks.retrieve_key("my_caesar", "master_password")

# Key rotation
manager = KeyRotationManager()
policy = KeyRotationPolicy(max_age_seconds=86400, max_uses=1000)
manager.register_key("cipher1", "key_value", policy)
if manager.needs_rotation("cipher1"):
    manager.rotate_key("cipher1")

# Diffie-Hellman key exchange
dh = DiffieHellman(256)
alice = dh.generate_keypair()
bob = dh.generate_keypair()
shared = dh.exchange(alice, bob.public_key)
assert verify_dh_exchange(dh, alice.private_key, alice.public_key,
                          bob.private_key, bob.public_key)
```

## Communication Protocols

```python
from cryptovault.protocols import (
    HMAC, create_mac, verify_mac,
    SignatureKeyPair, sign_message, verify_signature,
    SecureEnvelope, SimpleEnvelope,
    establish_secure_channel,
)

# HMAC message authentication
hmac = HMAC(b"secret_key")
tag = hmac.compute(b"hello world")
assert hmac.verify(b"hello world", tag)

# Digital signatures
keypair = SignatureKeyPair(1024)
signature = keypair.sign(b"important message")
assert keypair.verify(b"important message", signature)

# Encrypt-then-MAC envelope
from cryptovault.ciphers import CaesarCipher
cipher = CaesarCipher(3)
envelope = SecureEnvelope(cipher)
sealed = envelope.seal("HELLO", "3")
opened = envelope.open(sealed, "3")  # "HELLO"
assert opened == "HELLO"

# Secure channel (DH + signatures)
dh = DiffieHellman(256)
alice_sign = SignatureKeyPair(512)
bob_sign = SignatureKeyPair(512)
alice_ch, bob_ch = establish_secure_channel(dh, alice_sign, bob_sign)

encrypted = alice_ch.encrypt_message("Secret message")
decrypted = bob_ch.decrypt_message(encrypted)
assert decrypted == "Secret message"
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
│   │   ├── transposition.py     # ColumnarTransposition variants
│   │   ├── binary_utils.py      # bin↔dec, xor
│   │   ├── playfair.py          # PlayfairCipher
│   │   ├── railfence.py         # RailFenceCipher
│   │   ├── affine.py            # AffineCipher
│   │   ├── atbash.py            # AtbashCipher
│   │   ├── bacon.py             # BaconCipher
│   │   ├── hill.py              # HillCipher
│   │   ├── bifid.py             # BifidCipher
│   │   ├── trifid.py            # TrifidCipher
│   │   ├── foursquare.py        # FourSquareCipher
│   │   ├── porta.py             # PortaCipher
│   │   ├── adfgvx.py            # ADFGVXCipher
│   │   ├── monoalphabetic.py    # MonoalphabeticCipher
│   │   └── myszkowski.py        # MyszkowskiCipher
│   ├── cryptanalysis/
│   │   ├── frequency.py         # Frequency analysis
│   │   ├── index_of_coincidence.py
│   │   ├── kasiski.py           # Kasiski examination
│   │   ├── caesar_cracker.py    # Caesar brute-force
│   │   ├── playfair_cracker.py  # Playfair crib/frequency
│   │   ├── affine_cracker.py    # Affine brute-force
│   │   ├── railfence_cracker.py # Rail Fence brute-force
│   │   ├── hill_cracker.py      # Hill known-plaintext
│   │   ├── bifid_cracker.py     # Bifid/Trifid cracking
│   │   └── adfgvx_cracker.py    # ADFGVX cryptanalysis
│   ├── keymanagement/
│   │   ├── generator.py         # Secure key generation
│   │   ├── keystore.py          # Encrypted local storage
│   │   ├── rotation.py          # Key rotation policies
│   │   └── diffie_hellman.py    # DH key exchange
│   ├── protocols/
│   │   ├── mac.py               # HMAC authentication
│   │   ├── signing.py           # Digital signatures
│   │   ├── envelope.py          # Encrypt-then-MAC
│   │   └── channel.py           # Secure channel handshake
│   └── cli.py                   # Click CLI
├── tests/
│   ├── test_ciphers.py          # Cipher KATs + roundtrips
│   ├── test_cryptanalysis.py    # Cracker tests
│   └── test_keymanagement.py    # Key mgmt + protocol tests
├── pyproject.toml
├── requirements.txt
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
