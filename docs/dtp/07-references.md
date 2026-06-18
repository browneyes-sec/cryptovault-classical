# Deliverable Technical Package — References & Standards Compliance

**Version:** 0.2.0  
**Date:** June 2026  

---

## 1. Cryptographic Standards

| Standard | Description | Relevance |
|---|---|---|
| NIST SP 800-57 Part 1 Rev. 5 | Key Management | Key generation, storage, rotation |
| NIST SP 800-175B | Guideline for Using Cryptographic Standards | Algorithm selection guidance |
| FIPS 197 | Advanced Encryption Standard (AES) | KeyStore encryption (AES-CBC) |
| FIPS 198-1 | HMAC (Keyed-Hash Message Authentication) | HMAC-SHA256 implementation |
| FIPS 186-4 | Digital Signature Standard | RSA-like signing |
| NIST SP 800-132 | Password-Based Key Derivation (PBKDF2) | KeyStore key derivation |

## 2. Classical Cryptography References

### 2.1 Foundational Texts

| Reference | Citation |
|---|---|
| Kahn, D. | *The Codebreakers: The Comprehensive History of Secret Communication from Ancient Times to the Internet*. Scribner, 1996. |
| Singh, S. | *The Code Book: The Science of Secrecy from Ancient Egypt to Quantum Cryptography*. Anchor, 2000. |
| Trappe, W. & Washington, L. | *Introduction to Cryptography with Coding Theory*. 2nd ed., Pearson, 2006. |
| Stinson, D.R. | *Cryptography: Theory and Practice*. 3rd ed., CRC Press, 2005. |
| Katz, J. & Lindell, Y. | *Introduction to Modern Cryptography*. 2nd ed., CRC Press, 2015. |

### 2.2 Cipher-Specific References

| Cipher | Reference |
|---|---|
| Caesar | Suetonius, *The Twelve Caesars*, c. 121 AD |
| Vigenère | Vigenère, B. *Traiffé Chiffres*, 1586 |
| Playfair | Playfair, L. & Wheatstone, C., c. 1854 |
| Hill | Hill, L.S. "The Cryptography of Apostolic Constitutions." *American Mathematical Monthly*, 1929. |
| ADFGVX | Friedman, W.F. *The War of the Ciphers*. 1937. |
| Vernam | Vernam, A.S. "Cipher Printing Telegraph Systems." *Bell System Technical Journal*, 1926. |
| Bifid | Bazeries, E. *Les Chiffres secrets dévoilés*. 1901. |
| Trifid | Givierge, M. *Cours de Cryptographie*. 1925. |
| Porta | Porta, G.B. *De Furtivis Literarum Notis*. 1563. |

## 3. Modern Cryptography References

| Reference | Citation |
|---|---|
| Diffie, W. & Hellman, M.E. | "New Directions in Cryptography." *IEEE Transactions on Information Theory*, 22(6), 1976. |
| Rivest, R.L., Shamir, A. & Adleman, L. | "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems." *Communications of the ACM*, 21(2), 1978. |
| Shannon, C.E. | "Communication Theory of Secrecy Systems." *Bell System Technical Journal*, 28(4), 1949. |
| Kerckhoffs, A. | "La Cryptographie Militaire." *Journal des Sciences Militaires*, 1883. |

## 4. Web Development Standards

| Standard | Description | Compliance |
|---|---|---|
| PEP 621 | Python package metadata | ✅ pyproject.toml |
| PEP 484 | Type hints | ✅ Throughout codebase |
| PEP 8 | Style guide | ✅ via ruff |
| RFC 7231 | HTTP/1.1 Semantics | ✅ FastAPI REST |
| OpenAPI 3.1 | API documentation | ✅ Auto-generated |
| WCAG 2.1 AA | Web accessibility | ✅ ARIA labels, focus indicators |
| ES2022 | JavaScript standard | ✅ Vanilla JS |

## 5. Architecture Frameworks

| Framework | Application |
|---|---|
| TOGAF ADM | Enterprise architecture assessment (Phase A-H) |
| Zachman 6×6 | System architecture matrix (What/How/Where/Who/When/Why) |
| SOLID Principles | Class design (Single Responsibility, Open/Closed, etc.) |
| Defense-in-Depth | Layered security model |

## 6. Testing Standards

| Standard | Description | Compliance |
|---|---|---|
| pytest | Python test framework | ✅ |
| coverage.py | Code coverage measurement | ✅ ≥80% target |
| mypy | Static type checking | ✅ Strict mode |
| ruff | Python linter | ✅ Zero errors |

## 7. Security Standards

| Standard | Description | Compliance |
|---|---|---|
| OWASP Top 10 | Web application security risks | ✅ Input validation, no eval() |
| CWE-78 | OS Command Injection | ✅ Not applicable |
| CWE-89 | SQL Injection | ✅ No SQL database |
| CWE-327 | Use of Broken Crypto | ⚠️ By design (educational) |
| CVE Disclosure | Vulnerability disclosure | ✅ GitHub Security Advisory |

## 8. Open Source Licenses

| License | Compatibility |
|---|---|
| GPL-3.0 | Project license |
| MIT | Compatible with GPL-3.0 |
| Apache-2.0 | Compatible with GPL-3.0 |
| BSD-2-Clause | Compatible with GPL-3.0 |

## 9. Publication Venues

| Venue | Type | Impact Factor |
|---|---|---|
| ACM SIGCSE Technical Symposium | Conference | — |
| IEEE Security & Privacy | Conference | 4.2 |
| Journal of Cryptographic Engineering | Journal | 1.5 |
| Cryptologia | Journal | 0.8 |
| Computers & Security | Journal | 3.9 |

## 10. Digital Object Identifier (DOI)

- **Project DOI:** Pending registration with Zenodo
- **Citation format:** `browneyes-sec. (2026). CryptoVault Classical: An Open-Source Educational Cryptographic Toolkit. GitHub. https://github.com/browneyes-sec/cryptovault-classical`
