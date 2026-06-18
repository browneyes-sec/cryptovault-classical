# Deliverable Technical Package — Security & Threat Model

**Version:** 0.2.0  
**Date:** June 2026  

---

## 1. Security Philosophy

CryptoVault Classical is an **educational toolkit**, not a production cryptography library. The design prioritizes:

1. **Transparency** — Full algorithm visibility for learning
2. **Correctness** — Faithful implementation of classical algorithms
3. **Safety** — Clear warnings about cryptographic weakness
4. **No False Security** — Never marketed as secure for real-world use

## 2. Threat Model

### 2.1 Assets

| Asset | Sensitivity | Protection |
|---|---|---|
| User plaintext | High | In-memory only, never persisted |
| User keys | High | Encrypted KeyStore with PBKDF2 |
| Shared secrets (DH) | High | Ephemeral, not stored |
| Session state | Medium | In-memory, auto-expiring |

### 2.2 Threat Actors

| Actor | Capability | Goal |
|---|---|---|
| Student/Researcher | Legitimate user | Learn cryptography |
| Curious Observer | Read source code | Understand algorithms |
| Adversary (Educational) | Intercept ciphertext | Break classical ciphers |

### 2.3 Threat Matrix

| Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Key reuse in Vernam | High | Critical | Weak-key rejection, warnings |
| Weak password in KeyStore | High | High | PBKDF2 with high iteration count |
| Man-in-the-Middle (DH) | Low | High | Educational only, no authentication in v1 |
| Timing attacks | Low | Medium | Constant-time comparison where possible |
| Memory disclosure | Low | Medium | No persistence of plaintext in memory |
| Source code analysis | N/A | N/A | Open-source by design |

## 3. Cryptographic Guarantees

### 3.1 Per-Cipher Security Assessment

| Cipher | Security Level | Broken? | Recommendation |
|---|---|---|---|
| Caesar | Trivial | Yes (26 keys) | Educational only |
| Affine | Trivial | Yes (312 keys) | Educational only |
| Atbash | None | Self-inverse | Demonstrate involution |
| Monoalphabetic | Weak | Yes (frequency) | Demonstrate frequency analysis |
| Vigenere | Weak | Yes (Kasiski) | Demonstrate polyalphabetic weakness |
| Porta | Weak | Yes (known-plaintext) | Demonstrate reciprocity |
| Playfair | Weak | Yes (frequency) | Historical interest only |
| Hill | Weak | Yes (known-plaintext) | Demonstrate matrix algebra |
| Four-Square | Weak | Yes (frequency) | Historical interest only |
| Bifid | Weak | Yes (IoC) | Demonstrate fractionation |
| Trifid | Weak | Yes (IoC) | Demonstrate 3D fractionation |
| Columnar | Weak | Yes (anagramming) | Demonstrate transposition |
| Rail Fence | Trivial | Yes (pattern) | Demonstrate zigzag |
| Myszkowski | Weak | Yes (anagramming) | Demonstrate grouping |
| Vernam | Perfect* | No* | *Only with true random, never-reused key |
| Bacon | None | Steganographic | Demonstrate hidden messaging |
| ADFGVX | Moderate | Yes (frequency) | Historical interest (WWI) |

### 3.2 Key Management Security

| Component | Algorithm | Parameters |
|---|---|---|
| KeyStore encryption | AES-CBC | 256-bit key |
| Key derivation | PBKDF2-HMAC-SHA256 | 600,000 iterations |
| DH key exchange | Custom | 256-bit safe prime |
| HMAC | HMAC-SHA256 | 256-bit key |
| Digital signatures | RSA-like | 512-bit prime, Miller-Rabin |

### 3.3 Vernam Cipher — Perfect Secrecy Conditions

The Vernam cipher achieves **information-theoretic security** (Shannon's perfect secrecy) **if and only if**:

1. Key is truly random (not pseudorandom)
2. Key is at least as long as the plaintext
3. Key is never reused
4. Key is kept secret

```python
# VernamCipher enforces these conditions:
# - Rejects keys shorter than plaintext
# - Rejects weak/repeated patterns
# - Warns about key reuse
```

## 4. Vulnerability Disclosure

### 4.1 Disclosure Policy

| Phase | Timeline | Action |
|---|---|---|
| Report | Day 0 | Researcher reports via GitHub Security Advisory |
| Triage | Day 1 | Maintainer confirms vulnerability |
| Fix | Day 3 | Patch developed and tested |
| Release | Day 5 | Patched version released |
| Disclosure | Day 7 | Public advisory published |

### 4.2 Reporting Channels

- **GitHub Security Advisory:** Primary channel
- **Email:** browneyes-sec@users.noreply.github.com
- **PGP:** Available on request

### 4.3 Scope

**In Scope:**
- Cryptographic vulnerabilities in implementations
- Key management weaknesses
- Protocol design flaws
- Side-channel vulnerabilities

**Out of Scope:**
- Classical cipher weakness (by design — educational)
- Denial of service
- Social engineering

## 5. Secure Coding Practices

### 5.1 Principles

| Practice | Implementation |
|---|---|
| No `eval()` | Never used anywhere in codebase |
| Input validation | All cipher inputs validated |
| Type hints | PEP 484 throughout |
| Immutability | Dataclasses, frozen where possible |
| Least privilege | Minimal permissions |

### 5.2 Code Review Checklist

- [ ] No hardcoded secrets
- [ ] No `eval()` or `exec()`
- [ ] Input validation present
- [ ] Type hints complete
- [ ] Docstrings present
- [ ] Tests cover new code
- [ ] No security regressions

## 6. Dependency Security

| Dependency | Version | Vulnerability Scan |
|---|---|---|
| click | ≥8.0 | `pip-audit` |
| pytest | ≥7.0 | N/A (dev only) |
| ruff | ≥0.1.0 | N/A (dev only) |
| mypy | ≥1.0 | N/A (dev only) |

### 6.1 Audit Commands

```bash
# Check for known vulnerabilities
pip-audit

# Check for outdated packages
pip list --outdated

# Security scan
bandit -r cryptovault/
```

## 7. Compliance & Standards

| Standard | Compliance |
|---|---|
| NIST SP 800-57 | Key management aligned (educational) |
| NIST SP 800-175B | Cryptographic algorithm guidance |
| OWASP Top 10 | Web portal hardened |
| WCAG 2.1 AA | Web portal accessible |

## 8. Security Testing

| Test Type | Tool | Frequency |
|---|---|---|
| Static analysis | bandit | Every commit |
| Dependency audit | pip-audit | Weekly |
| Type checking | mypy | Every commit |
| Fuzz testing | hypothesis | Monthly |
| Penetration testing | Manual | Quarterly |
