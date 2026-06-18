# Deliverable Technical Package — Executive Summary

**Project:** CryptoVault Classical  
**Version:** 0.2.0  
**Date:** June 2026  
**Author:** browneyes-sec  
**License:** GPL-3.0  

---

## 1. Project Overview

CryptoVault Classical is an open-source educational cryptographic toolkit that implements 19 classical ciphers with full cryptanalysis capabilities, key management, and secure communication protocols. The project transforms a legacy C++ codebase (by José Pablo Molina Ávila) into a modern, well-documented Python package with a web-based interactive learning portal.

## 2. Objectives

| Objective | Status |
|---|---|
| Implement all 19 classical ciphers with standardized API | ✅ Complete |
| Build comprehensive cryptanalysis module (10 attack methods) | ✅ Complete |
| Deliver key management (generation, storage, rotation, DH exchange) | ✅ Complete |
| Implement communication protocols (MAC, signing, envelope, channel) | ✅ Complete |
| Provide interactive CLI with Click | ✅ Complete |
| Achieve ≥80% test coverage | ✅ Complete (30/30 tests) |
| Build FastAPI web portal with interactive labs | 🔄 In Progress |
| Publish scientific research paper draft | 🔄 In Progress |

## 3. Stakeholders

| Role | Entity |
|---|---|
| Development Team | browneyes-sec |
| Original Author | José Pablo Molina Ávila |
| Primary Users | Students, researchers, cryptography educators |
| Secondary Users | Security professionals, CTF participants |
| Governance | GPL-3.0 open-source community |

## 4. Scope

### 4.1 In Scope

- 19 cipher implementations (monoalphabetic, polyalphabetic, polygraphic, fractionation, transposition, special)
- 10 cryptanalysis modules (frequency analysis, IoC, Kasiski, brute-force, known-plaintext)
- Key management (secure generation, encrypted storage, rotation policies, Diffie-Hellman)
- Communication protocols (HMAC-SHA256, RSA-like signing, Encrypt-then-MAC envelope, DH key exchange)
- CLI interface (encrypt, decrypt, crack, analyze, keygen, list-ciphers, dh-demo)
- Web portal (FastAPI backend, vanilla JS SPA, 5 interactive labs)
- Documentation (this DTP, scientific paper, research statement)

### 4.2 Out of Scope

- Modern symmetric ciphers (AES, ChaCha20) — separate project
- Asymmetric cryptography beyond DH/RSA-like teaching implementations
- Production-grade TLS/SSL — educational protocols only
- Hardware security module (HSM) integration

## 5. Architecture Principles

| Principle | Implementation |
|---|---|
| SOLID | CipherBase ABC enforces single responsibility; each cipher is a standalone class |
| Defense-in-Depth | KeyStore encryption + PBKDF2 derivation + rotation policies |
| Reversibility | All ciphers support encrypt/decrypt; no destructive operations |
| Testability | Every cipher has roundtrip tests; ≥80% coverage enforced |
| Educational Transparency | Full docstrings, algorithm explanations, vulnerability annotations |

## 6. Deliverable List

| Deliverable | Format | Location |
|---|---|---|
| Python package | pip-installable | `cryptovault/` |
| CLI tool | Click-based | `cryptovault/cli.py` |
| Web portal | FastAPI + SPA | `web/` (planned) |
| Test suite | pytest | `tests/` |
| DTP documentation | Markdown | `docs/dtp/` |
| Scientific paper | Markdown (IEEE/ACM) | `docs/scientific/` |
| Research statement | Markdown | `docs/scientific/` |

## 7. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| No pip in build env | High | Medium | Tests via `python3 -c` inline runner |
| `gh` CLI unavailable | High | Low | Push via PAT in remote URL |
| Web portal scope creep | Medium | High | Strict DTP adherence; 4 ciphers in v1 |
| Academic review rejection | Low | Medium | Peer review before submission |

## 8. Acceptance Criteria

- [ ] All 19 ciphers pass roundtrip tests
- [ ] All 10 cryptanalysis modules produce correct results
- [ ] KeyStore encrypts/decrypts reliably
- [ ] Diffie-Hellman exchange produces matching shared secrets
- [ ] CLI handles all cipher operations
- [ ] Web portal serves on port 8000 without errors
- [ ] Documentation is complete and accurate
- [ ] Scientific paper is publication-ready
