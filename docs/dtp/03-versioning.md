# Deliverable Technical Package — Versioning & Release Lifecycle

**Version:** 0.2.0  
**Date:** June 2026  

---

## 1. Semantic Versioning Policy

CryptoVault Classical follows [Semantic Versioning 2.0.0](https://semver.org/).

### 1.1 Version Format

```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

| Component | Increment When |
|---|---|
| MAJOR | Breaking API changes (cipher interface, key format, return types) |
| MINOR | New ciphers, new analysis methods, new CLI commands (backward-compatible) |
| PATCH | Bug fixes, docstring updates, performance improvements |
| PRERELEASE | `alpha`, `beta`, `rc1`, `rc2` |
| BUILD | Build metadata (e.g., `+20260618`) |

### 1.2 Current Versions

| Version | Release Date | Description |
|---|---|---|
| 0.1.0 | May 2026 | Initial Python port (4 core ciphers) |
| 0.2.0 | June 2026 | Extended to 19 ciphers, key management, protocols |
| 0.3.0 | Planned | Web portal, FastAPI backend |
| 1.0.0 | Planned | Stable API, full test coverage, production-ready |

## 2. Changelog Format

All changes documented in `CHANGELOG.md` following [Keep a Changelog](https://keepachangelog.com/).

```markdown
# Changelog

## [Unreleased]

### Added
- Web portal with FastAPI backend
- 5 interactive cryptography labs

### Changed
- Migrated CLI from argparse to Click

### Fixed
- Playfair cipher padding handling

### Deprecated
- `crack_vigenere()` → use `VigenereCipher.crack()`

### Removed
- Legacy C++ source files

### Security
- Patched weak key validation in VernamCipher

## [0.2.0] - 2026-06-18

### Added
- 13 extended ciphers (Playfair, Rail Fence, Affine, Atbash, Bacon, Hill, Bifid, Trifid, Four-Square, Porta, ADFGVX, Monoalphabetic, Myszkowski)
- 6 cryptanalysis crackers
- Key management module (generator, keystore, rotation, Diffie-Hellman)
- Communication protocols (MAC, signing, envelope, channel)
- CLI extensions (keygen, dh-demo, list-ciphers)

## [0.1.0] - 2026-05-XX

### Added
- Caesar cipher with brute-force
- Vigenere cipher
- Vernam cipher (XOR OTP)
- Columnar transposition (3 variants)
- Frequency analysis
- Index of Coincidence
- Kasiski examination
```

## 3. Release Lifecycle

### 3.1 Release Stages

```
Development → Alpha → Beta → Release Candidate → Stable Release
    ↓           ↓       ↓           ↓                  ↓
  feature/   v0.3.0a1 v0.3.0b1  v0.3.0rc1          v0.3.0
```

### 3.2 Release Process

1. **Feature Freeze:** All planned features merged to `main`
2. **Alpha Release:** `v0.3.0a1` — internal testing
3. **Beta Release:** `v0.3.0b1` — external early adopters
4. **Release Candidate:** `v0.3.0rc1` — full test suite passes
5. **Stable Release:** `v0.3.0` — tagged, published to PyPI
6. **Post-Release:** Hotfix branch for critical bugs

### 3.3 Release Checklist

- [ ] All tests pass (`python -m pytest tests/ -v`)
- [ ] Linting passes (`ruff check cryptovault/`)
- [ ] Type checking passes (`mypy cryptovault/`)
- [ ] Version bumped in `pyproject.toml`
- [ ] `CHANGELOG.md` updated
- [ ] Git tag created (`git tag v0.3.0`)
- [ ] Pushed to GitHub (`git push origin main --tags`)
- [ ] Release published on GitHub
- [ ] PyPI package published
- [ ] README.md updated if API changed

## 4. Branch Strategy

```
main ←── stable releases
  ↑
develop ←── integration branch
  ↑
feature/* ←── new features
bugfix/* ←── bug fixes
hotfix/* ←── critical production fixes
```

### 4.1 Branch Naming

| Pattern | Purpose | Example |
|---|---|---|
| `feature/*` | New functionality | `feature/web-portal-api` |
| `bugfix/*` | Non-critical fixes | `bugfix/playfair-padding` |
| `hotfix/*` | Critical production fixes | `hotfix/vernam-weak-key` |
| `release/*` | Release preparation | `release/v0.3.0` |

## 5. Deprecation Policy

| Phase | Duration | Action |
|---|---|---|
| Warning | 2 minor versions | `DeprecationWarning` in code + docs |
| Error | 1 minor version | Raises `DeprecatedError` |
| Removal | Next major version | Code removed |

## 6. Compatibility Guarantees

| Guarantee | Scope |
|---|---|
| Python versions | ≥3.10 (current: 3.10, 3.11, 3.12) |
| API stability | Stable after v1.0.0 |
| Key format | Stable after v1.0.0 |
| CLI interface | Stable after v1.0.0 |
| Web API | Versioned (`/api/v1/`) |

## 7. Security Releases

Security fixes follow accelerated timeline:

1. **Report received** → Triage within 24 hours
2. **Fix developed** → Patch release within 72 hours
3. **CVE assigned** → If applicable
4. **Disclosure** → Coordinated with reporter
5. **Advisory published** → GitHub Security Advisory
