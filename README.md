# @qmoosa/pqc-mldsa-tests

**QMOOSA Post-Quantum Cryptography — NIST FIPS 204 ML-DSA Multi-Repo Reality Gates & Invariant CI**

Part of the **QMOOSA-1000 Sovereign Web4 Infrastructure Portfolio** (Repository 060 / 1,000, Domain 2: Post-Quantum Cryptography & Zero-Knowledge Reality Gates, Batch 12).

---

## 1. Multi-Tier Reality Gates Architecture

This repository acts as the central security and verification anchor for Batch 12 (NIST FIPS 204 ML-DSA Module-Lattice Digital Signatures). It enforces four non-negotiable reality gates:

```
[Pinned Source Commits]
          │
          ▼
┌──────────────────────────────────────────────┐
│ Gate 1: Strict SHA-256 Checksum Gate        │  ==> Verifies canonical tarball checksums
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ Gate 2: Source Provenance Ancestry Gate     │  ==> Verifies git merge-base ancestry
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ Gate 3: Strict Current-HEAD Alignment Gate   │  ==> Verifies exact commit alignment
└──────────────────────────────────────────────┘
          │
          ▼
┌──────────────────────────────────────────────┐
│ Gate 4: Adversarial Negative Control Suite   │  ==> 14 rigorous tests against corruption,
└──────────────────────────────────────────────┘      replay attacks & tampering
```

---

## 2. Invariants & Reality Verifications

- **Gate 1 (Archive Integrity):** Verifies SHA-256 hashes of `@qmoosa/pqc-mldsa-protocol`, `@qmoosa/pqc-mldsa-engine`, and `@qmoosa/pqc-mldsa-sdk` tarballs.
- **Gate 2 (Source Provenance):** Verifies that pinned commits are direct ancestors in the repository histories.
- **Gate 3 (Current-HEAD Alignment):** Ensures zero drift between declared manifest hashes and live repository HEAD commits.
- **Gate 4 (Adversarial Negative Controls):** 14 negative controls validating rejection of single-bit signature flips, tampered amounts, nonce changes, recipient substitutions, cross-chain context replays, and parameter overflows.

---

## 3. Scorecard & Status

- **Repositories in Portfolio:** 60 / 1,000 (Batch 12 Milestone Reached)
- **Production Certification Status:** 0 / 60 (Strictly locked from mainnet deployment until formal audit sign-offs).
- **Cost Incurred:** $0.00
