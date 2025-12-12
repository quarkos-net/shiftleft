# Reproducibility Evidence

This directory contains cryptographically verifiable evidence for all claims made in:

**"Pre-Silicon Side-Channel Verification of Post-Quantum Hardware: A Shift-Left Approach"**

## Files

| File | Purpose | How to Verify |
|------|---------|---------------|
| `REPRODUCIBILITY_EVIDENCE_PACKAGE.md` | Main evidence document | Read it |
| `REPRODUCIBILITY_EVIDENCE_PACKAGE.md.ots` | Bitcoin blockchain timestamp | `ots verify *.ots` |
| `REPRODUCIBILITY_EVIDENCE_PACKAGE.md.asc` | GPG signature (author identity) | `gpg --verify *.asc` |
| `PUBLIC_KEY.asc` | Author's GPG public key | Import to verify signature |

## Quick Verification

### 1. Verify Blockchain Timestamp (Proof of Existence)

```bash
pip install opentimestamps-client
ots verify REPRODUCIBILITY_EVIDENCE_PACKAGE.md.ots
```

### 2. Verify GPG Signature (Proof of Authorship)

```bash
# Import author's public key
gpg --import PUBLIC_KEY.asc

# Verify signature
gpg --verify REPRODUCIBILITY_EVIDENCE_PACKAGE.md.asc REPRODUCIBILITY_EVIDENCE_PACKAGE.md
```

Expected output:
```
gpg: Good signature from "Ray Iskander (Independent Security Researcher) <ray@quarkos.net>"
```

### 3. Verify Document Integrity

```bash
shasum -a 256 REPRODUCIBILITY_EVIDENCE_PACKAGE.md
```

Compare with hash in the evidence package.

### 4. Reproduce Experiments

```bash
# Using Docker (recommended)
docker build -t shiftleft-reproducible .
docker run --rm shiftleft-reproducible

# Or manually
python scripts/reproduce_paper.py
```

## What This Proves

| Claim | Evidence | Strength |
|-------|----------|----------|
| Document existed at timestamp | Bitcoin blockchain | Irrefutable |
| Author is Ray Iskander | GPG signature | Cryptographic |
| Experiments were executed | GitHub Actions logs | Third-party attestation |
| Environment was exact | Docker image hash | Deterministic |
| Results are accurate | Z3 machine proofs | Mathematically proven |

## Legal Use

This evidence package is designed for:
- Academic priority disputes
- Patent prior art claims
- Peer review verification
- Legal proceedings requiring proof of work

All cryptographic proofs are independently verifiable without trusting any single party.
