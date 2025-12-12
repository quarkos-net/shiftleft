# Paper Reproduction Guide

**Paper:** "Pre-Silicon Side-Channel Verification of Post-Quantum Hardware: A Shift-Left Approach"
**Author:** Ray Iskander
**Date:** December 2025

This document provides complete instructions for reproducing all experiments and claims from the paper.

## Prerequisites

### Software Requirements

- Python 3.8 or later
- Z3 SMT solver (installed via `pip install z3-solver`)
- Git

### Hardware

- Any modern computer (no special hardware required)
- Recommended: 8GB+ RAM for larger analyses

## Setup

### 1. Clone This Repository

```bash
git clone https://github.com/quarkos-net/shiftleft.git
cd shiftleft
```

### 2. Install Dependencies

```bash
pip install -e .
```

### 3. Clone Target Designs (Optional)

For full reproduction, clone the analyzed hardware designs:

```bash
# Adams Bridge ML-DSA Accelerator
git clone https://github.com/chipsalliance/adams-bridge external/adams-bridge

# OpenTitan (for validation baseline)
git clone https://github.com/lowrisc/opentitan external/opentitan
```

## Experiment Reproduction

### Quick Verification (No External Dependencies)

Run the mathematical verification experiments that require no external RTL:

```bash
python3 scripts/reproduce_paper.py
```

This validates:
- Carry probability formula: P(carry=1|s) = (2^W - s) / 2^W
- Information leakage calculation (~0.81 bits per carry)
- Spread calculation (37% across ML-DSA secret range)

### Adams Bridge Analysis

Analyze the Adams Bridge ML-DSA accelerator for vulnerabilities:

```bash
# Ensure Adams Bridge is cloned first
python3 scripts/analyze_adams_bridge.py --target external/adams-bridge
```

**Expected Findings:**
- DOM Pipeline=0 default (INFO) - secure if overridden
- Unmasked intermediate at Line 69 (HIGH) - `res = (res0 + res1) % Q`
- 5-6 carry leakage locations (MEDIUM)

### OpenTitan Validation (Zero False Positives)

Validate our methodology produces zero false positives on Coco-Alma verified designs:

```bash
# Ensure OpenTitan is cloned first
python3 scripts/analyze_opentitan.py --target external/opentitan
```

**Expected Result:** Zero vulnerabilities detected

### Individual Demonstrations

Run individual demos to understand specific concepts:

```bash
# Carry bit leakage (Monte Carlo + mathematical proof)
python3 examples/carry_leakage_demo.py

# DOM Pipeline vulnerability demonstration
python3 examples/dom_pipeline_test.py

# Unmasked intermediate detection
python3 examples/unmasked_intermediate.py
```

## Paper Claims Verification

| Claim | Section | Verification Command | Expected Result |
|-------|---------|---------------------|-----------------|
| Carry probability formula | Section 3.2 | `reproduce_paper.py` | Formula verified |
| 0.81 bits/observation | Section 3.2 | `reproduce_paper.py` | H(carry) = 0.81 |
| 37% spread | Section 3.3 | `reproduce_paper.py` | Spread = 37.43% |
| Adams Bridge vulnerabilities | Section 5.1 | `analyze_adams_bridge.py` | 6+ findings |
| OpenTitan zero FP | Section 5.2 | `analyze_opentitan.py` | 0 vulnerabilities |

## Output Formats

All analysis scripts support JSON output for automated processing:

```bash
# JSON output
python3 scripts/analyze_adams_bridge.py --json > results.json

# Human-readable (default)
python3 scripts/analyze_adams_bridge.py
```

## Test Suite

Run the full test suite to verify the framework:

```bash
# Full suite (1729 tests)
python3 -m pytest tests/ -v

# Just formal verification tests
python3 -m pytest tests/qdebug/unit/ -v

# With coverage
python3 -m pytest tests/ --cov=src/qrisc_validator --cov-report=term-missing
```

## Troubleshooting

### "Module not found" errors

Ensure you're running from the repository root and have installed dependencies:

```bash
cd qrisc-validator
pip install -e .
```

### "Target not found" errors

Clone the external repositories as described in Setup step 3.

### Z3 timeout

Some complex proofs may take longer. Increase the timeout:

```python
# In your analysis script
solver.set("timeout", 60000)  # 60 seconds
```

## File Structure

```
qrisc-validator/
├── scripts/
│   ├── reproduce_paper.py      # Full paper reproduction
│   ├── analyze_adams_bridge.py # Adams Bridge analysis
│   └── analyze_opentitan.py    # OpenTitan validation
│
├── examples/
│   ├── carry_leakage_demo.py   # Carry bit leakage demo
│   ├── dom_pipeline_test.py    # DOM Pipeline demo
│   └── unmasked_intermediate.py # Detection demo
│
├── src/qrisc_validator/qdebug/formal/
│   ├── glitch_verifier.py      # Core verification
│   ├── arithmetic_analyzer.py  # Arithmetic masking analysis
│   └── ...
│
└── tests/
    └── qdebug/unit/            # 1729 unit tests
```

## Citation

If you use this work, please cite:

```bibtex
@article{iskander2025presilicon,
  title={Pre-Silicon Side-Channel Verification of Post-Quantum Hardware: A Shift-Left Approach},
  author={Iskander, Ray},
  year={2025}
}
```

## Contact

For questions about reproduction, please open an issue on GitHub.
