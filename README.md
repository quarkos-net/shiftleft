# Shiftleft

> **Pre-Silicon Side-Channel Verification for Post-Quantum Cryptographic Hardware**

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-Apache--2.0-green.svg)](LICENSE)

Detect power analysis vulnerabilities **before** tape-out—in seconds, with no hardware required.

## Paper

**"Pre-Silicon Side-Channel Verification of Post-Quantum Hardware: A Shift-Left Approach"**

*Ray Iskander, December 2025*

### Abstract

Post-quantum cryptographic hardware faces a critical vulnerability gap: masked implementations designed to resist power analysis attacks often contain subtle flaws that evade traditional verification. We present Shiftleft, a formal verification framework that detects side-channel vulnerabilities in PQC hardware **before silicon fabrication**.

Our key contributions:

1. **Carry Bit Leakage Detection** - We prove that arithmetic masking in modular operations leaks information through carry propagation. Each carry observation reveals ~0.81 bits about the secret, with a 50% spread across the ML-DSA coefficient range.

2. **Unmasked Intermediate Detection** - We identify a critical pattern where shares are combined before modular reduction (e.g., `res = (share0 + share1) % Q`), exposing the full secret value.

3. **DOM Pipeline Verification** - We verify that Domain-Oriented Masking implementations use Pipeline=1 for glitch resistance, detecting configurations vulnerable to transient leakage.

Applied to the Adams Bridge ML-DSA accelerator, Shiftleft detected **7 vulnerabilities** including 1 HIGH severity unmasked intermediate and 5 carry leakage locations—all confirmed as genuine security issues.

## The Problem

Side-channel vulnerabilities in PQC hardware are traditionally detected through post-silicon power analysis:
- Requires physical chips ($2-10M tape-out cost)
- Expensive equipment (~$50K+ for oscilloscopes, probes)
- Weeks of trace collection (10,000+ measurements)
- Discovered vulnerabilities require costly respins

## The Solution

Shiftleft uses SMT-based formal verification to detect the same vulnerabilities **pre-silicon**:
- Operates on RTL (Verilog/SystemVerilog)
- Sub-second verification times
- No hardware required
- Fix vulnerabilities before they cost millions

## Validated Results

| Metric | Post-Silicon (CPA) | Shiftleft |
|--------|-------------------|-----------|
| Detection | Line 69 | Line 69 |
| Traces required | 10,000 | **0** |
| Time | Weeks | **0.21 seconds** |
| Hardware | FPGA + scope | **None** |

## Quick Start: Reproduce Paper Results

```bash
# Clone and install
git clone https://github.com/quarkos-net/shiftleft
cd shiftleft
pip install -e .

# Clone target design
git clone https://github.com/chipsalliance/adams-bridge external/adams-bridge

# Run ALL paper experiments
python3 scripts/reproduce_paper.py
```

**Expected Output:**
```
✓ Carry Probability Formula - PASS
✓ Information Leakage (~0.81 bits) - PASS
✓ Spread Calculation (~50%) - PASS
✓ DOM Pipeline Detection - PASS
✓ Adams Bridge Full Analysis - PASS
```

## Key Findings: Adams Bridge

| Finding | Severity | Location | Description |
|---------|----------|----------|-------------|
| Unmasked Intermediate | HIGH | `ntt_masked_BFU_mult.sv:69` | `(res0 + res1) % Q` exposes secret |
| Carry Leakage | MEDIUM | `masked_barrett_reduction.sv:66` | Carry bit extraction |
| Carry Leakage | MEDIUM | `masked_barrett_reduction.sv:82` | Share combination overflow |
| Carry Leakage | MEDIUM | `masked_barrett_reduction.sv:87` | Carry propagation |
| Carry Leakage | MEDIUM | `masked_barrett_reduction.sv:122` | Bit extraction |
| Carry Leakage | MEDIUM | `masked_barrett_reduction.sv:133` | Bit extraction |
| DOM Default | INFO | `abr_prim_dom_and_2share.sv:30` | Pipeline=0 default |

## Individual Demonstrations

```bash
# Carry bit leakage (Monte Carlo + mathematical proof)
python3 examples/carry_leakage_demo.py

# DOM Pipeline vulnerability demonstration
python3 examples/dom_pipeline_test.py

# Unmasked intermediate detection
python3 examples/unmasked_intermediate.py
```

## Target Analysis

```bash
# Analyze Adams Bridge ML-DSA accelerator
python3 scripts/analyze_adams_bridge.py --target external/adams-bridge

# JSON output for automation
python3 scripts/analyze_adams_bridge.py --json > results.json
```

## Installation

```bash
pip install shiftleft
```

Or from source:

```bash
git clone https://github.com/quarkos-net/shiftleft
cd shiftleft
pip install -e ".[dev]"
```

### Requirements

- Python 3.9+
- Z3 Solver (automatically installed via `z3-solver`)

## Usage

```python
from shiftleft import HammingWeightVerifier, ModularHintVerifier

# L1: Check for timing leaks (control-flow)
l1 = ModularHintVerifier()
l1_result = l1.verify_module("path/to/module.sv")

# L2: Check for power leaks (Hamming weight)
l2 = HammingWeightVerifier()
l2_result = l2.verify_module("path/to/module.sv")

if l2_result.vulnerable:
    print(f"Vulnerability at: {l2_result.location}")
    print(f"Leaking expression: {l2_result.expression}")
```

## Repository Structure

```
shiftleft/
├── scripts/
│   ├── reproduce_paper.py      # Full paper reproduction
│   ├── analyze_adams_bridge.py # Adams Bridge analysis
│   └── analyze_opentitan.py    # OpenTitan validation
│
├── examples/
│   ├── carry_leakage_demo.py   # Carry probability demo
│   ├── dom_pipeline_test.py    # DOM Pipeline demo
│   └── unmasked_intermediate.py # Detection demo
│
├── src/shiftleft/              # Core library
│
└── docs/
    └── REPRODUCTION.md         # Detailed reproduction guide
```

## Citation

```bibtex
@article{iskander2025shiftleft,
  title={Pre-Silicon Side-Channel Verification of Post-Quantum Hardware:
         A Shift-Left Approach},
  author={Iskander, Ray},
  year={2025}
}
```

This methodology validates against findings by Karabulut and Azarderakhsh:

> Merve Karabulut and Reza Azarderakhsh, "Efficient CPA Attack on Hardware
> Implementation of ML-DSA in Post-Quantum Root of Trust," ePrint 2025/009.

## License

Apache-2.0. See [LICENSE](LICENSE).

## Contributing

Contributions welcome! Please open an issue or pull request.

## Contact

- Ray Iskander ([ray@quarkos.net](mailto:ray@quarkos.net))
- Website: [quarkos.net](https://quarkos.net)
- Organization: [github.com/quarkos-net](https://github.com/quarkos-net)
