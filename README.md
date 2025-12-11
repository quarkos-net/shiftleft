# Shiftleft

**Pre-silicon side-channel verification for post-quantum cryptographic hardware.**

Detect power analysis vulnerabilities *before* tape-out—in seconds, with no hardware required.

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

On the Adams Bridge ML-DSA accelerator, Shiftleft detects the same vulnerability at `ntt_masked_BFU_mult.sv` line 69 that Karabulut and Azarderakhsh discovered through correlation power analysis (ePrint 2025/009):

| Metric | Post-Silicon | Shiftleft |
|--------|--------------|-----------|
| Detection | Line 69 | Line 69 |
| Traces required | 10,000 | 0 |
| Time | Weeks | **0.21 seconds** |
| Hardware | FPGA + scope | None |

## Features

- **L1 Verifier**: Control-flow (timing) verification—detects secret-dependent branches
- **L2 Verifier**: Hamming weight (power) verification—detects unmasked intermediates
- **Complementary models**: Neither subsumes the other; both needed for comprehensive coverage

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

## Quick Start

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

## Example: Adams Bridge Vulnerability

The Adams Bridge ML-DSA accelerator contains a first-order side-channel vulnerability:

```verilog
// ntt_masked_BFU_mult.sv:69
// Arithmetic masking: shares are mul_res0, mul_res1
mul_res_combined = (mul_res0 + mul_res1) % MLDSA_Q;  // UNMASKED!
mul_res_combined_share0 = mul_res_combined - rnd0;   // Re-masked too late
```

The unmasked value `mul_res_combined` exists for one clock cycle—enough for power analysis to correlate its Hamming weight with secret operands.

Shiftleft detects this in 0.21 seconds.

## Paper

This work is described in:

> Ray Iskander, "Shift-Left Side-Channel Verification for ML-DSA Hardware,"
> arXiv [cs.CR], December 2025.

The methodology validates against findings by Karabulut and Azarderakhsh:

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
