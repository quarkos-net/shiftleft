#!/usr/bin/env python3
"""
DOM Pipeline Configuration Demonstration

This demo illustrates why the DOM AND gate's Pipeline parameter
is critical for glitch resistance, as described in the paper.

DOM (Domain-Oriented Masking) AND Gate:
- Pipeline=0: Combinational - vulnerable to glitch attacks
- Pipeline=1: Pipelined with register - glitch resistant

Reference:
    "Pre-Silicon Side-Channel Verification of Post-Quantum Hardware"
    Ray Iskander, December 2025

    Also see: Gross et al., "Domain-Oriented Masking" (CHES 2016)
"""


def print_header(title: str):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}\n")


def demonstrate_dom_and_gate():
    """Demonstrate DOM AND gate operation and glitch vulnerability."""

    print_header("DOM AND GATE SECURITY ANALYSIS")

    print("""
DOM AND Gate computes: q = (a ∧ b) where a, b are 2-share masked

  Input shares: a = (a0, a1), b = (b0, b1)
  Where: a0 ⊕ a1 = actual_a, b0 ⊕ b1 = actual_b

The masked AND computation:

  z = fresh randomness

  inner0 = (a0 & b0) ^ z
  inner1 = (a0 & b1) ^ (a1 & b0) ^ (a1 & b1) ^ z

  q0 = inner0
  q1 = inner1

Result: q0 ⊕ q1 = (a0 ⊕ a1) ∧ (b0 ⊕ b1) = actual_a ∧ actual_b
""")

    # Demonstrate with concrete values
    print_header("CONCRETE EXAMPLE")

    # Secret values
    actual_a = 1
    actual_b = 1

    # Random shares
    import random
    random.seed(42)  # For reproducibility

    a1 = random.randint(0, 1)
    b1 = random.randint(0, 1)
    a0 = actual_a ^ a1
    b0 = actual_b ^ b1
    z = random.randint(0, 1)  # Fresh randomness

    print(f"Secret values: a = {actual_a}, b = {actual_b}")
    print(f"Expected result: a ∧ b = {actual_a & actual_b}")
    print()
    print(f"Shares: a = ({a0}, {a1}), b = ({b0}, {b1})")
    print(f"Fresh randomness: z = {z}")
    print()

    # Compute DOM AND
    inner0 = (a0 & b0) ^ z
    cross_term = (a0 & b1) ^ (a1 & b0)
    inner1 = cross_term ^ (a1 & b1) ^ z

    q0 = inner0
    q1 = inner1

    print(f"Computation:")
    print(f"  inner0 = (a0 & b0) ^ z = ({a0} & {b0}) ^ {z} = {inner0}")
    print(f"  cross  = (a0 & b1) ^ (a1 & b0) = ({a0} & {b1}) ^ ({a1} & {b0}) = {cross_term}")
    print(f"  inner1 = cross ^ (a1 & b1) ^ z = {cross_term} ^ ({a1} & {b1}) ^ {z} = {inner1}")
    print()
    print(f"Output: q = ({q0}, {q1})")
    print(f"Unmasked: q0 ^ q1 = {q0} ^ {q1} = {q0 ^ q1}")
    print(f"Correct: {q0 ^ q1 == (actual_a & actual_b)}")


def demonstrate_glitch_vulnerability():
    """Demonstrate why Pipeline=0 is vulnerable to glitches."""

    print_header("GLITCH VULNERABILITY ANALYSIS")

    print("""
THE GLITCH PROBLEM (Pipeline=0):

In combinational logic, signal transitions create temporary "glitch" states
where intermediate values momentarily appear on wires.

Timeline of DOM AND computation (combinational):

  t=0:  Input shares arrive
  t=1:  inner0 = (a0 & b0) ^ z computed
  t=2:  cross_term = (a0 & b1) ^ (a1 & b0) TRANSITIONING...
  t=3:  inner1 being computed, but cross_term not yet stable
  t=4:  Final values stable

During t=2 to t=3, the cross_term may have GLITCH STATES where:
  - (a0 & b1) has arrived
  - (a1 & b0) has NOT yet arrived

This momentarily exposes: a0 & b1 (unmasked!)

If an attacker can observe power during this glitch, they see
partial products that leak information about the secret shares.
""")

    # Simulation of glitch states
    print("Simulated Glitch States in cross_term computation:")
    print()

    import random
    random.seed(42)

    a0, a1 = 1, 0  # actual_a = 1
    b0, b1 = 1, 0  # actual_b = 1

    print(f"Shares: a=({a0},{a1}), b=({b0},{b1})")
    print()

    # Different arrival orders create different glitch states
    arrival_orders = [
        ("(a0&b1) first", lambda: (a0 & b1)),
        ("(a1&b0) first", lambda: (a1 & b0)),
        ("Both together", lambda: (a0 & b1) ^ (a1 & b0)),
    ]

    print(f"{'Arrival Order':<20} | {'Glitch Value':<15} | {'Security':<15}")
    print("-" * 55)

    for name, func in arrival_orders:
        glitch_val = func()
        final_val = (a0 & b1) ^ (a1 & b0)
        security = "LEAKED!" if glitch_val != final_val else "OK"
        print(f"{name:<20} | {glitch_val:<15} | {security:<15}")

    print()
    print("The glitch values (a0&b1) and (a1&b0) are NOT masked!")
    print("They partially reveal the relationship between input shares.")


def demonstrate_pipeline_solution():
    """Demonstrate how Pipeline=1 fixes the glitch vulnerability."""

    print_header("PIPELINE SOLUTION (Pipeline=1)")

    print("""
THE FIX: Pipeline Register

With Pipeline=1, a register is inserted that:
1. Captures the cross_term AFTER it stabilizes
2. Prevents glitch states from propagating to inner1
3. Re-randomizes timing to hide glitch patterns

Timeline with Pipeline=1:

  Cycle 1:
    t=0-4: inner0, cross_term computed (glitches happen but contained)
    t=5:   Register captures STABLE cross_term

  Cycle 2:
    t=6:   Stable cross_term released from register
    t=7:   inner1 = stable_cross ^ (a1 & b1) ^ z computed cleanly

The register acts as a "glitch firewall":
- Glitches cannot propagate through the register
- Only the final, stable value is used in subsequent computation
- Attacker observing Cycle 2 sees no glitch information

SECURITY PROPERTY:
  With Pipeline=1, the DOM AND gate is secure under the
  "glitch-extended probing model" (GEPRO).
""")

    # Summary table
    print("Configuration Comparison:")
    print()
    print(f"{'Parameter':<15} | {'Latency':<10} | {'Glitch Secure':<15} | {'Area':<10}")
    print("-" * 60)
    print(f"{'Pipeline=0':<15} | {'1 cycle':<10} | {'NO':<15} | {'Smaller':<10}")
    print(f"{'Pipeline=1':<15} | {'2 cycles':<10} | {'YES':<15} | {'Larger':<10}")
    print()
    print("Recommendation: ALWAYS use Pipeline=1 for production designs")


def check_real_design():
    """Check a real design for Pipeline configuration."""

    print_header("REAL DESIGN ANALYSIS")

    from pathlib import Path
    import re

    # Look for Adams Bridge
    target = Path("external/adams-bridge")
    if not target.exists():
        print("Adams Bridge not found at external/adams-bridge")
        print("Clone it with: git clone https://github.com/chipsalliance/adams-bridge external/adams-bridge")
        return

    dom_file = target / "src/abr_prim/rtl/abr_prim_dom_and_2share.sv"
    if not dom_file.exists():
        print(f"DOM module not found: {dom_file}")
        return

    content = dom_file.read_text()

    # Find Pipeline parameter
    param_match = re.search(r'parameter\s+bit\s+Pipeline\s*=\s*1\'b([01])', content)

    if param_match:
        default = param_match.group(1)
        print(f"Adams Bridge DOM AND gate default: Pipeline={default}")
        print()

        if default == '0':
            print("DEFAULT IS INSECURE!")
            print("Security depends on each instantiation overriding to Pipeline=1")
            print()

            # Check instantiations
            keccak_file = target / "src/abr_sha3/rtl/abr_keccak_2share.sv"
            if keccak_file.exists():
                keccak_content = keccak_file.read_text()
                instances = re.findall(r'\.Pipeline\s*\(\s*(\d+)\s*\)', keccak_content)

                if instances:
                    print(f"Keccak instantiations: {instances}")
                    all_secure = all(i == '1' for i in instances)
                    if all_secure:
                        print("All Keccak instances use Pipeline=1 (SECURE)")
                    else:
                        print("WARNING: Some instances may use Pipeline=0!")
        else:
            print("DEFAULT IS SECURE (Pipeline=1)")


def main():
    print_header("DOM PIPELINE SECURITY DEMONSTRATION")
    print("Author: Ray Iskander, December 2025")
    print("Reference: 'Pre-Silicon Side-Channel Verification of Post-Quantum Hardware'")

    demonstrate_dom_and_gate()
    demonstrate_glitch_vulnerability()
    demonstrate_pipeline_solution()
    check_real_design()

    print_header("SUMMARY")
    print("""
Key Takeaways:

1. DOM (Domain-Oriented Masking) provides provable SCA security
   - BUT only against the standard probing model

2. Glitches break the security guarantee
   - Combinational logic has transient states
   - These states can leak unmasked partial products

3. Pipeline=1 is REQUIRED for glitch security
   - Adds one cycle of latency
   - Adds register area
   - But provides provable glitch resistance

4. Our tool detects Pipeline=0 configurations
   - Flags HIGH severity for instantiations with Pipeline=0
   - Flags INFO for defaults (must verify overrides)

Always verify Pipeline configuration in security-critical designs!
""")


if __name__ == '__main__':
    main()
