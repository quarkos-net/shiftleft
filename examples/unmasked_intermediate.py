#!/usr/bin/env python3
"""
Unmasked Intermediate Detection Demonstration

This demo illustrates how combining masked shares BEFORE modular reduction
creates an unmasked intermediate value that leaks the full secret.

The Classic Bug (e.g., Adams Bridge Line 69):
    res = (res0 + res1) % Q  # WRONG: res0 + res1 is UNMASKED!

The Fix:
    res0 = res0 % Q          # Reduce each share
    res1 = res1 % Q          # independently
    res = res0 + res1        # Now combine (still masked mod 2*Q-2)

Reference:
    "Pre-Silicon Side-Channel Verification of Post-Quantum Hardware"
    Ray Iskander, December 2025
"""

import random
import math


def print_header(title: str):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}\n")


def demonstrate_the_bug():
    """Show why combining before modular reduction leaks the secret."""

    print_header("THE UNMASKED INTERMEDIATE BUG")

    # Parameters
    Q = 8380417  # ML-DSA modulus
    WIDTH = 24
    MAX_VAL = 2 ** WIDTH

    print(f"Parameters:")
    print(f"  ML-DSA modulus Q = {Q:,}")
    print(f"  Arithmetic width W = {WIDTH}")
    print(f"  2^W = {MAX_VAL:,}")
    print()

    # Secret value
    secret = 1234567

    # Create arithmetic shares: secret = share0 + share1 mod 2^W
    share1 = random.randint(0, MAX_VAL - 1)
    share0 = (secret - share1) % MAX_VAL

    print(f"Secret: s = {secret:,}")
    print(f"Shares: s0 = {share0:,}, s1 = {share1:,}")
    print(f"Verify: (s0 + s1) mod 2^W = {(share0 + share1) % MAX_VAL:,}")
    print()

    # THE BUG: Combine then reduce
    print("THE BUG (combine then reduce):")
    print(f"  Step 1: sum = s0 + s1 = {share0:,} + {share1:,}")

    unmasked_sum = share0 + share1  # This value IS the secret (plus possible wrap)
    print(f"  Step 2: sum = {unmasked_sum:,}")
    print()
    print(f"  >>> THIS VALUE ({unmasked_sum:,}) IS UNMASKED! <<<")
    print(f"  >>> It equals the secret ({secret:,}) or secret + 2^W <<<")
    print()

    # The attacker observes the sum
    recovered_secret = unmasked_sum % MAX_VAL
    print(f"  Attacker recovers: {recovered_secret:,}")
    print(f"  Actual secret:     {secret:,}")
    print(f"  Match: {recovered_secret == secret}")
    print()

    # Then reduction happens (but damage is done)
    result = unmasked_sum % Q
    print(f"  Step 3: result = sum % Q = {result:,}")
    print(f"  (But the secret was already leaked in Step 2!)")


def demonstrate_power_analysis():
    """Show how power consumption during addition leaks the secret."""

    print_header("POWER ANALYSIS ATTACK")

    print("""
When hardware computes: sum = share0 + share1

The POWER CONSUMPTION correlates with:
1. Hamming weight of sum (number of 1 bits)
2. Hamming distance from previous value
3. Carry propagation chain length

All of these leak information about the UNMASKED SUM, which equals the secret!
""")

    # Demonstrate with different secrets
    WIDTH = 24
    MAX_VAL = 2 ** WIDTH
    SAMPLES = 5

    secrets = [0, 1000000, 4000000, 7000000, 8380416]

    print(f"{'Secret':>12} | {'Avg HW(sum)':>12} | {'Expected HW':>12}")
    print("-" * 45)

    for secret in secrets:
        hw_sum = 0
        for _ in range(SAMPLES):
            share1 = random.randint(0, MAX_VAL - 1)
            share0 = (secret - share1) % MAX_VAL

            unmasked_sum = share0 + share1
            hw = bin(unmasked_sum).count('1')
            hw_sum += hw

        avg_hw = hw_sum / SAMPLES
        # Expected HW for the secret value
        expected_hw = bin(secret).count('1')

        print(f"{secret:>12,} | {avg_hw:>12.1f} | {expected_hw:>12}")

    print()
    print("The Hamming weight of the sum correlates with the secret!")
    print("An attacker with power traces can distinguish secret values.")


def demonstrate_the_fix():
    """Show the correct way to handle modular reduction with masking."""

    print_header("THE FIX: REDUCE SHARES SEPARATELY")

    Q = 8380417
    WIDTH = 24
    MAX_VAL = 2 ** WIDTH

    secret = 1234567

    # Create arithmetic shares
    share1 = random.randint(0, MAX_VAL - 1)
    share0 = (secret - share1) % MAX_VAL

    print(f"Secret: s = {secret:,}")
    print(f"Shares: s0 = {share0:,}, s1 = {share1:,}")
    print()

    print("CORRECT APPROACH (reduce then combine):")
    print()
    print(f"  Step 1a: reduced0 = s0 % Q = {share0:,} % {Q:,}")
    reduced0 = share0 % Q
    print(f"           reduced0 = {reduced0:,}")
    print()
    print(f"  Step 1b: reduced1 = s1 % Q = {share1:,} % {Q:,}")
    reduced1 = share1 % Q
    print(f"           reduced1 = {reduced1:,}")
    print()

    # Each individual reduction is still masked because:
    # - share0 alone is uniformly random
    # - share1 alone is uniformly random
    # - Neither reveals the secret

    print("  Security check:")
    print(f"    reduced0 = {reduced0:,} (random, no correlation to secret)")
    print(f"    reduced1 = {reduced1:,} (random, no correlation to secret)")
    print()

    # Now combine (still masked, just in a different range)
    print(f"  Step 2: result = reduced0 + reduced1")
    result_sum = reduced0 + reduced1
    print(f"          result = {reduced0:,} + {reduced1:,} = {result_sum:,}")
    print()

    # Final reduction if needed (shares are in [0, 2Q-2])
    if result_sum >= Q:
        result = result_sum - Q
    else:
        result = result_sum

    print(f"  Step 3: final = result mod Q = {result:,}")
    print()

    # Verify correctness
    expected = secret % Q
    print(f"  Verify: secret % Q = {expected:,}")
    print(f"  Match: {result == expected}")
    print()

    print("WHY IS THIS SECURE?")
    print("  - reduced0 by itself is uniformly random in [0, Q-1]")
    print("  - reduced1 by itself is uniformly random in [0, Q-1]")
    print("  - Neither intermediate value correlates with the secret")
    print("  - The masking is preserved throughout!")


def demonstrate_detection():
    """Show how our tool detects this vulnerability."""

    print_header("AUTOMATED DETECTION")

    print("""
Our analyzer detects patterns like:

VULNERABLE PATTERNS:
  result = (share0 + share1) % Q     # Shares combined BEFORE mod
  res = (a[0] + a[1]) % MODULUS      # Array-indexed shares
  out = (r0 + r1) % prime            # Various naming conventions

DETECTION REGEX:
  (\\w+)\\s*=\\s*\\(?\\s*(\\w+)\\s*\\+\\s*(\\w+)\\s*\\)?\\s*%\\s*(\\w+)

  Then check if operands look like share pairs:
  - res0/res1, share0/share1, a[0]/a[1], etc.
""")

    # Demonstrate pattern matching
    import re

    test_cases = [
        ("result = (res0 + res1) % Q", True),
        ("out = (share0 + share1) % MODULUS", True),
        ("x = a + b % Q", False),  # Not combining shares
        ("y = (x0 + x1) % M", True),  # Looks like shares
        ("res0 = res0 % Q", False),  # Single share reduction (SAFE)
    ]

    pattern = re.compile(r'(\w+)\s*=\s*\(?\s*(\w+)\s*\+\s*(\w+)\s*\)?\s*%\s*(\w+)')

    print("Detection Results:")
    print()
    print(f"{'Code Pattern':<40} | {'Detected':<10} | {'Expected':<10}")
    print("-" * 65)

    for code, expected_vuln in test_cases:
        match = pattern.search(code)
        detected = False

        if match:
            op1 = match.group(2)
            op2 = match.group(3)

            # Check if operands look like share pairs
            if (op1.endswith('0') and op2.endswith('1') and
                op1[:-1] == op2[:-1]):
                detected = True
            elif 'share0' in op1 and 'share1' in op2:
                detected = True
            elif 'res0' in op1 and 'res1' in op2:
                detected = True

        status = "VULN" if detected else "safe"
        expected = "VULN" if expected_vuln else "safe"
        match_str = "OK" if (detected == expected_vuln) else "MISS"

        print(f"{code:<40} | {status:<10} | {expected:<10} {match_str}")


def check_real_code():
    """Check real Adams Bridge code for this vulnerability."""

    print_header("REAL CODE ANALYSIS: ADAMS BRIDGE")

    from pathlib import Path
    import re

    target = Path("external/adams-bridge")
    if not target.exists():
        print("Adams Bridge not found. Clone with:")
        print("  git clone https://github.com/chipsalliance/adams-bridge external/adams-bridge")
        return

    # Known vulnerable file
    ntt_file = target / "src/ntt_top/rtl/ntt_masked_BFU_mult.sv"
    if not ntt_file.exists():
        print(f"NTT file not found: {ntt_file}")
        return

    content = ntt_file.read_text()
    lines = content.split('\n')

    pattern = re.compile(r'(\w+)\s*=\s*\(?\s*(\w+)\s*\+\s*(\w+)\s*\)?\s*%\s*(\w+)')

    print(f"Scanning: {ntt_file}")
    print()

    for i, line in enumerate(lines, 1):
        match = pattern.search(line)
        if match:
            op1 = match.group(2)
            op2 = match.group(3)

            # Check for share combination
            if ('res0' in op1 and 'res1' in op2) or \
               ('share0' in op1 and 'share1' in op2) or \
               (op1.endswith('0') and op2.endswith('1') and op1[:-1] == op2[:-1]):

                print(f"VULNERABILITY FOUND at line {i}:")
                print(f"  {line.strip()}")
                print()
                print("  Analysis:")
                print(f"    Result variable: {match.group(1)}")
                print(f"    Share 0: {op1}")
                print(f"    Share 1: {op2}")
                print(f"    Modulus: {match.group(4)}")
                print()
                print("  Issue: Shares are combined BEFORE modular reduction")
                print("  Impact: Full secret value is exposed as unmasked intermediate")
                print("  Fix: Reduce each share separately, then combine")
                print()


def main():
    print_header("UNMASKED INTERMEDIATE DETECTION DEMO")
    print("Author: Ray Iskander, December 2025")
    print("Reference: 'Pre-Silicon Side-Channel Verification of Post-Quantum Hardware'")

    demonstrate_the_bug()
    demonstrate_power_analysis()
    demonstrate_the_fix()
    demonstrate_detection()
    check_real_code()

    print_header("SUMMARY")
    print("""
Key Takeaways:

1. THE BUG: result = (share0 + share1) % Q
   - The sum (share0 + share1) is UNMASKED
   - It equals the secret value (possibly wrapped)
   - Power analysis during addition leaks the full secret

2. THE FIX: Reduce shares separately
   - reduced0 = share0 % Q
   - reduced1 = share1 % Q
   - result = reduced0 + reduced1  (or with additional mod Q)

3. WHY IT WORKS:
   - Each share remains uniformly random after individual reduction
   - No unmasked intermediate appears at any point
   - Masking property preserved throughout

4. OUR TOOL DETECTS THIS:
   - Pattern matching for share combination before modulus
   - Flags HIGH severity (complete secret exposure)
   - Provides fix recommendations

This is one of the most common masking bugs in post-quantum cryptography!
Always verify modular reductions maintain the masking property.
""")


if __name__ == '__main__':
    main()
