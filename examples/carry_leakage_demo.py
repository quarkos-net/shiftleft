#!/usr/bin/env python3
"""
Carry Bit Leakage Demonstration

This demo illustrates the mathematical basis for carry bit leakage in
arithmetic masking, as described in the paper.

Key Formula:
    P(carry = 1 | secret = s) = (2^W - s) / 2^W

This means the probability of a carry depends on the SECRET VALUE,
leaking approximately 0.81 bits of information per observation.

Reference:
    "Pre-Silicon Side-Channel Verification of Post-Quantum Hardware"
    Ray Iskander, December 2025
"""

import random
import math


def demonstrate_carry_leakage():
    """Demonstrate carry bit leakage in arithmetic masking."""
    
    print("=" * 60)
    print("CARRY BIT LEAKAGE DEMONSTRATION")
    print("=" * 60)
    print()
    
    # Parameters (ML-DSA typical)
    WIDTH = 24
    MAX_VAL = 2 ** WIDTH
    Q = 8380417  # ML-DSA modulus
    SAMPLES = 100000
    
    print(f"Parameters:")
    print(f"  Bit width W = {WIDTH}")
    print(f"  Max value 2^W = {MAX_VAL:,}")
    print(f"  ML-DSA Q = {Q:,}")
    print(f"  Samples per test = {SAMPLES:,}")
    print()
    
    # Test different secret values
    test_secrets = [
        0,
        Q // 4,
        Q // 2,
        3 * Q // 4,
        Q - 1,
    ]
    
    print("=" * 60)
    print("MATHEMATICAL VERIFICATION")
    print("=" * 60)
    print()
    print(f"{'Secret':>12} | {'Theoretical':>12} | {'Empirical':>12} | {'Match':>8}")
    print("-" * 60)
    
    for secret in test_secrets:
        # Theoretical probability
        p_theory = (MAX_VAL - secret) / MAX_VAL
        
        # Monte Carlo simulation
        carries = 0
        for _ in range(SAMPLES):
            # Random mask
            r = random.randint(0, MAX_VAL - 1)
            
            # Compute share0 = (secret - r) mod 2^W
            share0 = (secret - r) % MAX_VAL
            share1 = r
            
            # Check if adding shares causes carry
            if share0 + share1 >= MAX_VAL:
                carries += 1
        
        p_empirical = carries / SAMPLES
        
        # Check match (within 1%)
        match = "✓" if abs(p_theory - p_empirical) < 0.01 else "✗"
        
        print(f"{secret:>12,} | {p_theory:>12.6f} | {p_empirical:>12.6f} | {match:>8}")
    
    print()
    
    # Calculate information leakage
    print("=" * 60)
    print("INFORMATION LEAKAGE ANALYSIS")
    print("=" * 60)
    print()
    
    # For secrets uniform in [0, Q)
    avg_p = (MAX_VAL - Q/2) / MAX_VAL
    
    # Shannon entropy
    h_carry = -avg_p * math.log2(avg_p) - (1 - avg_p) * math.log2(1 - avg_p)
    
    print(f"Average P(carry) for secrets in [0, Q): {avg_p:.4f}")
    print(f"Shannon entropy H(carry): {h_carry:.4f} bits")
    print()
    print(f"=> Each carry observation leaks ~{h_carry:.2f} bits about the secret")
    print()
    
    # Calculate spread
    p_at_0 = MAX_VAL / MAX_VAL  # = 1.0
    p_at_q = (MAX_VAL - Q) / MAX_VAL
    spread = (p_at_0 - p_at_q) * 100
    
    print(f"Carry rate at secret=0: {p_at_0:.4f} (100%)")
    print(f"Carry rate at secret=Q-1: {p_at_q:.4f} ({p_at_q*100:.1f}%)")
    print(f"Spread: {spread:.2f} percentage points")
    print()
    
    # Security implications
    print("=" * 60)
    print("SECURITY IMPLICATIONS")
    print("=" * 60)
    print()
    print("1. Single carry observation: Reveals range of secret (37% spread)")
    print("2. Multiple observations: Statistical attack improves with sqrt(N)")
    print("3. 1000 traces: Estimate secret within ~3% of Q")
    print("4. 10000 traces: Estimate secret within ~1% of Q")
    print()
    print("COUNTERMEASURES:")
    print("  - Secure A2B conversion (Goubin CHES 2001)")
    print("  - Carry-lookahead with fresh randomness")
    print("  - Avoid exposing carry bits to external observation")
    print()


def estimate_attack_complexity():
    """Estimate how many traces needed for different precision."""
    
    print("=" * 60)
    print("ATTACK COMPLEXITY ESTIMATION")
    print("=" * 60)
    print()
    
    WIDTH = 24
    MAX_VAL = 2 ** WIDTH
    Q = 8380417
    
    # For a given number of observations, estimate precision
    trace_counts = [10, 100, 1000, 10000, 100000]
    
    print(f"{'Traces':>10} | {'Std Error':>12} | {'Secret Precision':>18}")
    print("-" * 50)
    
    for n in trace_counts:
        # Standard error of proportion estimate
        p = 0.75  # average carry probability
        std_err = math.sqrt(p * (1 - p) / n)
        
        # This translates to secret uncertainty
        # P(carry) = (2^W - s) / 2^W
        # s = 2^W * (1 - P(carry))
        # delta_s = 2^W * delta_P = 2^W * std_err
        secret_uncertainty = MAX_VAL * std_err
        precision_pct = (secret_uncertainty / Q) * 100
        
        print(f"{n:>10,} | {std_err:>12.6f} | ±{precision_pct:>6.1f}% of Q")
    
    print()


if __name__ == '__main__':
    demonstrate_carry_leakage()
    estimate_attack_complexity()
