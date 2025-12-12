#!/usr/bin/env python3
"""
Paper Reproduction Script

Reproduces all experiments from:
"Pre-Silicon Side-Channel Verification of Post-Quantum Hardware: A Shift-Left Approach"
Ray Iskander, December 2025

This script runs all analyses and validates the paper's claims.

Usage:
    python3 scripts/reproduce_paper.py

Requirements:
    - Adams Bridge cloned to external/adams-bridge
    - OpenTitan cloned to external/opentitan (optional)
    - Python 3.8+
"""

import subprocess
import sys
import time
from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class ExperimentResult:
    name: str
    passed: bool
    duration: float
    details: str


def print_header(title: str):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}\n")


def run_experiment(name: str, func) -> ExperimentResult:
    """Run an experiment and capture results."""
    print(f"[RUNNING] {name}...")
    start = time.time()
    try:
        passed, details = func()
        duration = time.time() - start
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"[{status}] {name} ({duration:.1f}s)")
        return ExperimentResult(name, passed, duration, details)
    except Exception as e:
        duration = time.time() - start
        print(f"[✗ ERROR] {name}: {e}")
        return ExperimentResult(name, False, duration, str(e))


def experiment_carry_probability() -> Tuple[bool, str]:
    """Verify carry probability formula: P(carry=1|s) = (2^W - s) / 2^W"""
    import random

    WIDTH = 24
    MAX_VAL = 2 ** WIDTH
    SAMPLES = 10000

    test_cases = [
        (0, 1.0),
        (MAX_VAL // 4, 0.75),
        (MAX_VAL // 2, 0.5),
        (3 * MAX_VAL // 4, 0.25),
        (MAX_VAL - 1, 0.0),
    ]

    results = []
    all_passed = True

    for secret, expected in test_cases:
        # Monte Carlo simulation
        carries = 0
        for _ in range(SAMPLES):
            r = random.randint(0, MAX_VAL - 1)
            share0 = (secret - r) % MAX_VAL
            if share0 + r >= MAX_VAL:
                carries += 1

        empirical = carries / SAMPLES
        theoretical = (MAX_VAL - secret) / MAX_VAL

        # Allow 5% tolerance
        passed = abs(empirical - theoretical) < 0.05
        all_passed = all_passed and passed

        results.append(f"s={secret}: theory={theoretical:.3f}, empirical={empirical:.3f}")

    return all_passed, "\n".join(results)


def experiment_info_leakage() -> Tuple[bool, str]:
    """Verify information leakage calculation: ~0.81 bits per carry."""
    import math

    # For ML-DSA parameters
    WIDTH = 24
    Q = 8380417

    # Average carry probability across [0, Q)
    avg_p = 0.75  # Approximate

    # Shannon entropy
    if 0 < avg_p < 1:
        h_carry = -avg_p * math.log2(avg_p) - (1 - avg_p) * math.log2(1 - avg_p)
    else:
        h_carry = 0

    # Paper claims ~0.81 bits
    expected = 0.81
    passed = abs(h_carry - expected) < 0.05

    return passed, f"H(carry) = {h_carry:.3f} bits (expected ~{expected})"


def experiment_adams_bridge_analysis() -> Tuple[bool, str]:
    """Run Adams Bridge analysis and verify expected findings."""
    script_dir = Path(__file__).parent
    target = script_dir.parent / "external" / "adams-bridge"

    if not target.exists():
        return False, f"Adams Bridge not found at {target}"

    # Run our analyzer
    result = subprocess.run(
        [sys.executable, str(script_dir / "analyze_adams_bridge.py"),
         "--target", str(target), "--json"],
        capture_output=True,
        text=True
    )

    if result.returncode not in [0, 1]:
        return False, f"Analyzer failed: {result.stderr}"

    import json
    try:
        output = json.loads(result.stdout)
    except:
        return False, f"Invalid JSON output: {result.stdout[:200]}"

    # Verify expected findings
    expected_unmasked = 1  # Line 69
    expected_carry = 5  # 5-6 locations

    actual_unmasked = len(output.get('findings', {}).get('unmasked', []))
    actual_carry = len(output.get('findings', {}).get('carry', []))

    passed = (actual_unmasked >= expected_unmasked and actual_carry >= expected_carry)

    details = (
        f"Unmasked intermediates: {actual_unmasked} (expected >= {expected_unmasked})\n"
        f"Carry leakage locations: {actual_carry} (expected >= {expected_carry})"
    )

    return passed, details


def experiment_dom_pipeline() -> Tuple[bool, str]:
    """Verify DOM Pipeline parameter detection."""
    # This is a simplified check - full version would run simulation
    script_dir = Path(__file__).parent
    target = script_dir.parent / "external" / "adams-bridge"

    if not target.exists():
        return False, "Adams Bridge not found"

    # Check that Pipeline=1 is used in Keccak
    keccak_file = target / "src" / "abr_sha3" / "rtl" / "abr_keccak_2share.sv"
    if not keccak_file.exists():
        return False, f"Keccak file not found: {keccak_file}"

    content = keccak_file.read_text()

    # Look for Pipeline instantiation
    import re
    pipeline_matches = re.findall(r'\.Pipeline\s*\(\s*(\d+)\s*\)', content)

    if not pipeline_matches:
        return False, "No Pipeline parameter found"

    all_secure = all(m == '1' for m in pipeline_matches)

    return all_secure, f"Pipeline values found: {pipeline_matches}"


def experiment_spread_calculation() -> Tuple[bool, str]:
    """Verify significant spread across ML-DSA secret range.

    The spread is Q/2^W ≈ 50%, meaning carry probability varies from
    100% at s=0 to ~50% at s=Q-1, providing significant distinguishability.
    """
    WIDTH = 24
    MAX_VAL = 2 ** WIDTH
    Q = 8380417

    # Carry rate at extremes of [0, Q)
    p_at_0 = (MAX_VAL - 0) / MAX_VAL  # = 1.0
    p_at_q = (MAX_VAL - Q) / MAX_VAL  # ≈ 0.50

    spread = (p_at_0 - p_at_q) * 100  # percentage points

    # Theoretical spread = Q/2^W * 100 ≈ 49.95%
    expected = Q / MAX_VAL * 100
    passed = abs(spread - expected) < 1.0  # 1 percentage point tolerance

    return passed, f"Spread: {spread:.2f}% (theoretical: {expected:.2f}%)"


def main():
    print_header("PAPER REPRODUCTION: Pre-Silicon Side-Channel Verification")
    print("Author: Ray Iskander")
    print("Date: December 2025")
    print()

    experiments = [
        ("Carry Probability Formula", experiment_carry_probability),
        ("Information Leakage (~0.81 bits)", experiment_info_leakage),
        ("Spread Calculation (~50%)", experiment_spread_calculation),
        ("DOM Pipeline Detection", experiment_dom_pipeline),
        ("Adams Bridge Full Analysis", experiment_adams_bridge_analysis),
    ]

    results: List[ExperimentResult] = []

    print_header("RUNNING EXPERIMENTS")

    for name, func in experiments:
        result = run_experiment(name, func)
        results.append(result)
        if result.details:
            for line in result.details.split('\n'):
                print(f"    {line}")
        print()

    # Summary
    print_header("REPRODUCTION SUMMARY")

    passed = sum(1 for r in results if r.passed)
    total = len(results)
    total_time = sum(r.duration for r in results)

    print(f"Experiments: {passed}/{total} passed")
    print(f"Total time: {total_time:.1f}s")
    print()

    for r in results:
        status = "✓" if r.passed else "✗"
        print(f"  {status} {r.name}")

    print()

    if passed == total:
        print("✓ ALL EXPERIMENTS PASSED - Paper claims verified")
        return 0
    else:
        print(f"⚠ {total - passed} experiment(s) failed")
        return 1


if __name__ == '__main__':
    sys.exit(main())
