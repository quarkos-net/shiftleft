#!/usr/bin/env python3
"""
Adams Bridge ML-DSA Accelerator Security Analysis

This script performs comprehensive side-channel security analysis on the
Adams Bridge ML-DSA accelerator, detecting:
1. DOM Pipeline configuration issues
2. Unmasked intermediate vulnerabilities
3. Carry bit statistical leakage

Usage:
    python3 scripts/analyze_adams_bridge.py [--target PATH]

Reference:
    "Pre-Silicon Side-Channel Verification of Post-Quantum Hardware: A Shift-Left Approach"
    Ray Iskander, December 2025
"""

import argparse
import os
import re
import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Tuple
from enum import Enum

class Severity(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Vulnerability:
    """Represents a detected vulnerability."""
    vuln_type: str
    severity: Severity
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    recommendation: str

@dataclass
class AnalysisReport:
    """Complete analysis report."""
    target: str
    dom_findings: List[Vulnerability] = field(default_factory=list)
    unmasked_findings: List[Vulnerability] = field(default_factory=list)
    carry_findings: List[Vulnerability] = field(default_factory=list)

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.dom_findings) + len(self.unmasked_findings) + len(self.carry_findings)

    @property
    def high_severity_count(self) -> int:
        all_vulns = self.dom_findings + self.unmasked_findings + self.carry_findings
        return sum(1 for v in all_vulns if v.severity == Severity.HIGH)


class AdamsBridgeAnalyzer:
    """
    Comprehensive security analyzer for Adams Bridge ML-DSA accelerator.
    """

    TARGET_FILES = {
        'dom': [
            'src/abr_prim/rtl/abr_prim_dom_and_2share.sv',
            'src/abr_sha3/rtl/abr_keccak_2share.sv',
        ],
        'ntt': [
            'src/ntt_top/rtl/ntt_masked_BFU_mult.sv',
            'src/ntt_top/rtl/ntt_masked_BFU_add_sub.sv',
            'src/ntt_top/rtl/ntt_masked_pairwm.sv',
        ],
        'barrett': [
            'src/barrett_reduction/rtl/masked_barrett_reduction.sv',
        ]
    }

    PATTERNS = {
        'pipeline_param': re.compile(r'parameter\s+bit\s+Pipeline\s*=\s*1\'b([01])'),
        'pipeline_instance': re.compile(r'\.Pipeline\s*\(\s*(\d+)\s*\)'),
        'share_combination': re.compile(r'(\w+)\s*=\s*\(?\s*(\w+)\[0\]\s*\+\s*(\w+)\[1\]\s*\)?'),
        'unmasked_mod': re.compile(r'(\w+)\s*=\s*\((\w+)\s*\+\s*(\w+)\)\s*%\s*(\w+)'),
        'carry_extraction': re.compile(r'carry_?\w*\s*=\s*.*\[(\d+)\]'),
    }

    def __init__(self, target_path: str, quiet: bool = False):
        self.target_path = Path(target_path)
        self.report = AnalysisReport(target=str(target_path))
        self.quiet = quiet

    def _log(self, msg: str):
        """Print message unless in quiet mode."""
        if not self.quiet:
            print(msg)

    def analyze(self) -> AnalysisReport:
        """Run complete security analysis."""
        self._log(f"\n{'='*70}")
        self._log("ADAMS BRIDGE SECURITY ANALYSIS")
        self._log(f"{'='*70}")
        self._log(f"Target: {self.target_path}")
        self._log("")

        self._analyze_dom_configuration()
        self._analyze_unmasked_intermediates()
        self._analyze_carry_leakage()

        return self.report

    def _analyze_dom_configuration(self):
        """Analyze DOM module configurations for Pipeline parameter."""
        self._log("[1/3] Analyzing DOM Pipeline Configuration...")

        for rel_path in self.TARGET_FILES['dom']:
            file_path = self.target_path / rel_path
            if not file_path.exists():
                self._log(f"  WARNING: {rel_path} not found")
                continue

            content = file_path.read_text()
            lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                match = self.PATTERNS['pipeline_param'].search(line)
                if match:
                    value = match.group(1)
                    if value == '0':
                        self.report.dom_findings.append(Vulnerability(
                            vuln_type="DOM Pipeline Default",
                            severity=Severity.INFO,
                            file_path=rel_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description="DOM module has Pipeline=0 as default (vulnerable if not overridden)",
                            recommendation="Ensure all instantiations use Pipeline=1"
                        ))
                    else:
                        self._log(f"  ✓ {rel_path}:{i} - Pipeline=1 (SECURE)")

            for i, line in enumerate(lines, 1):
                match = self.PATTERNS['pipeline_instance'].search(line)
                if match:
                    value = match.group(1)
                    if value == '0':
                        self.report.dom_findings.append(Vulnerability(
                            vuln_type="DOM Pipeline Instance",
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description="DOM instantiation with Pipeline=0 is vulnerable to glitch attacks",
                            recommendation="Change to .Pipeline(1) for glitch protection"
                        ))
                    else:
                        self._log(f"  ✓ {rel_path}:{i} - Instance uses Pipeline={value} (SECURE)")

        if not self.report.dom_findings:
            self._log("  ✓ All DOM configurations are SECURE (Pipeline=1)")
        self._log("")

    def _analyze_unmasked_intermediates(self):
        """Detect unmasked intermediate values in NTT operations."""
        self._log("[2/3] Analyzing for Unmasked Intermediates...")

        for rel_path in self.TARGET_FILES['ntt']:
            file_path = self.target_path / rel_path
            if not file_path.exists():
                self._log(f"  WARNING: {rel_path} not found")
                continue

            content = file_path.read_text()
            lines = content.split('\n')

            for i, line in enumerate(lines, 1):
                match = self.PATTERNS['unmasked_mod'].search(line)
                if match:
                    result_var = match.group(1)
                    operand1 = match.group(2)
                    operand2 = match.group(3)
                    modulus = match.group(4)

                    if ('res0' in operand1 and 'res1' in operand2) or \
                       ('share0' in operand1 and 'share1' in operand2) or \
                       (operand1.endswith('0') and operand2.endswith('1') and operand1[:-1] == operand2[:-1]):

                        self.report.unmasked_findings.append(Vulnerability(
                            vuln_type="Unmasked Intermediate",
                            severity=Severity.HIGH,
                            file_path=rel_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description=f"Shares combined BEFORE modular reduction creates unmasked value '{result_var}'",
                            recommendation=f"Reduce each share separately before combining"
                        ))
                        self._log(f"  ✗ VULNERABLE: {rel_path}:{i}")
                        self._log(f"    {line.strip()}")

        if not self.report.unmasked_findings:
            self._log("  ✓ No unmasked intermediates detected")
        self._log("")

    def _analyze_carry_leakage(self):
        """Detect carry bit extraction patterns that leak secret information."""
        self._log("[3/3] Analyzing for Carry Bit Leakage...")

        for rel_path in self.TARGET_FILES['barrett']:
            file_path = self.target_path / rel_path
            if not file_path.exists():
                self._log(f"  WARNING: {rel_path} not found")
                continue

            content = file_path.read_text()
            lines = content.split('\n')

            in_combination_block = False
            combination_line = 0

            for i, line in enumerate(lines, 1):
                comb_match = self.PATTERNS['share_combination'].search(line)
                if comb_match:
                    in_combination_block = True
                    combination_line = i

                carry_match = self.PATTERNS['carry_extraction'].search(line)
                if carry_match and ('carry' in line.lower() or '[' in line):
                    if '+' in line or (in_combination_block and i - combination_line <= 2):
                        bit_pos = carry_match.group(1)
                        self.report.carry_findings.append(Vulnerability(
                            vuln_type="Carry Bit Leakage",
                            severity=Severity.MEDIUM,
                            file_path=rel_path,
                            line_number=i,
                            code_snippet=line.strip(),
                            description=f"Carry bit extraction at bit {bit_pos} leaks ~0.81 bits per observation",
                            recommendation="Use secure A2B conversion (Goubin CHES 2001)"
                        ))
                        self._log(f"  ⚠ CARRY LEAKAGE: {rel_path}:{i}")
                        self._log(f"    {line.strip()}")
                        in_combination_block = False

        if not self.report.carry_findings:
            self._log("  ✓ No carry bit leakage detected")
        self._log("")

    def print_summary(self):
        """Print analysis summary."""
        print(f"{'='*70}")
        print("ANALYSIS SUMMARY")
        print(f"{'='*70}")

        print(f"\n[DOM Configuration]")
        if self.report.dom_findings:
            for v in self.report.dom_findings:
                print(f"  {v.severity.value}: {v.file_path}:{v.line_number}")
                print(f"         {v.description}")
        else:
            print("  ✓ SECURE - All DOM modules use Pipeline=1")

        print(f"\n[Unmasked Intermediates]")
        if self.report.unmasked_findings:
            for v in self.report.unmasked_findings:
                print(f"  {v.severity.value}: {v.file_path}:{v.line_number}")
                print(f"         {v.description}")
        else:
            print("  ✓ SECURE - No unmasked intermediates found")

        print(f"\n[Carry Bit Leakage]")
        if self.report.carry_findings:
            for v in self.report.carry_findings:
                print(f"  {v.severity.value}: {v.file_path}:{v.line_number}")
                print(f"         {v.description}")
        else:
            print("  ✓ SECURE - No carry leakage patterns found")

        print(f"\n{'='*70}")
        print(f"TOTAL FINDINGS: {self.report.total_vulnerabilities}")
        print(f"  HIGH severity: {self.report.high_severity_count}")
        print(f"  MEDIUM severity: {len(self.report.carry_findings)}")
        print(f"  INFO: {len([v for v in self.report.dom_findings if v.severity == Severity.INFO])}")
        print(f"{'='*70}")

        if self.report.high_severity_count > 0:
            print("\n⚠️  HIGH severity issues detected - immediate remediation recommended")
            return 1
        elif self.report.total_vulnerabilities > 0:
            print("\n⚠️  Issues detected - review and assess risk")
            return 0
        else:
            print("\n✓ No vulnerabilities detected")
            return 0


def main():
    parser = argparse.ArgumentParser(
        description="Adams Bridge ML-DSA Security Analyzer",
        epilog="Reference: 'Pre-Silicon Side-Channel Verification of Post-Quantum Hardware' by Ray Iskander"
    )
    parser.add_argument('--target', '-t', default='external/adams-bridge',
                        help='Path to Adams Bridge repository')
    parser.add_argument('--json', action='store_true', help='Output as JSON')

    args = parser.parse_args()

    target = Path(args.target)
    if not target.is_absolute():
        script_dir = Path(__file__).parent.parent
        target = script_dir / args.target

    if not target.exists():
        print(f"ERROR: Target path not found: {target}", file=sys.stderr)
        print(f"\nTo analyze Adams Bridge, first clone the repository:", file=sys.stderr)
        print(f"  git clone https://github.com/chipsalliance/adams-bridge {args.target}", file=sys.stderr)
        sys.exit(1)

    analyzer = AdamsBridgeAnalyzer(str(target), quiet=args.json)
    report = analyzer.analyze()

    if args.json:
        import json
        output = {
            'target': report.target,
            'summary': {
                'total_vulnerabilities': report.total_vulnerabilities,
                'high_severity': report.high_severity_count,
            },
            'findings': {
                'dom': [{'type': v.vuln_type, 'severity': v.severity.value,
                        'file': v.file_path, 'line': v.line_number,
                        'description': v.description} for v in report.dom_findings],
                'unmasked': [{'type': v.vuln_type, 'severity': v.severity.value,
                             'file': v.file_path, 'line': v.line_number,
                             'description': v.description} for v in report.unmasked_findings],
                'carry': [{'type': v.vuln_type, 'severity': v.severity.value,
                          'file': v.file_path, 'line': v.line_number,
                          'description': v.description} for v in report.carry_findings],
            }
        }
        print(json.dumps(output, indent=2))
    else:
        exit_code = analyzer.print_summary()
        sys.exit(exit_code)


if __name__ == '__main__':
    main()
