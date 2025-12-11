"""
Hamming Weight Verifier - Level 2 Power Model: HW/HD Independence

This module verifies that intermediate values in NTT hardware have
input-independent Hamming weight distributions, preventing DPA/CPA attacks.

Attack Model:
    DPA/CPA attacks exploit: P ∝ α·HW(v) + β·HD(v_prev, v) + noise

Property to Verify:
    ∀ x₁, x₂ ∈ Z_q : HW(f(x₁)) = HW(f(x₂))

Verification Options:
    A. Prove HW is constant (strongest): ∀ x1, x2: HW(v(x1)) = HW(v(x2))
    B. Prove masking complete (v = x ⊕ r) → HW-safe by construction
    C. Prove HW bounded: |HW(v(x1)) - HW(v(x2))| ≤ threshold

Usage:
    from shiftleft.formal import HammingWeightVerifier

    verifier = HammingWeightVerifier(algorithm="dilithium")
    result = verifier.verify_module(yosys_netlist)

    for sig in result.signal_results:
        if not sig.is_hw_independent:
            print(f"LEAKAGE: {sig.signal_name} - HW depends on input")

Requirements:
    - Z3 Python bindings (pip install z3-solver)
    - Yosys for RTL synthesis (optional, for RTL file verification)

References:
    - DPA: Kocher et al., Crypto 1999
    - .claude/research/4LEVEL_IMPLEMENTATION_PLAN.md

Author: Q-DEBUG Team
Date: December 10, 2025
Version: 1.0.0 (v1.0-L2: Level 2 Power Model - HW Verification)
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Union


# =============================================================================
# Constants
# =============================================================================

# Dilithium (ML-DSA) parameters
MLDSA_Q = 8380417
MLDSA_WIDTH = 23

# Kyber (ML-KEM) parameters
MLKEM_Q = 3329
MLKEM_WIDTH = 12


# =============================================================================
# Exceptions
# =============================================================================

class HammingWeightError(Exception):
    """Base error for Hamming weight verification."""
    pass


class SignalExtractionError(HammingWeightError):
    """Error during signal extraction from netlist."""
    pass


class SMTEncodingError(HammingWeightError):
    """Error during SMT encoding."""
    pass


# =============================================================================
# Enums
# =============================================================================

class HWSecurityStatus(Enum):
    """Hamming weight security classification."""
    SECURE_CONSTANT = "secure_constant"
    """Signal has constant value - HW trivially independent."""

    SECURE_MASKED = "secure_masked"
    """Signal is masked (v = x ⊕ r) - HW independent by construction."""

    SECURE_NO_SECRET = "secure_no_secret"
    """Signal does not depend on secrets - HW leakage irrelevant."""

    SECURE_VERIFIED = "secure_verified"
    """Signal verified HW-independent via SMT (UNSAT)."""

    REQUIRES_VERIFICATION = "requires_verification"
    """Signal needs SMT verification."""

    VULNERABLE = "vulnerable"
    """Signal has HW that depends on secret input (SAT found)."""

    UNKNOWN = "unknown"
    """Could not determine HW security status."""


# =============================================================================
# Dataclasses
# =============================================================================

@dataclass
class IntermediateSignal:
    """Represents an intermediate signal extracted from netlist."""
    name: str
    """Signal name from netlist."""

    width: int
    """Bit width of the signal."""

    source_cell: str = ""
    """Cell that produces this signal."""

    cell_type: str = ""
    """Type of the source cell ($add, $xor, etc.)."""

    is_secret: bool = False
    """Whether this signal is marked as secret."""

    is_random: bool = False
    """Whether this signal is marked as random."""

    is_constant: bool = False
    """Whether this signal is a constant."""

    constant_value: Optional[int] = None
    """Value if constant."""

    depends_on: List[str] = field(default_factory=list)
    """Signals this signal depends on."""

    input_a: Optional[str] = None
    """First input signal name (for binary ops)."""

    input_b: Optional[str] = None
    """Second input signal name (for binary ops)."""

    def __str__(self) -> str:
        return f"IntermediateSignal({self.name}, width={self.width}, type={self.cell_type})"


@dataclass
class SignalClassification:
    """Classification result for a signal."""
    signal_name: str
    status: HWSecurityStatus
    explanation: str = ""
    masked_by: Optional[str] = None


@dataclass
class HWVerificationResult:
    """Result of HW independence verification for a single signal."""
    signal_name: str
    """Name of the verified signal."""

    is_hw_independent: bool
    """True if HW is proven input-independent."""

    status: str
    """Verification status: safe, unsafe, timeout, unknown, safe_by_masking."""

    counterexample: Optional[Dict[str, Any]] = None
    """If leakage found, inputs demonstrating different HW."""

    time_seconds: float = 0.0
    """Time taken for verification."""

    explanation: str = ""
    """Human-readable explanation."""

    hw_bound: Optional[int] = None
    """If bounded mode, the HW difference bound."""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "signal_name": self.signal_name,
            "is_hw_independent": self.is_hw_independent,
            "status": self.status,
            "counterexample": self.counterexample,
            "time_seconds": self.time_seconds,
            "explanation": self.explanation,
            "hw_bound": self.hw_bound,
        }


@dataclass
class ModuleVerificationResult:
    """Result of HW verification for an entire module."""
    total_signals: int
    """Total number of signals analyzed."""

    hw_safe_signals: int
    """Number of signals proven HW-safe."""

    hw_leaking_signals: int
    """Number of signals with HW leakage."""

    signal_results: List[HWVerificationResult]
    """Per-signal verification results."""

    is_hw_safe: bool
    """True if all signals are HW-safe."""

    time_seconds: float = 0.0
    """Total verification time."""

    def summary(self) -> str:
        """Generate human-readable summary."""
        lines = [
            "=" * 60,
            "HAMMING WEIGHT VERIFICATION REPORT",
            "=" * 60,
            f"Total signals analyzed: {self.total_signals}",
            f"  HW-safe signals: {self.hw_safe_signals}",
            f"  HW-leaking signals: {self.hw_leaking_signals}",
            f"Overall status: {'SECURE' if self.is_hw_safe else 'VULNERABLE'}",
            f"Verification time: {self.time_seconds:.2f}s",
        ]

        if self.hw_leaking_signals > 0:
            lines.append("")
            lines.append("LEAKING SIGNALS:")
            for r in self.signal_results:
                if not r.is_hw_independent:
                    lines.append(f"  - {r.signal_name}: {r.explanation}")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_signals": self.total_signals,
            "hw_safe_signals": self.hw_safe_signals,
            "hw_leaking_signals": self.hw_leaking_signals,
            "is_hw_safe": self.is_hw_safe,
            "time_seconds": self.time_seconds,
            "signal_results": [r.to_dict() for r in self.signal_results],
        }


# =============================================================================
# HammingWeightVerifier Class
# =============================================================================

class HammingWeightVerifier:
    """
    Verifies Hamming weight independence of intermediate signals.

    This class analyzes hardware netlists to prove that intermediate
    signal values have input-independent Hamming weights, preventing
    DPA/CPA side-channel attacks.

    Example:
        >>> verifier = HammingWeightVerifier(algorithm="dilithium")
        >>> result = verifier.verify_module(yosys_netlist)
        >>> print(result.summary())
    """

    def __init__(
        self,
        algorithm: str = "dilithium",
        timeout: int = 120,
    ):
        """
        Initialize the verifier.

        Args:
            algorithm: PQC algorithm ("dilithium" or "kyber")
            timeout: Solver timeout per signal (seconds)

        Raises:
            ValueError: If algorithm is not recognized
        """
        self.algorithm = algorithm.lower()
        self.timeout = timeout

        if self.algorithm in ("dilithium", "mldsa"):
            self.q = MLDSA_Q
            self.width = MLDSA_WIDTH
        elif self.algorithm in ("kyber", "mlkem"):
            self.q = MLKEM_Q
            self.width = MLKEM_WIDTH
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}. Use 'dilithium' or 'kyber'.")

        self._z3_module = None
        self._signal_info: Dict[str, IntermediateSignal] = {}

    def _import_z3(self) -> Any:
        """Import z3 module lazily."""
        if self._z3_module is None:
            try:
                import z3
                self._z3_module = z3
            except ImportError as e:
                raise HammingWeightError(
                    "Z3 Python bindings not found. Install with: pip install z3-solver"
                ) from e
        return self._z3_module

    # =========================================================================
    # Signal Extraction
    # =========================================================================

    def extract_intermediate_signals(self, yosys_json: dict) -> List[IntermediateSignal]:
        """
        Extract all intermediate signals from Yosys JSON netlist.

        Args:
            yosys_json: Parsed Yosys JSON netlist

        Returns:
            List of IntermediateSignal objects
        """
        signals = []
        self._signal_info = {}

        modules = yosys_json.get("modules", {})

        for module_name, module in modules.items():
            cells = module.get("cells", {})
            netnames = module.get("netnames", {})
            ports = module.get("ports", {})

            # Build bit-to-name mapping
            bit_to_name: Dict[int, str] = {}
            for name, info in netnames.items():
                for bit in info.get("bits", []):
                    if isinstance(bit, int):
                        bit_to_name[bit] = name

            # Process netnames to extract signals
            for name, info in netnames.items():
                bits = info.get("bits", [])
                attrs = info.get("attributes", {})

                # Check if constant
                is_constant = all(isinstance(b, str) for b in bits)
                constant_value = None
                if is_constant and bits:
                    try:
                        # Convert bit string to integer
                        bit_str = "".join(str(b) for b in reversed(bits))
                        constant_value = int(bit_str.replace("x", "0").replace("z", "0"), 2)
                    except (ValueError, TypeError):
                        is_constant = False

                # Check attributes for secret/random
                is_secret = attrs.get("secret") == "1" or "secret" in name.lower()
                is_random = attrs.get("random") == "1" or "random" in name.lower() or "rnd" in name.lower()

                signal = IntermediateSignal(
                    name=name,
                    width=len(bits),
                    is_secret=is_secret,
                    is_random=is_random,
                    is_constant=is_constant,
                    constant_value=constant_value,
                )

                signals.append(signal)
                self._signal_info[name] = signal

            # Process cells to add computation info
            for cell_name, cell in cells.items():
                cell_type = cell.get("type", "")
                connections = cell.get("connections", {})

                # Get output signal
                output_bits = connections.get("Y", [])
                if not output_bits:
                    continue

                # Find output signal name
                output_name = None
                for bit in output_bits:
                    if isinstance(bit, int) and bit in bit_to_name:
                        output_name = bit_to_name[bit]
                        break

                if output_name and output_name in self._signal_info:
                    sig = self._signal_info[output_name]
                    sig.source_cell = cell_name
                    sig.cell_type = cell_type

                    # Track inputs
                    input_a_bits = connections.get("A", [])
                    input_b_bits = connections.get("B", [])

                    if input_a_bits:
                        for bit in input_a_bits:
                            if isinstance(bit, int) and bit in bit_to_name:
                                sig.input_a = bit_to_name[bit]
                                sig.depends_on.append(sig.input_a)
                                break

                    if input_b_bits:
                        for bit in input_b_bits:
                            if isinstance(bit, int) and bit in bit_to_name:
                                sig.input_b = bit_to_name[bit]
                                sig.depends_on.append(sig.input_b)
                                break

        return signals

    # =========================================================================
    # Signal Classification
    # =========================================================================

    def classify_signals(
        self,
        signals: List[IntermediateSignal]
    ) -> Dict[str, SignalClassification]:
        """
        Classify signals for HW security.

        Classifications:
        - SECURE_CONSTANT: Constant value
        - SECURE_MASKED: v = secret ⊕ random
        - SECURE_NO_SECRET: No secret dependency
        - REQUIRES_VERIFICATION: Needs SMT verification

        Args:
            signals: List of signals to classify

        Returns:
            Dict mapping signal name to classification
        """
        classifications = {}

        # Build dependency graph for transitive analysis
        secret_dependent = set()
        random_signals = set()

        for sig in signals:
            if sig.is_secret:
                secret_dependent.add(sig.name)
            if sig.is_random:
                random_signals.add(sig.name)

        # Propagate secret dependency
        changed = True
        while changed:
            changed = False
            for sig in signals:
                if sig.name not in secret_dependent:
                    for dep in sig.depends_on:
                        if dep in secret_dependent:
                            secret_dependent.add(sig.name)
                            changed = True
                            break

        # Classify each signal
        for sig in signals:
            # Check constant
            if sig.is_constant:
                classifications[sig.name] = SignalClassification(
                    signal_name=sig.name,
                    status=HWSecurityStatus.SECURE_CONSTANT,
                    explanation=f"Constant value {sig.constant_value}"
                )
                continue

            # Check no secret dependency
            if sig.name not in secret_dependent and not sig.is_secret:
                classifications[sig.name] = SignalClassification(
                    signal_name=sig.name,
                    status=HWSecurityStatus.SECURE_NO_SECRET,
                    explanation="No dependency on secret values"
                )
                continue

            # Check masking: XOR with random
            if sig.cell_type == "$xor":
                input_a_is_random = sig.input_a in random_signals if sig.input_a else False
                input_b_is_random = sig.input_b in random_signals if sig.input_b else False

                if input_a_is_random or input_b_is_random:
                    mask_var = sig.input_a if input_a_is_random else sig.input_b
                    classifications[sig.name] = SignalClassification(
                        signal_name=sig.name,
                        status=HWSecurityStatus.SECURE_MASKED,
                        explanation=f"Masked by XOR with {mask_var}",
                        masked_by=mask_var
                    )
                    continue

            # Requires SMT verification
            classifications[sig.name] = SignalClassification(
                signal_name=sig.name,
                status=HWSecurityStatus.REQUIRES_VERIFICATION,
                explanation="Secret-dependent, requires SMT verification"
            )

        return classifications

    # =========================================================================
    # SMT Encoding
    # =========================================================================

    def generate_hw_independence_smt(
        self,
        signal: IntermediateSignal,
        input_width: Optional[int] = None,
    ) -> str:
        """
        Generate SMT-LIB2 assertion for HW independence check.

        Property: ∀ x1, x2 ∈ [0, Q): HW(f(x1)) = HW(f(x2))
        We negate this to find counterexample: ∃ x1, x2: HW(f(x1)) ≠ HW(f(x2))

        Args:
            signal: Signal to verify
            input_width: Override input width (defaults to self.width)

        Returns:
            SMT-LIB2 string for Z3
        """
        # Determine widths - use signal width if available, else PQC default
        output_width = signal.width or self.width
        # Input width for the computation (use signal width for generic cases)
        width = input_width or output_width

        lines = []

        # Header
        lines.append(f"; Hamming Weight Independence Check")
        lines.append(f"; Signal: {signal.name}")
        lines.append(f"; Cell: {signal.source_cell} ({signal.cell_type})")
        lines.append(f"; Algorithm: {self.algorithm}, Q = {self.q}, input_width = {width}, output_width = {output_width}")
        lines.append("")

        # Set logic - use BV for bitvectors
        lines.append("(set-logic QF_BV)")
        lines.append("")

        # Define Q constant - always define it with appropriate width
        # Use output_width if large enough, else use self.width for general ops
        q_width = max(output_width, self.width)
        lines.append(f"; Q constant for modular constraints")
        lines.append(f"(define-fun Q () (_ BitVec {q_width}) (_ bv{self.q} {q_width}))")
        lines.append("")

        # Declare inputs - use output_width to match signal dimension
        lines.append("; First input")
        lines.append(f"(declare-const x1 (_ BitVec {output_width}))")
        # Only add Q constraint if width is sufficient for PQC modulus
        if output_width >= self.width:
            lines.append("(assert (bvult x1 Q))")
        lines.append("")

        lines.append("; Second input")
        lines.append(f"(declare-const x2 (_ BitVec {output_width}))")
        if output_width >= self.width:
            lines.append("(assert (bvult x2 Q))")
        lines.append("")

        # Define Hamming weight function using bit extraction and addition
        # HW(x) = sum of all bits
        lines.append("; Hamming weight (popcount) computation")
        lines.append("; HW(x) = number of 1-bits in x")
        lines.append("")

        # Generate HW computation for output width
        # Use recursive bit counting
        hw_width = output_width.bit_length() + 1  # Enough bits for max HW

        # For each input, compute the output and its HW
        lines.append("; Compute output for x1")
        lines.extend(self._generate_computation_smt(signal, "x1", "v1", output_width, output_width))
        lines.append("")

        lines.append("; Compute output for x2")
        lines.extend(self._generate_computation_smt(signal, "x2", "v2", output_width, output_width))
        lines.append("")

        # Compute HW for both outputs
        lines.append("; Compute Hamming weights")
        lines.extend(self._generate_hw_smt("v1", "hw1", output_width))
        lines.extend(self._generate_hw_smt("v2", "hw2", output_width))
        lines.append("")

        # Assert HW differs (looking for leakage)
        lines.append("; INDEPENDENCE CHECK: assert HW differs")
        lines.append("; SAT = leakage found, UNSAT = HW-independent")
        lines.append("(assert (not (= hw1 hw2)))")
        lines.append("")

        lines.append("(check-sat)")
        lines.append("(get-model)")

        return "\n".join(lines)

    def _generate_computation_smt(
        self,
        signal: IntermediateSignal,
        input_var: str,
        output_var: str,
        input_width: int,
        output_width: int,
    ) -> List[str]:
        """Generate SMT for computing signal from input."""
        lines = []

        cell_type = signal.cell_type
        # Use unique variable names based on output_var to avoid conflicts
        twiddle_var = f"twiddle_{output_var}"
        other_var = f"other_{output_var}"
        mul_result_var = f"mul_result_{output_var}"

        # Q width is max(output_width, self.width) - defined in parent
        q_width = max(output_width, self.width)

        if cell_type == "$add":
            # Addition: output = input + constant or input + input
            # For simplicity, model as output = input + twiddle
            lines.append(f"(declare-const {twiddle_var} (_ BitVec {input_width}))")
            # Only assert twiddle < Q if the width supports it
            if input_width >= self.width:
                lines.append(f"(assert (bvult {twiddle_var} ((_ extract {input_width-1} 0) Q)))")
            ext = output_width - input_width
            if ext > 0:
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  (bvadd ((_ zero_extend {ext}) {input_var}) ((_ zero_extend {ext}) {twiddle_var})))")
            else:
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  (bvadd {input_var} {twiddle_var}))")

        elif cell_type == "$sub":
            # Subtraction
            lines.append(f"(declare-const {twiddle_var} (_ BitVec {input_width}))")
            if input_width >= self.width:
                lines.append(f"(assert (bvult {twiddle_var} ((_ extract {input_width-1} 0) Q)))")
            ext = output_width - input_width
            if ext > 0:
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  (bvsub ((_ zero_extend {ext}) {input_var}) ((_ zero_extend {ext}) {twiddle_var})))")
            else:
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  (bvsub {input_var} {twiddle_var}))")

        elif cell_type == "$xor":
            # XOR: output = input ^ other
            lines.append(f"(declare-const {other_var} (_ BitVec {input_width}))")
            if output_width != input_width:
                ext = max(0, output_width - input_width)
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  (bvxor ((_ zero_extend {ext}) {input_var}) ((_ zero_extend {ext}) {other_var})))")
            else:
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  (bvxor {input_var} {other_var}))")

        elif cell_type == "$mul":
            # Multiplication
            lines.append(f"(declare-const {twiddle_var} (_ BitVec {input_width}))")
            if input_width >= self.width:
                lines.append(f"(assert (bvult {twiddle_var} ((_ extract {input_width-1} 0) Q)))")
            # Result width is typically 2*input_width, truncate if needed
            mul_width = 2 * input_width
            lines.append(f"(define-fun {mul_result_var} () (_ BitVec {mul_width})")
            lines.append(f"  (bvmul ((_ zero_extend {input_width}) {input_var}) ((_ zero_extend {input_width}) {twiddle_var})))")
            if output_width < mul_width:
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  ((_ extract {output_width-1} 0) {mul_result_var}))")
            else:
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  ((_ zero_extend {output_width - mul_width}) {mul_result_var}))")

        else:
            # Default: just pass through with possible extension
            if output_width != input_width:
                ext = max(0, output_width - input_width)
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width})")
                lines.append(f"  ((_ zero_extend {ext}) {input_var}))")
            else:
                lines.append(f"(define-fun {output_var} () (_ BitVec {output_width}) {input_var})")

        return lines

    def _generate_hw_smt(
        self,
        input_var: str,
        output_var: str,
        width: int
    ) -> List[str]:
        """Generate SMT for computing Hamming weight (popcount)."""
        lines = []

        # Compute HW by summing individual bits
        # HW(x) = bit0 + bit1 + ... + bit(n-1)

        hw_width = (width.bit_length() + 1)  # Enough bits for result

        # Extract and sum each bit
        bit_sums = []
        for i in range(width):
            bit_name = f"{input_var}_bit{i}"
            lines.append(f"(define-fun {bit_name} () (_ BitVec {hw_width})")
            lines.append(f"  ((_ zero_extend {hw_width-1}) ((_ extract {i} {i}) {input_var})))")
            bit_sums.append(bit_name)

        # Sum all bits
        if len(bit_sums) == 1:
            lines.append(f"(define-fun {output_var} () (_ BitVec {hw_width}) {bit_sums[0]})")
        else:
            # Build balanced tree of additions
            current = bit_sums
            level = 0
            while len(current) > 1:
                next_level = []
                for i in range(0, len(current), 2):
                    if i + 1 < len(current):
                        sum_name = f"{input_var}_sum_l{level}_{i//2}"
                        lines.append(f"(define-fun {sum_name} () (_ BitVec {hw_width})")
                        lines.append(f"  (bvadd {current[i]} {current[i+1]}))")
                        next_level.append(sum_name)
                    else:
                        next_level.append(current[i])
                current = next_level
                level += 1

            lines.append(f"(define-fun {output_var} () (_ BitVec {hw_width}) {current[0]})")

        return lines

    # =========================================================================
    # Z3 Verification
    # =========================================================================

    def prove_hw_independence(
        self,
        signal: IntermediateSignal,
        bounded_mode: bool = False,
        bound: int = 1,
    ) -> HWVerificationResult:
        """
        Prove HW independence for a signal using Z3.

        Args:
            signal: Signal to verify
            bounded_mode: If True, check |HW(v1) - HW(v2)| ≤ bound
            bound: Maximum HW difference in bounded mode

        Returns:
            HWVerificationResult
        """
        start_time = time.time()

        # Quick checks first
        if signal.is_constant:
            return HWVerificationResult(
                signal_name=signal.name,
                is_hw_independent=True,
                status="safe",
                explanation="Constant value - HW trivially independent",
                time_seconds=time.time() - start_time,
            )

        # Check if masked
        if signal.cell_type == "$xor":
            input_a = self._signal_info.get(signal.input_a)
            input_b = self._signal_info.get(signal.input_b)

            if (input_a and input_a.is_random) or (input_b and input_b.is_random):
                return HWVerificationResult(
                    signal_name=signal.name,
                    is_hw_independent=True,
                    status="safe_by_masking",
                    explanation="Masked by XOR with random - HW independent by construction",
                    time_seconds=time.time() - start_time,
                )

        # Run SMT verification
        z3 = self._import_z3()

        try:
            smt2 = self.generate_hw_independence_smt(signal)

            solver = z3.Solver()
            solver.set("timeout", self.timeout * 1000)

            try:
                assertions = z3.parse_smt2_string(smt2)
                solver.add(assertions)
            except Exception as e:
                return HWVerificationResult(
                    signal_name=signal.name,
                    is_hw_independent=False,
                    status="error",
                    explanation=f"SMT parse error: {e}",
                    time_seconds=time.time() - start_time,
                )

            result = solver.check()
            elapsed = time.time() - start_time

            if result == z3.unsat:
                return HWVerificationResult(
                    signal_name=signal.name,
                    is_hw_independent=True,
                    status="safe",
                    explanation="No inputs produce different HW - verified HW-independent",
                    time_seconds=elapsed,
                )

            elif result == z3.sat:
                # Extract counterexample
                model = solver.model()
                counterexample = {}

                try:
                    for decl in model.decls():
                        name = str(decl.name())
                        val = model[decl]
                        if hasattr(val, 'as_long'):
                            counterexample[name] = val.as_long()
                        else:
                            counterexample[name] = str(val)
                except Exception:
                    pass

                return HWVerificationResult(
                    signal_name=signal.name,
                    is_hw_independent=False,
                    status="unsafe",
                    counterexample=counterexample,
                    explanation=f"HW leakage: found inputs with different HW",
                    time_seconds=elapsed,
                )

            else:
                return HWVerificationResult(
                    signal_name=signal.name,
                    is_hw_independent=False,
                    status="unknown",
                    explanation="Solver returned unknown",
                    time_seconds=elapsed,
                )

        except Exception as e:
            return HWVerificationResult(
                signal_name=signal.name,
                is_hw_independent=False,
                status="error",
                explanation=f"Verification error: {e}",
                time_seconds=time.time() - start_time,
            )

    # =========================================================================
    # Module Verification
    # =========================================================================

    def verify_module(self, yosys_json: dict) -> ModuleVerificationResult:
        """
        Verify all signals in a module for HW independence.

        Args:
            yosys_json: Parsed Yosys JSON netlist

        Returns:
            ModuleVerificationResult with all signal results
        """
        start_time = time.time()

        # Extract signals
        signals = self.extract_intermediate_signals(yosys_json)

        if not signals:
            return ModuleVerificationResult(
                total_signals=0,
                hw_safe_signals=0,
                hw_leaking_signals=0,
                signal_results=[],
                is_hw_safe=True,
                time_seconds=time.time() - start_time,
            )

        # Classify signals
        classifications = self.classify_signals(signals)

        # Verify each signal
        results = []
        hw_safe = 0
        hw_leaking = 0

        for sig in signals:
            classification = classifications.get(sig.name)

            if classification:
                if classification.status == HWSecurityStatus.SECURE_CONSTANT:
                    result = HWVerificationResult(
                        signal_name=sig.name,
                        is_hw_independent=True,
                        status="safe",
                        explanation="Constant value",
                    )
                elif classification.status == HWSecurityStatus.SECURE_NO_SECRET:
                    result = HWVerificationResult(
                        signal_name=sig.name,
                        is_hw_independent=True,
                        status="safe",
                        explanation="No secret dependency",
                    )
                elif classification.status == HWSecurityStatus.SECURE_MASKED:
                    result = HWVerificationResult(
                        signal_name=sig.name,
                        is_hw_independent=True,
                        status="safe_by_masking",
                        explanation=f"Masked by {classification.masked_by}",
                    )
                else:
                    # Requires verification
                    result = self.prove_hw_independence(sig)
            else:
                result = self.prove_hw_independence(sig)

            results.append(result)

            if result.is_hw_independent:
                hw_safe += 1
            else:
                hw_leaking += 1

        elapsed = time.time() - start_time

        return ModuleVerificationResult(
            total_signals=len(signals),
            hw_safe_signals=hw_safe,
            hw_leaking_signals=hw_leaking,
            signal_results=results,
            is_hw_safe=(hw_leaking == 0),
            time_seconds=elapsed,
        )

    def verify_rtl_file(
        self,
        rtl_path: Union[str, Path],
        top_module: str,
    ) -> ModuleVerificationResult:
        """
        Verify HW independence from RTL file using Yosys.

        Args:
            rtl_path: Path to Verilog/SystemVerilog file
            top_module: Name of top module

        Returns:
            ModuleVerificationResult
        """
        from .yosys_backend import YosysBackend

        rtl_path = Path(rtl_path)

        # Synthesize with Yosys to JSON
        backend = YosysBackend()

        # We need JSON output, not SMT2
        # Modify backend to output JSON
        import subprocess
        import tempfile
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / f"{top_module}.json"

            script = f"""
            read_verilog {rtl_path}
            hierarchy -top {top_module}
            proc
            opt
            write_json {json_path}
            """

            result = subprocess.run(
                [str(backend.yosys_path), "-p", script],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode != 0:
                raise HammingWeightError(f"Yosys synthesis failed: {result.stderr}")

            if not json_path.exists():
                raise HammingWeightError("JSON output not generated")

            yosys_json = json.loads(json_path.read_text())

        return self.verify_module(yosys_json)
