"""
Shiftleft: Pre-silicon side-channel verification for PQC hardware.

Detect power analysis vulnerabilities before tape-out—in seconds, with no hardware required.
"""

__version__ = "0.1.0"
__author__ = "Ray Iskander"
__email__ = "ray@quarkos.net"

from shiftleft.formal.hamming_weight_verifier import HammingWeightVerifier
from shiftleft.formal.modular_hint_verifier import ModularHintVerifier

__all__ = [
    "HammingWeightVerifier",
    "ModularHintVerifier",
    "__version__",
]
