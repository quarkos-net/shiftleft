"""
Basic tests for L1 and L2 verifiers.
"""

import pytest


class TestModularHintVerifier:
    """Tests for L1 (control-flow) verifier."""

    def test_import(self):
        """Verify L1 verifier can be imported."""
        from shiftleft.formal import ModularHintVerifier
        assert ModularHintVerifier is not None

    def test_instantiation(self):
        """Verify L1 verifier can be instantiated."""
        from shiftleft.formal import ModularHintVerifier
        verifier = ModularHintVerifier()
        assert verifier is not None


class TestHammingWeightVerifier:
    """Tests for L2 (power) verifier."""

    def test_import(self):
        """Verify L2 verifier can be imported."""
        from shiftleft.formal import HammingWeightVerifier
        assert HammingWeightVerifier is not None

    def test_instantiation(self):
        """Verify L2 verifier can be instantiated."""
        from shiftleft.formal import HammingWeightVerifier
        verifier = HammingWeightVerifier()
        assert verifier is not None


class TestIntegration:
    """Integration tests."""

    def test_package_version(self):
        """Verify package has version."""
        import shiftleft
        assert shiftleft.__version__ == "0.1.0"

    def test_package_exports(self):
        """Verify package exports expected classes."""
        from shiftleft import HammingWeightVerifier, ModularHintVerifier
        assert HammingWeightVerifier is not None
        assert ModularHintVerifier is not None
