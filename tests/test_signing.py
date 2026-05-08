"""Tests for Ed25519 model signing and verification.

All cryptographic operations are REAL — no mocking.
Uses the 'cryptography' library (same as pip, certbot, SSH).
Ed25519: Bernstein et al., "High-speed high-security signatures" (2012).
"""

import pytest

from src.signing import (
    compute_model_hash,
    generate_signing_keypair,
    sign_model,
    verify_model,
    export_public_key,
    ModelSignature,
)


@pytest.fixture
def keypair():
    """Generate a real Ed25519 keypair."""
    return generate_signing_keypair()


@pytest.fixture
def model_file(tmp_path):
    """Create a real file with deterministic content."""
    filepath = tmp_path / "weights.pt"
    # 1900 bytes — realistic small model checkpoint
    filepath.write_bytes(bytes(range(256)) * 7 + bytes(range(156)))
    return str(filepath)


class TestHashing:
    """SHA-256 hashing of model files."""

    def test_hash_is_64_hex_chars(self, model_file):
        h = compute_model_hash(model_file)
        assert len(h) == 64
        int(h, 16)  # valid hex

    def test_hash_is_deterministic(self, model_file):
        assert compute_model_hash(model_file) == compute_model_hash(model_file)

    def test_different_files_different_hashes(self, tmp_path):
        a = tmp_path / "a.pt"
        b = tmp_path / "b.pt"
        a.write_bytes(b"\x00" * 100)
        b.write_bytes(b"\x01" * 100)
        assert compute_model_hash(str(a)) != compute_model_hash(str(b))


class TestKeypair:
    """Ed25519 key generation."""

    def test_keypair_generated(self, keypair):
        private_key, public_key = keypair
        assert private_key is not None
        assert public_key is not None

    def test_public_key_exports_to_pem(self, keypair):
        _, pub = keypair
        pem = export_public_key(pub)
        assert b"-----BEGIN PUBLIC KEY-----" in pem
        assert b"-----END PUBLIC KEY-----" in pem

    def test_each_keypair_is_unique(self):
        _, pub1 = generate_signing_keypair()
        _, pub2 = generate_signing_keypair()
        assert export_public_key(pub1) != export_public_key(pub2)


class TestSignVerify:
    """End-to-end sign and verify — real cryptographic operations."""

    def test_sign_returns_valid_signature(self, keypair, model_file):
        priv, _ = keypair
        sig = sign_model(model_file, priv, signer="training-pipeline-v1")
        assert isinstance(sig, ModelSignature)
        assert len(sig.signature) == 64  # Ed25519 = 64-byte signatures
        assert sig.signer == "training-pipeline-v1"
        assert sig.metadata["algorithm"] == "Ed25519"

    def test_verify_unmodified_model(self, keypair, model_file):
        priv, pub = keypair
        sig = sign_model(model_file, priv)
        assert verify_model(model_file, sig, pub) is True

    def test_tampered_model_fails_verification(self, keypair, model_file):
        """Simulates supply chain attack: model modified after signing."""
        priv, pub = keypair
        sig = sign_model(model_file, priv)
        # Attacker appends backdoor weights
        with open(model_file, "ab") as f:
            f.write(b"BACKDOOR_WEIGHTS")
        assert verify_model(model_file, sig, pub) is False

    def test_wrong_public_key_fails(self, model_file):
        """Attacker signs with their key, victim verifies with legitimate key."""
        attacker_priv, _ = generate_signing_keypair()
        _, legitimate_pub = generate_signing_keypair()
        sig = sign_model(model_file, attacker_priv, signer="attacker")
        assert verify_model(model_file, sig, legitimate_pub) is False

    def test_signature_contains_timestamp(self, keypair, model_file):
        priv, _ = keypair
        sig = sign_model(model_file, priv)
        assert sig.timestamp > 0
        assert sig.metadata["hash_algorithm"] == "SHA-256"
