"""
Model Signing and Verification

Implements cryptographic model provenance using Ed25519 signatures.
Ensures model integrity from training to deployment.

Workflow:
1. After training, compute SHA-256 hash of model file
2. Sign the hash with Ed25519 private key
3. Distribute model + signature + public key
4. Before loading, verify signature against model hash

Ed25519 chosen because:
- Fast (62,000 signatures/sec on commodity hardware)
- Small keys (32 bytes) and signatures (64 bytes)
- Deterministic (no nonce reuse vulnerabilities like ECDSA)
- Used by: SSH, TLS 1.3, Signal Protocol, Tor

Reference: Bernstein et al., "High-speed high-security signatures" (2012)
"""
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path

# Use Python's built-in cryptography (available since 3.6 via hashlib)
# For Ed25519, we use the 'cryptography' library
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey, Ed25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@dataclass
class ModelSignature:
    model_hash: str  # SHA-256 hex digest
    signature: bytes  # Ed25519 signature
    signer: str  # Identity of signer
    timestamp: float  # Unix timestamp
    metadata: dict  # Additional provenance info


def compute_model_hash(filepath: str) -> str:
    """Compute SHA-256 hash of a model file."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def generate_signing_keypair():
    """Generate Ed25519 keypair for model signing."""
    if not HAS_CRYPTO:
        raise ImportError("Install 'cryptography' package: pip install cryptography")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def sign_model(filepath: str, private_key, signer: str = "unknown") -> ModelSignature:
    """
    Sign a model file with Ed25519.

    Args:
        filepath: Path to model file
        private_key: Ed25519PrivateKey
        signer: Identity string (e.g., "training-pipeline-v2")

    Returns:
        ModelSignature with hash, signature, and metadata
    """
    model_hash = compute_model_hash(filepath)
    # Sign the hash bytes
    signature = private_key.sign(model_hash.encode("utf-8"))

    return ModelSignature(
        model_hash=model_hash,
        signature=signature,
        signer=signer,
        timestamp=time.time(),
        metadata={
            "algorithm": "Ed25519",
            "hash_algorithm": "SHA-256",
            "file": str(Path(filepath).name),
            "file_size": Path(filepath).stat().st_size,
        },
    )


def verify_model(filepath: str, signature: ModelSignature, public_key) -> bool:
    """
    Verify model integrity against signature.

    Args:
        filepath: Path to model file
        signature: ModelSignature to verify against
        public_key: Ed25519PublicKey of the signer

    Returns:
        True if signature is valid and model is unmodified
    """
    # Recompute hash
    current_hash = compute_model_hash(filepath)

    # Check hash matches
    if current_hash != signature.model_hash:
        return False

    # Verify Ed25519 signature
    try:
        public_key.verify(signature.signature, signature.model_hash.encode("utf-8"))
        return True
    except InvalidSignature:
        return False


def export_public_key(public_key) -> bytes:
    """Export public key in PEM format for distribution."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(pem_data: bytes):
    """Load public key from PEM bytes."""
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
    return load_pem_public_key(pem_data)
