"""Tests for provenance generation and promotion policy gates."""

import json
import time

import yaml

from src.provenance import build_provenance, evaluate_policy
from src.signing import generate_signing_keypair, sign_model


def _base_policy() -> dict:
    return {
        "allowed_signers": ["training-pipeline-v1"],
        "allowed_builders": ["github-actions://poojakira/model-release"],
        "allowed_source_repositories": ["https://github.com/poojakira/Model-Supply-Chain-Auditor"],
        "allowed_source_refs": ["refs/heads/main"],
        "max_provenance_age_seconds": 3600,
        "required_material_names": ["training-data"],
    }


def test_build_provenance_subject_matches_artifact_hash(safe_pkl_file):
    provenance = build_provenance(
        safe_pkl_file,
        builder_id="github-actions://poojakira/model-release",
        source_repo="https://github.com/poojakira/Model-Supply-Chain-Auditor",
        source_ref="refs/heads/main",
        run_id="12345",
        timestamp=1000.0,
    )

    assert provenance["_type"] == "https://in-toto.io/Statement/v1"
    assert provenance["predicateType"] == "https://slsa.dev/provenance/v1"
    assert provenance["subject"][0]["digest"]["sha256"]
    assert provenance["predicate"]["runDetails"]["metadata"]["invocationId"] == "12345"


def test_policy_allows_signed_artifact_with_trusted_provenance(safe_pkl_file, tmp_path):
    material = tmp_path / "train.csv"
    material.write_text("x,y\n1,0\n")
    private_key, public_key = generate_signing_keypair()
    signature = sign_model(safe_pkl_file, private_key, signer="training-pipeline-v1")
    provenance = build_provenance(
        safe_pkl_file,
        builder_id="github-actions://poojakira/model-release",
        source_repo="https://github.com/poojakira/Model-Supply-Chain-Auditor",
        source_ref="refs/heads/main",
        run_id="12345",
        materials=[
            {
                "uri": "training-data",
                "digest": {"sha256": "not-used-for-policy-yet"},
            }
        ],
        timestamp=time.time(),
    )

    decision = evaluate_policy(
        artifact_path=safe_pkl_file,
        signature=signature,
        public_key=public_key,
        provenance=provenance,
        policy=_base_policy(),
    )

    assert decision.allowed is True
    assert decision.reasons == []


def test_policy_denies_tampered_artifact(safe_pkl_file):
    private_key, public_key = generate_signing_keypair()
    signature = sign_model(safe_pkl_file, private_key, signer="training-pipeline-v1")
    provenance = build_provenance(
        safe_pkl_file,
        builder_id="github-actions://poojakira/model-release",
        source_repo="https://github.com/poojakira/Model-Supply-Chain-Auditor",
        source_ref="refs/heads/main",
        run_id="12345",
        materials=[{"uri": "training-data", "digest": {"sha256": "abc"}}],
        timestamp=time.time(),
    )

    with open(safe_pkl_file, "ab") as f:
        f.write(b"tamper")

    decision = evaluate_policy(
        artifact_path=safe_pkl_file,
        signature=signature,
        public_key=public_key,
        provenance=provenance,
        policy=_base_policy(),
    )

    assert decision.allowed is False
    assert "signature verification failed" in decision.reasons
    assert "provenance subject digest does not match artifact hash" in decision.reasons


def test_policy_denies_untrusted_builder(safe_pkl_file):
    private_key, public_key = generate_signing_keypair()
    signature = sign_model(safe_pkl_file, private_key, signer="training-pipeline-v1")
    provenance = build_provenance(
        safe_pkl_file,
        builder_id="local-laptop",
        source_repo="https://github.com/poojakira/Model-Supply-Chain-Auditor",
        source_ref="refs/heads/main",
        run_id="12345",
        materials=[{"uri": "training-data", "digest": {"sha256": "abc"}}],
        timestamp=time.time(),
    )

    decision = evaluate_policy(
        artifact_path=safe_pkl_file,
        signature=signature,
        public_key=public_key,
        provenance=provenance,
        policy=_base_policy(),
    )

    assert decision.allowed is False
    assert "builder not allowed: local-laptop" in decision.reasons


def test_cli_attest_and_policy_allow(safe_pkl_file, tmp_path):
    from src.cli import cmd_attest, cmd_policy

    private_key, public_key = generate_signing_keypair()
    signature = sign_model(safe_pkl_file, private_key, signer="training-pipeline-v1")

    signature_path = tmp_path / "model.sig"
    signature_path.write_text(
        json.dumps(
            {
                "model_hash": signature.model_hash,
                "signature": signature.signature.hex(),
                "signer": signature.signer,
                "timestamp": signature.timestamp,
                "metadata": signature.metadata,
            }
        )
    )
    public_key_path = tmp_path / "model.pub"

    from src.signing import export_public_key

    public_key_path.write_bytes(export_public_key(public_key))
    material_path = tmp_path / "train.csv"
    material_path.write_text("x,y\n1,0\n")
    provenance_path = tmp_path / "provenance.json"
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(yaml.safe_dump(_base_policy()))

    attest_args = type(
        "Args",
        (),
        {
            "file": safe_pkl_file,
            "builder_id": "github-actions://poojakira/model-release",
            "source_repo": "https://github.com/poojakira/Model-Supply-Chain-Auditor",
            "source_ref": "refs/heads/main",
            "run_id": "12345",
            "material": [f"training-data={material_path}"],
            "output": str(provenance_path),
        },
    )()
    assert cmd_attest(attest_args) == 0

    policy_args = type(
        "Args",
        (),
        {
            "file": safe_pkl_file,
            "signature": str(signature_path),
            "key": str(public_key_path),
            "provenance": str(provenance_path),
            "policy": str(policy_path),
            "format": "json",
        },
    )()
    assert cmd_policy(policy_args) == 0
