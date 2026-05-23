"""SLSA-style provenance generation and policy evaluation.

This module intentionally keeps the data model small and auditable. It does not
claim full in-toto/SLSA compliance; it produces and validates the fields this
project can verify locally before a model artifact is loaded or promoted.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from src.signing import ModelSignature, compute_model_hash, verify_model

PROVENANCE_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://github.com/poojakira/Model-Supply-Chain-Auditor/model-build/v1"


@dataclass
class PolicyDecision:
    """Policy evaluation result."""

    allowed: bool
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def add_deny(self, reason: str) -> None:
        self.allowed = False
        self.reasons.append(reason)

    def add_warning(self, warning: str) -> None:
        self.warnings.append(warning)


def load_json(path: str | Path) -> dict[str, Any]:
    """Load a JSON object from disk."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError(f"JSON document must be an object: {path}")
    return data


def load_policy(path: str | Path) -> dict[str, Any]:
    """Load a model promotion policy from YAML."""
    data = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Policy must be a YAML object: {path}")
    return data


def build_provenance(
    artifact_path: str | Path,
    *,
    builder_id: str,
    source_repo: str,
    source_ref: str,
    run_id: str,
    materials: list[dict[str, str]] | None = None,
    build_type: str = BUILD_TYPE,
    timestamp: float | None = None,
) -> dict[str, Any]:
    """Create a minimal SLSA-style provenance statement for a model artifact."""
    path = Path(artifact_path)
    artifact_hash = compute_model_hash(str(path))
    created_at = timestamp or time.time()
    return {
        "_type": PROVENANCE_TYPE,
        "subject": [
            {
                "name": path.name,
                "digest": {"sha256": artifact_hash},
            }
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": build_type,
                "externalParameters": {
                    "sourceRepository": source_repo,
                    "sourceRef": source_ref,
                },
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {
                    "invocationId": run_id,
                    "startedOn": created_at,
                    "finishedOn": created_at,
                },
            },
            "materials": materials or [],
        },
    }


def evaluate_policy(
    *,
    artifact_path: str | Path,
    signature: ModelSignature,
    public_key: Any,
    provenance: dict[str, Any],
    policy: dict[str, Any],
    now: float | None = None,
) -> PolicyDecision:
    """Evaluate artifact signature and provenance against a promotion policy."""
    decision = PolicyDecision(allowed=True)
    current_time = now or time.time()

    if not verify_model(str(artifact_path), signature, public_key):
        decision.add_deny("signature verification failed")

    if signature.signer not in set(policy.get("allowed_signers", [])):
        decision.add_deny(f"signer not allowed: {signature.signer}")

    subject_digest = _subject_digest(provenance)
    artifact_hash = compute_model_hash(str(artifact_path))
    if subject_digest != artifact_hash:
        decision.add_deny("provenance subject digest does not match artifact hash")

    if provenance.get("_type") != PROVENANCE_TYPE:
        decision.add_deny("provenance statement type is not in-toto Statement v1")

    if provenance.get("predicateType") != PREDICATE_TYPE:
        decision.add_deny("provenance predicate type is not SLSA provenance v1")

    predicate = provenance.get("predicate", {})
    if not isinstance(predicate, dict):
        decision.add_deny("provenance predicate must be an object")
        predicate = {}

    build_def = predicate.get("buildDefinition", {})
    run_details = predicate.get("runDetails", {})
    builder = run_details.get("builder", {}) if isinstance(run_details, dict) else {}
    metadata = run_details.get("metadata", {}) if isinstance(run_details, dict) else {}

    builder_id = builder.get("id") if isinstance(builder, dict) else None
    if builder_id not in set(policy.get("allowed_builders", [])):
        decision.add_deny(f"builder not allowed: {builder_id}")

    external = build_def.get("externalParameters", {}) if isinstance(build_def, dict) else {}
    source_repo = external.get("sourceRepository") if isinstance(external, dict) else None
    source_ref = external.get("sourceRef") if isinstance(external, dict) else None

    if source_repo not in set(policy.get("allowed_source_repositories", [])):
        decision.add_deny(f"source repository not allowed: {source_repo}")

    allowed_refs = policy.get("allowed_source_refs", [])
    if allowed_refs and source_ref not in set(allowed_refs):
        decision.add_deny(f"source ref not allowed: {source_ref}")

    max_age_seconds = policy.get("max_provenance_age_seconds")
    finished_on = metadata.get("finishedOn") if isinstance(metadata, dict) else None
    if isinstance(max_age_seconds, int | float) and isinstance(finished_on, int | float):
        if current_time - finished_on > max_age_seconds:
            decision.add_deny("provenance is older than policy max age")
    elif max_age_seconds:
        decision.add_warning("policy requested provenance age check but finishedOn is missing")

    required_materials = set(policy.get("required_material_names", []))
    material_names = {
        str(material.get("uri"))
        for material in predicate.get("materials", [])
        if isinstance(material, dict)
    }
    missing_materials = sorted(required_materials - material_names)
    if missing_materials:
        decision.add_deny(f"required materials missing: {', '.join(missing_materials)}")

    return decision


def _subject_digest(provenance: dict[str, Any]) -> str | None:
    subjects = provenance.get("subject", [])
    if not isinstance(subjects, list) or not subjects:
        return None
    first = subjects[0]
    if not isinstance(first, dict):
        return None
    digest = first.get("digest", {})
    if not isinstance(digest, dict):
        return None
    return digest.get("sha256")
