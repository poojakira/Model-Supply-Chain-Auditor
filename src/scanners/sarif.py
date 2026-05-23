"""SARIF output formatter for pickle scan results.

Generates Static Analysis Results Interchange Format (SARIF) v2.1.0
compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other tools.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from .pickle_scanner import PickleScanResult

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"

RULES = {
    "PICKLE000": {
        "name": "ParseError",
        "shortDescription": "Failed to parse pickle file",
        "level": "note",
    },
    "PICKLE001": {
        "name": "DangerousImport",
        "shortDescription": "Import of dangerous module detected",
        "level": "error",
    },
    "PICKLE002": {
        "name": "CodeExecution",
        "shortDescription": "Code execution opcode with dangerous callable",
        "level": "error",
    },
    "PICKLE003": {
        "name": "StateInjection",
        "shortDescription": "State injection via BUILD opcode",
        "level": "warning",
    },
    "PICKLE004": {
        "name": "SuspiciousChain",
        "shortDescription": "Suspicious REDUCE chain depth",
        "level": "warning",
    },
    "PICKLE005": {
        "name": "PostStopPayload",
        "shortDescription": "Opcodes found after STOP (hidden payload)",
        "level": "error",
    },
}

SEVERITY_MAP = {"critical": "9.8", "high": "7.5", "medium": "5.0", "low": "2.0", "info": "0.0"}


def to_sarif(result: PickleScanResult, filepath: str) -> dict[str, Any]:
    """Convert scan result to SARIF v2.1.0 JSON structure."""
    rules_used = {}
    results = []

    for finding in result.findings:
        rule_id = finding.rule_id
        if rule_id not in rules_used:
            rules_used[rule_id] = RULES.get(
                rule_id,
                {
                    "name": rule_id,
                    "shortDescription": finding.message,
                    "level": "warning",
                },
            )

        results.append(
            {
                "ruleId": rule_id,
                "level": rules_used[rule_id]["level"],
                "message": {"text": finding.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": filepath},
                            "region": {"byteOffset": finding.byte_offset},
                        }
                    }
                ],
                "properties": {"security-severity": SEVERITY_MAP.get(finding.severity, "5.0")},
            }
        )

    rule_descriptors = []
    for rule_id, rule_info in rules_used.items():
        rule_descriptors.append(
            {
                "id": rule_id,
                "name": rule_info["name"],
                "shortDescription": {"text": rule_info["shortDescription"]},
                "properties": {"tags": ["security", "supply-chain", "pickle"]},
            }
        )

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "model-supply-chain-auditor",
                        "version": "0.4.0",
                        "informationUri": "https://github.com/poojakira/Model-Supply-Chain-Auditor",
                        "rules": rule_descriptors,
                    }
                },
                "results": results,
            }
        ],
    }


def sarif_json(result: PickleScanResult, filepath: str) -> str:
    """Return SARIF as formatted JSON string."""
    return json.dumps(to_sarif(result, filepath), indent=2)
