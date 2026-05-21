"""Tests for SARIF output formatter."""

import json
import os
import pickle

from src.scanners import scan_pickle_bytes
from src.scanners.sarif import to_sarif, sarif_json, SARIF_VERSION


class TestSarifOutput:
    def test_sarif_structure(self):
        class E:
            def __reduce__(self):
                return (os.system, ("id",))

        result = scan_pickle_bytes(pickle.dumps(E()))
        sarif = to_sarif(result, "test.pkl")

        assert sarif["version"] == SARIF_VERSION
        assert "$schema" in sarif
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "model-supply-chain-auditor"

    def test_sarif_has_results(self):
        class E:
            def __reduce__(self):
                return (os.system, ("id",))

        result = scan_pickle_bytes(pickle.dumps(E()))
        sarif = to_sarif(result, "evil.pkl")

        results = sarif["runs"][0]["results"]
        assert len(results) > 0
        assert results[0]["ruleId"].startswith("PICKLE")
        assert "locations" in results[0]
        assert results[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "evil.pkl"

    def test_sarif_json_is_valid(self):
        result = scan_pickle_bytes(pickle.dumps({"safe": True}))
        output = sarif_json(result, "safe.pkl")
        parsed = json.loads(output)
        assert parsed["version"] == SARIF_VERSION

    def test_safe_file_has_no_results(self):
        result = scan_pickle_bytes(pickle.dumps(42))
        sarif = to_sarif(result, "num.pkl")
        assert sarif["runs"][0]["results"] == []

    def test_sarif_security_severity(self):
        import subprocess

        class E:
            def __reduce__(self):
                return (subprocess.Popen, (["id"],))

        result = scan_pickle_bytes(pickle.dumps(E()))
        sarif = to_sarif(result, "test.pkl")
        results = sarif["runs"][0]["results"]
        severities = [r["properties"]["security-severity"] for r in results]
        assert "9.8" in severities  # critical findings
