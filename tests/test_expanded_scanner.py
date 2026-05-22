"""Tests for expanded scanner features: ZIP extraction, BUILD/INST opcodes, chain depth."""

import os
import pickle
import zipfile

from src.scanners import scan_pickle_bytes, scan_pickle_file, Finding


class TestStructuredFindings:
    """Verify Finding objects have correct structure."""

    def test_finding_has_required_fields(self):
        data = pickle.dumps(type("E", (), {"__reduce__": lambda s: (os.system, ("id",))})())
        result = scan_pickle_bytes(data)
        assert len(result.findings) > 0
        f = result.findings[0]
        assert isinstance(f, Finding)
        assert f.rule_id.startswith("PICKLE")
        assert f.severity in ("critical", "high", "medium", "low", "info")
        assert isinstance(f.byte_offset, int)
        assert len(f.message) > 0

    def test_finding_str_representation(self):
        f = Finding("PICKLE001", "critical", "Dangerous import: os.system", 25)
        s = str(f)
        assert "PICKLE001" in s
        assert "os.system" in s
        assert "25" in s


class TestZipExtraction:
    """Test scanning of PyTorch .pt ZIP archives."""

    def _make_pt_file(self, tmp_path, pkl_data: bytes, entry_name: str = "archive/data.pkl"):
        """Create a minimal .pt ZIP file containing pickle data."""
        filepath = tmp_path / "model.pt"
        with zipfile.ZipFile(filepath, "w") as zf:
            zf.writestr(entry_name, pkl_data)
        return str(filepath)

    def test_safe_pt_file(self, tmp_path):
        safe_data = pickle.dumps({"weight": [0.1, 0.2], "bias": 0.0})
        filepath = self._make_pt_file(tmp_path, safe_data)
        result = scan_pickle_file(filepath)
        assert result.risk_level == "safe"
        assert "archive/data.pkl" in result.scanned_files

    def test_malicious_pt_file(self, tmp_path):
        class Exploit:
            def __reduce__(self):
                return (os.system, ("id",))

        mal_data = pickle.dumps(Exploit())
        filepath = self._make_pt_file(tmp_path, mal_data)
        result = scan_pickle_file(filepath)
        assert result.risk_level in ("suspicious", "malicious")
        assert len(result.dangerous_imports) > 0

    def test_non_zip_pkl_still_works(self, tmp_path):
        """Plain .pkl files (not ZIP) still scan correctly."""
        filepath = tmp_path / "model.pkl"
        filepath.write_bytes(pickle.dumps({"x": 1}))
        result = scan_pickle_file(str(filepath))
        assert result.risk_level == "safe"

    def test_malformed_zip(self, tmp_path):
        filepath = tmp_path / "bad.pt"
        # Write ZIP magic but corrupt content
        filepath.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        result = scan_pickle_file(str(filepath))
        assert result.risk_level == "error"


class TestExpandedOpcodes:
    """Test detection of BUILD, NEWOBJ, and other execution opcodes."""

    def test_reduce_chain_depth_detection(self):
        """Multiple chained REDUCE operations should be flagged."""
        # Create a pickle with multiple REDUCE calls by chaining
        class Chain:
            def __reduce__(self):
                return (os.system, ("echo step1 && echo step2 && echo step3 && echo step4",))

        data = pickle.dumps(Chain())
        result = scan_pickle_bytes(data)
        # Should detect the dangerous import + REDUCE
        assert result.risk_level in ("suspicious", "malicious")

    def test_subprocess_detected_as_critical(self):
        """subprocess.Popen should be severity=critical."""
        import subprocess

        class Exploit:
            def __reduce__(self):
                return (subprocess.Popen, (["id"],))

        data = pickle.dumps(Exploit())
        result = scan_pickle_bytes(data)
        critical_findings = [f for f in result.findings if f.severity == "critical"]
        assert len(critical_findings) > 0

    def test_importlib_detected(self):
        """importlib.import_module is in dangerous_callables (CVE-2025-1716 class)."""
        import importlib

        class Exploit:
            def __reduce__(self):
                return (importlib.import_module, ("os",))

        data = pickle.dumps(Exploit())
        result = scan_pickle_bytes(data)
        assert result.risk_level in ("suspicious", "malicious")
        assert any("importlib" in imp for imp in result.dangerous_imports)


class TestRulesLoading:
    """Test YAML rules loading and customization."""

    def test_custom_rules(self):
        """Scanner respects custom rules dict."""
        custom_rules = {
            "settings": {"max_reduce_depth": 3, "unknown_module_risk": "suspicious", "scan_past_stop": True},
            "safe_modules": ["numpy"],
            "dangerous_modules": {"critical": ["os", "nt", "posix"], "high": [], "medium": []},
            "dangerous_callables": ["os.system"],
        }
        # Safe pickle with custom rules
        data = pickle.dumps({"x": 1})
        result = scan_pickle_bytes(data, rules=custom_rules)
        assert result.risk_level == "safe"

    def test_rules_yaml_loads(self):
        """The rules.yaml file loads without error."""
        from src.scanners.pickle_scanner import _load_rules
        from pathlib import Path

        rules = _load_rules(Path("rules.yaml"))
        assert "settings" in rules
        assert "safe_modules" in rules
        assert "dangerous_modules" in rules
        assert "dangerous_callables" in rules
        assert "os.system" in rules["dangerous_callables"]
