"""Regression tests for recent pickle bypass patterns."""

import io
import pickle
import zipfile

from src.scanners import scan_pickle_bytes, scan_pickle_file


class TestTypingForwardRefBypass:
    """SiggytheShark technique: typing.ForwardRef + typing._eval_type."""

    def test_typing_forwardref_detected(self):
        """typing.ForwardRef should be flagged as an eval-capable callable."""
        # Craft pickle with typing.ForwardRef
        # Protocol 0: GLOBAL typing ForwardRef + arg + REDUCE + STOP
        raw = b'ctyping\nForwardRef\n(S\'__import__("os").system("id")\'\ntR.'
        result = scan_pickle_bytes(raw)
        assert result.risk_level == "malicious"
        assert any("typing.ForwardRef" in str(f) for f in result.findings)


class TestOperatorChainBypass:
    """Operator helpers can defer attribute or method dispatch."""

    def test_methodcaller_detected(self):
        """operator.methodcaller is in dangerous_callables."""
        raw = b"coperator\nmethodcaller\n(S'system'\ntR."
        result = scan_pickle_bytes(raw)
        assert result.risk_level == "malicious"
        assert any("methodcaller" in str(f) for f in result.findings)

    def test_attrgetter_detected(self):
        """operator.attrgetter is in dangerous_callables."""
        raw = b"coperator\nattrgetter\n(S'system'\ntR."
        result = scan_pickle_bytes(raw)
        assert result.risk_level == "malicious"


class TestPipMainBypass:
    """Sonatype CVE-2025-1716: pip.main bypass."""

    def test_pip_main_detected(self):
        """pip.main is in dangerous_callables (CVE-2025-1716)."""
        raw = b"cpip\nmain\n(]S'install'\nS'evil'\netR."
        result = scan_pickle_bytes(raw)
        assert result.risk_level == "malicious"
        assert any("pip.main" in str(f) for f in result.findings)


class TestNumpyGadgets:
    """NumPy internal gadgets described in pickle bypass research."""

    def test_numpy_distutils_exec_command_detected(self):
        """numpy.distutils.exec_command._exec_command bypasses scanners (PickleCloak)."""
        raw = b"cnumpy.distutils.exec_command\n_exec_command\n(S'id'\ntR."
        result = scan_pickle_bytes(raw)
        assert result.risk_level == "malicious"

    def test_numpy_f2py_capi_maps_getinit_detected(self):
        """numpy.f2py.capi_maps.getinit (PickleCloak ACE gadget)."""
        raw = b'cnumpy.f2py.capi_maps\ngetinit\n(S\'__import__("os").system("id")\'\ntR.'
        result = scan_pickle_bytes(raw)
        assert result.risk_level == "malicious"


class TestAsyncioBypass:
    """JFrog CVE-2025-10157: unsafe globals submodule bypass pattern."""

    def test_asyncio_unix_subprocess_detected(self):
        """asyncio.unix_events._UnixSubprocessTransport is critical."""
        raw = b"casyncio\nunix_events\n."  # Module import alone
        result = scan_pickle_bytes(raw)
        # asyncio is in dangerous_modules.high
        assert result.risk_level in ("suspicious", "malicious")


class TestNestedArchives:
    """Nested archive evasion regression tests."""

    def test_nested_zip_recursion(self, tmp_path):
        """Scanner must recurse into nested ZIPs."""
        # Inner ZIP containing malicious pickle
        import os

        class E:
            def __reduce__(self):
                return (os.system, ("id",))

        mal_pickle = pickle.dumps(E())

        inner_zip = io.BytesIO()
        with zipfile.ZipFile(inner_zip, "w") as zf:
            zf.writestr("data.pkl", mal_pickle)

        # Outer ZIP containing inner ZIP
        outer = tmp_path / "model.pt"
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("nested.zip", inner_zip.getvalue())

        result = scan_pickle_file(str(outer))
        assert result.risk_level == "malicious"
        # Should report nested archive finding
        assert any("Nested archive" in str(f) for f in result.findings)

    def test_nested_archive_depth_limit(self, tmp_path):
        """Scanner should refuse to recurse beyond MAX_NEST_DEPTH."""
        # Create deeply nested ZIPs
        current = io.BytesIO()
        with zipfile.ZipFile(current, "w") as zf:
            zf.writestr("data.pkl", pickle.dumps({"safe": True}))
        for _ in range(7):  # Exceeds MAX_NEST_DEPTH=5
            outer = io.BytesIO()
            with zipfile.ZipFile(outer, "w") as zf:
                zf.writestr("nested.zip", current.getvalue())
            current = outer

        deep_file = tmp_path / "deep.pt"
        deep_file.write_bytes(current.getvalue())
        result = scan_pickle_file(str(deep_file))
        assert any("nesting" in str(f).lower() or "deep" in str(f).lower() for f in result.findings)


class TestReduceChainDepth:
    """Verify cumulative depth tracking across GLOBAL opcodes."""

    def test_chain_depth_does_not_reset(self):
        """REDUCE depth must accumulate across multiple GLOBALs."""
        # Custom rules with low max_reduce_depth to make test reliable
        rules = {
            "safe_modules": [],
            "dangerous_modules": {"critical": [], "high": [], "medium": []},
            "settings": {
                "max_reduce_depth": 1,
                "unknown_module_risk": "safe",
                "scan_past_stop": True,
                "track_memo": True,
                "allowlist_only_mode": False,
            },
            "dangerous_callables": [],
        }
        # Two GLOBAL+REDUCE chains in one pickle
        # cmodule\nfunc\n)R cmodule2\nfunc2\n)R .
        raw = b"cmodule1\nfunc1\n)Rcmodule2\nfunc2\n)R."
        result = scan_pickle_bytes(raw, rules=rules)
        # Chain depth should be 2, exceeding max=1
        assert any(f.rule_id == "PICKLE004" for f in result.findings)


class TestMemoTracking:
    """MEMOWNED-style indicator: codecs.decode plus memoized names."""

    def test_codecs_decode_detected(self):
        """codecs.decode (used in MEMOWNED to decode UTF-16-LE names)."""
        raw = b"ccodecs\ndecode\n(c__builtin__\nbytes\n)RS'utf-16-le'\ntR."
        result = scan_pickle_bytes(raw)
        # codecs.decode should trigger PICKLE002 (in dangerous_callables)
        assert result.risk_level == "malicious"
        assert any("codecs.decode" in str(f) for f in result.findings)


class TestAllowlistMode:
    """Strict allowlist mode flags anything not on safe list."""

    def test_allowlist_mode_flags_unknown(self):
        """Unknown modules should be flagged in allowlist-only mode."""
        rules = {
            "safe_modules": ["numpy"],
            "dangerous_modules": {"critical": [], "high": [], "medium": []},
            "settings": {
                "max_reduce_depth": 5,
                "unknown_module_risk": "safe",
                "scan_past_stop": True,
                "track_memo": True,
                "allowlist_only_mode": True,
            },  # STRICT
            "dangerous_callables": [],
        }
        # Use an unknown module
        raw = b"crandom_unknown_module\nsome_func\n."
        result = scan_pickle_bytes(raw, rules=rules)
        assert any(f.rule_id == "PICKLE007" for f in result.findings)

    def test_allowlist_mode_passes_safe(self):
        """Safe modules pass in allowlist mode."""
        rules = {
            "safe_modules": ["numpy"],
            "dangerous_modules": {"critical": [], "high": [], "medium": []},
            "settings": {
                "max_reduce_depth": 5,
                "unknown_module_risk": "safe",
                "scan_past_stop": True,
                "track_memo": True,
                "allowlist_only_mode": True,
            },
            "dangerous_callables": [],
        }
        import numpy as np

        data = pickle.dumps(np.array([1.0]))
        result = scan_pickle_bytes(data, rules=rules)
        # numpy is safe in this rule set and should pass.
        assert not any(f.rule_id == "PICKLE007" for f in result.findings)
