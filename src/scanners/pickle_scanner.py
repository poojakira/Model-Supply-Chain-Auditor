"""Pickle Malware Scanner.

Scans Python pickle files for malicious payloads by disassembling
the pickle bytecode and detecting dangerous operations.

Detection covers all 6 code-execution opcodes in the pickle VM:
- GLOBAL / STACK_GLOBAL: import a module.callable
- REDUCE: call a callable with arguments
- INST: import + instantiate in one opcode (protocol 0)
- OBJ: call class from stack (protocol 1)
- BUILD: call __setstate__ or update __dict__
- NEWOBJ / NEWOBJ_EX: call cls.__new__ (protocol 2+)

References:
- Python pickletools source (cpython/Lib/pickletools.py)
- Trail of Bits Fickling (2021)
- "Stealthy Again" arxiv 2508.19774 (2025)
- Sonatype CVE-2025-1716 (pip.main bypass)
"""
from __future__ import annotations

import io
import pickletools
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Finding:
    """A single security finding from pickle analysis."""

    rule_id: str
    severity: str  # "critical", "high", "medium", "low", "info"
    message: str
    byte_offset: int

    def __str__(self) -> str:
        return f"[{self.rule_id}] {self.message} (byte {self.byte_offset})"


@dataclass
class PickleScanResult:
    """Result of scanning a pickle file or archive."""

    is_malicious: bool
    risk_level: str  # "safe", "suspicious", "malicious", "error"
    findings: list[Finding] = field(default_factory=list)
    dangerous_imports: list[str] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)

    @property
    def finding_strings(self) -> list[str]:
        """Backward-compatible string list of findings."""
        return [str(f) for f in self.findings]


def _load_rules(rules_path: Path | None = None) -> dict[str, Any]:
    """Load scanning rules from YAML file."""
    if rules_path is None:
        rules_path = Path(__file__).parent.parent.parent / "rules.yaml"
    if rules_path.exists():
        with open(rules_path) as f:
            return yaml.safe_load(f)
    # Fallback: minimal hardcoded rules if YAML not found
    return {
        "settings": {"max_reduce_depth": 3, "unknown_module_risk": "suspicious", "scan_past_stop": True},
        "safe_modules": ["torch", "numpy", "sklearn", "collections", "copyreg", "_codecs"],
        "dangerous_modules": {
            "critical": ["os", "nt", "posix", "subprocess", "builtins"],
            "high": ["sys", "shutil", "socket", "importlib", "ctypes"],
            "medium": [],
        },
        "dangerous_callables": ["os.system", "subprocess.Popen", "builtins.eval", "builtins.exec"],
    }


def _classify_module(module: str, rules: dict[str, Any]) -> tuple[str, str]:
    """Classify a module as safe/dangerous and return (risk_level, severity).

    Returns:
        ("safe", "") if module is allowlisted
        ("dangerous", severity) if module is on dangerous list
        (unknown_risk, "medium") if module is unknown
    """
    safe = rules.get("safe_modules", [])
    dangerous = rules.get("dangerous_modules", {})

    # Check safe list (prefix match: "torch.nn.modules.conv" matches "torch.nn.modules")
    for safe_mod in safe:
        if module == safe_mod or module.startswith(safe_mod + "."):
            return ("safe", "")

    # Check dangerous lists by severity
    for severity in ("critical", "high", "medium"):
        for dmod in dangerous.get(severity, []):
            if module == dmod or module.startswith(dmod + "."):
                return ("dangerous", severity)

    # Unknown module
    unknown_risk = rules.get("settings", {}).get("unknown_module_risk", "suspicious")
    return (unknown_risk, "medium")


def scan_pickle_bytes(data: bytes, rules: dict[str, Any] | None = None) -> PickleScanResult:
    """Scan pickle bytecode for malicious operations.

    Args:
        data: Raw pickle bytes
        rules: Loaded rules dict (loads default if None)

    Returns:
        PickleScanResult with security assessment
    """
    if rules is None:
        rules = _load_rules()

    findings: list[Finding] = []
    dangerous_imports: list[str] = []
    settings = rules.get("settings", {})
    max_reduce_depth = settings.get("max_reduce_depth", 3)
    scan_past_stop = settings.get("scan_past_stop", True)
    dangerous_callables = set(rules.get("dangerous_callables", []))

    try:
        ops = list(pickletools.genops(data))
    except Exception as e:
        return PickleScanResult(
            is_malicious=False,
            risk_level="error",
            findings=[Finding("PICKLE000", "info", f"Failed to parse pickle: {e}", 0)],
        )

    # Post-STOP detection: pickletools.genops() stops at STOP opcode,
    # so we check for additional data after the last parsed position.
    if scan_past_stop and ops:
        last_opcode, last_arg, last_pos = ops[-1]
        # STOP is 1 byte, no argument
        end_of_parsed = last_pos + 1
        if end_of_parsed < len(data):
            remaining = data[end_of_parsed:]
            # Check if remaining bytes could be another pickle stream
            if len(remaining) >= 2 and (remaining[0] == 0x80 or remaining[0:1] in (b"(", b"}")):
                findings.append(Finding(
                    "PICKLE005", "critical",
                    f"Data after STOP opcode at byte {end_of_parsed} ({len(remaining)} bytes — possible hidden payload)",
                    end_of_parsed,
                ))

    # State tracking
    stack_strings: list[str] = []
    reduce_depth = 0
    last_imported_module = ""

    for opcode, arg, pos in ops:
        op_name = opcode.name

        if op_name == "STOP":
            continue

        # Track string values pushed to stack
        if op_name in ("SHORT_BINUNICODE", "BINUNICODE", "SHORT_BINSTRING", "BINSTRING"):
            if isinstance(arg, str):
                stack_strings.append(arg)

        # --- GLOBAL opcode (protocol 0-2): pickletools returns "module name" (space-separated) ---
        if op_name == "GLOBAL" and isinstance(arg, str):
            parts = arg.split()
            module = parts[0] if parts else ""
            name = parts[1] if len(parts) > 1 else ""
            callable_name = f"{module}.{name}"
            last_imported_module = module

            risk, severity = _classify_module(module, rules)
            if risk == "dangerous":
                findings.append(Finding(
                    "PICKLE001", severity,
                    f"Dangerous import: {callable_name}", pos,
                ))
                dangerous_imports.append(callable_name)
            if callable_name in dangerous_callables:
                findings.append(Finding(
                    "PICKLE002", "critical",
                    f"Malicious callable: {callable_name}", pos,
                ))
                dangerous_imports.append(callable_name)

        # --- STACK_GLOBAL (protocol 4+): module and name on stack ---
        if op_name == "STACK_GLOBAL" and len(stack_strings) >= 2:
            module = stack_strings[-2]
            name = stack_strings[-1]
            callable_name = f"{module}.{name}"
            last_imported_module = module

            risk, severity = _classify_module(module, rules)
            if risk == "dangerous":
                findings.append(Finding(
                    "PICKLE001", severity,
                    f"Dangerous import: {callable_name}", pos,
                ))
                dangerous_imports.append(callable_name)
            if callable_name in dangerous_callables:
                findings.append(Finding(
                    "PICKLE002", "critical",
                    f"Malicious callable: {callable_name}", pos,
                ))
                dangerous_imports.append(callable_name)

        # --- INST opcode (protocol 0): import + instantiate ---
        # pickletools returns arg as "module name" (space-separated)
        if op_name == "INST" and isinstance(arg, str):
            parts = arg.split()
            module = parts[0] if parts else ""
            name = parts[1] if len(parts) > 1 else ""
            callable_name = f"{module}.{name}"
            last_imported_module = module

            risk, severity = _classify_module(module, rules)
            if risk == "dangerous":
                findings.append(Finding(
                    "PICKLE001", severity,
                    f"Dangerous import via INST: {callable_name}", pos,
                ))
                dangerous_imports.append(callable_name)

        # --- REDUCE: call a callable ---
        if op_name == "REDUCE":
            reduce_depth += 1
            if dangerous_imports:
                findings.append(Finding(
                    "PICKLE002", "critical",
                    f"Code execution via REDUCE (depth {reduce_depth})", pos,
                ))
            if reduce_depth > max_reduce_depth:
                findings.append(Finding(
                    "PICKLE004", "high",
                    f"Suspicious REDUCE chain depth: {reduce_depth} (max {max_reduce_depth})", pos,
                ))

        # --- OBJ opcode: call class from stack ---
        if op_name == "OBJ":
            if dangerous_imports:
                findings.append(Finding(
                    "PICKLE002", "critical",
                    f"Code execution via OBJ opcode", pos,
                ))

        # --- NEWOBJ / NEWOBJ_EX: call cls.__new__ ---
        if op_name in ("NEWOBJ", "NEWOBJ_EX"):
            if dangerous_imports:
                findings.append(Finding(
                    "PICKLE002", "critical",
                    f"Code execution via {op_name}", pos,
                ))

        # --- BUILD: calls __setstate__ or updates __dict__ ---
        if op_name == "BUILD":
            risk, _ = _classify_module(last_imported_module, rules)
            if risk != "safe":
                findings.append(Finding(
                    "PICKLE003", "high",
                    f"State injection via BUILD (module: {last_imported_module})", pos,
                ))

        # Reset state on stack-consuming operations
        if op_name in ("REDUCE", "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3",
                       "LIST", "DICT", "MARK", "INST", "OBJ"):
            stack_strings = []

        # Reset reduce depth on non-REDUCE operations that indicate new call chain
        if op_name in ("GLOBAL", "STACK_GLOBAL", "INST") and reduce_depth > 0:
            reduce_depth = 0

    # Determine risk level from findings
    severities = [f.severity for f in findings]
    if "critical" in severities:
        risk_level = "malicious"
    elif "high" in severities:
        risk_level = "suspicious"
    elif "medium" in severities:
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    return PickleScanResult(
        is_malicious=risk_level == "malicious",
        risk_level=risk_level,
        findings=findings,
        dangerous_imports=dangerous_imports,
    )


def scan_pickle_file(filepath: str, rules: dict[str, Any] | None = None) -> PickleScanResult:
    """Scan a pickle file from disk. Handles .pt/.pth ZIP archives."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    data = path.read_bytes()

    # Detect ZIP archive (PyTorch .pt/.pth/.ckpt files)
    if data[:4] == b"PK\x03\x04":
        return _scan_zip_archive(path, data, rules)

    return scan_pickle_bytes(data, rules)


def _scan_zip_archive(path: Path, data: bytes, rules: dict[str, Any] | None) -> PickleScanResult:
    """Extract and scan pickle files from a ZIP archive (PyTorch format)."""
    all_findings: list[Finding] = []
    all_imports: list[str] = []
    scanned: list[str] = []

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for entry in zf.namelist():
                # Scan entries that are pickle files
                entry_lower = entry.lower()
                if any(entry_lower.endswith(ext) for ext in (".pkl", ".pickle", ".joblib", ".data")):
                    pkl_data = zf.read(entry)
                    result = scan_pickle_bytes(pkl_data, rules)
                    scanned.append(entry)
                    all_findings.extend(result.findings)
                    all_imports.extend(result.dangerous_imports)
                elif not any(entry_lower.endswith(ext) for ext in (".json", ".txt")) and "/" not in entry:
                    # Check if entry has pickle magic bytes
                    pkl_data = zf.read(entry)
                    if len(pkl_data) >= 2 and pkl_data[0] == 0x80 and pkl_data[1] <= 5:
                        result = scan_pickle_bytes(pkl_data, rules)
                        scanned.append(entry)
                        all_findings.extend(result.findings)
                        all_imports.extend(result.dangerous_imports)
    except zipfile.BadZipFile:
        return PickleScanResult(
            is_malicious=False,
            risk_level="error",
            findings=[Finding("PICKLE000", "info", "Malformed ZIP archive", 0)],
            scanned_files=[str(path)],
        )

    severities = [f.severity for f in all_findings]
    if "critical" in severities:
        risk_level = "malicious"
    elif "high" in severities or "medium" in severities:
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    return PickleScanResult(
        is_malicious=risk_level == "malicious",
        risk_level=risk_level,
        findings=all_findings,
        dangerous_imports=all_imports,
        scanned_files=scanned,
    )
