"""Pickle malware scanner.

Detects malicious pickles using:
- Curated denylist of documented dangerous callables
- Memo tracking for MEMOWNED desync attack detection
- REDUCE chain depth tracking (cumulative across pickle)
- Post-STOP payload detection
- Nested archive recursion
- Allowlist mode for strict environments

References:
- https://arxiv.org/abs/2508.19774
- https://www.sonatype.com/security-advisories/cve-2025-1716
- https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10155/
- https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10156/
- https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10157/
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
    risk_level: str
    findings: list[Finding] = field(default_factory=list)
    dangerous_imports: list[str] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)

    @property
    def finding_strings(self) -> list[str]:
        return [str(f) for f in self.findings]


def _load_rules(rules_path: Path | None = None) -> dict[str, Any]:
    """Load scanning rules from YAML file."""
    if rules_path is None:
        rules_path = Path(__file__).parent.parent.parent / "rules.yaml"
    if rules_path.exists():
        with open(rules_path) as f:
            return yaml.safe_load(f)
    return {
        "settings": {
            "max_reduce_depth": 5,
            "unknown_module_risk": "suspicious",
            "scan_past_stop": True,
            "track_memo": True,
            "allowlist_only_mode": False,
        },
        "safe_modules": ["torch", "numpy.core.multiarray", "collections", "copyreg"],
        "dangerous_modules": {
            "critical": ["os", "nt", "posix", "subprocess", "builtins"],
            "high": ["sys", "importlib", "ctypes"],
            "medium": [],
        },
        "dangerous_callables": [
            "os.system",
            "subprocess.Popen",
            "builtins.eval",
            "builtins.exec",
            "typing.ForwardRef",
            "operator.methodcaller",
            "codecs.decode",
        ],
    }


def _classify_module(module: str, rules: dict[str, Any]) -> tuple[str, str]:
    """Return (risk_level, severity) for a module."""
    safe = rules.get("safe_modules", [])
    dangerous = rules.get("dangerous_modules", {})

    for safe_mod in safe:
        if module == safe_mod or module.startswith(safe_mod + "."):
            return ("safe", "")

    for severity in ("critical", "high", "medium"):
        for dmod in dangerous.get(severity, []):
            if module == dmod or module.startswith(dmod + "."):
                return ("dangerous", severity)

    unknown_risk = rules.get("settings", {}).get("unknown_module_risk", "suspicious")
    return (unknown_risk, "medium")


def scan_pickle_bytes(data: bytes, rules: dict[str, Any] | None = None) -> PickleScanResult:
    """Scan pickle bytecode for malicious operations.

    Tracks memo (PUT/GET) to detect MEMOWNED-style desync attacks.
    REDUCE chain depth is cumulative across the entire pickle (not reset on new GLOBAL).
    """
    if rules is None:
        rules = _load_rules()

    findings: list[Finding] = []
    dangerous_imports: list[str] = []
    settings = rules.get("settings", {})
    max_reduce_depth = settings.get("max_reduce_depth", 5)
    scan_past_stop = settings.get("scan_past_stop", True)
    track_memo = settings.get("track_memo", True)
    allowlist_only = settings.get("allowlist_only_mode", False)
    dangerous_callables = set(rules.get("dangerous_callables", []))

    try:
        ops = list(pickletools.genops(data))
    except Exception as e:
        return PickleScanResult(
            is_malicious=False,
            risk_level="error",
            findings=[Finding("PICKLE000", "info", f"Failed to parse pickle: {e}", 0)],
        )

    # Post-STOP detection
    if scan_past_stop and ops:
        _, _, last_pos = ops[-1]
        end_of_parsed = last_pos + 1
        if end_of_parsed < len(data):
            remaining = data[end_of_parsed:]
            if len(remaining) >= 2 and (
                remaining[0] == 0x80 or remaining[0:1] in (b"(", b"}", b"]")
            ):
                findings.append(
                    Finding(
                        "PICKLE005",
                        "critical",
                        f"Data after STOP at byte {end_of_parsed} ({len(remaining)} bytes — hidden payload)",
                        end_of_parsed,
                    )
                )

    # State tracking
    stack_strings: list[str] = []
    memo: dict[int, Any] = {}  # MEMOWNED detection: track memo values
    reduce_depth = 0  # Cumulative across pickle (not reset on new GLOBAL)
    last_imported_module = ""
    codecs_decode_used = False  # MEMOWNED indicator

    def _check_callable(module: str, name: str, pos: int, op_source: str) -> None:
        """Check a resolved callable against denylist/allowlist."""
        nonlocal codecs_decode_used
        callable_name = f"{module}.{name}"

        if callable_name == "codecs.decode" or callable_name == "_codecs.decode":
            codecs_decode_used = True

        # Allowlist mode: flag anything not in safe_modules (independent of risk classification)
        if allowlist_only:
            safe = rules.get("safe_modules", [])
            is_safe = any(module == s or module.startswith(s + ".") for s in safe)
            if not is_safe:
                findings.append(
                    Finding(
                        "PICKLE007",
                        "medium",
                        f"Non-allowlisted import via {op_source}: {callable_name}",
                        pos,
                    )
                )
                dangerous_imports.append(callable_name)

        risk, severity = _classify_module(module, rules)
        if risk == "dangerous":
            findings.append(
                Finding(
                    "PICKLE001",
                    severity,
                    f"Dangerous import via {op_source}: {callable_name}",
                    pos,
                )
            )
            dangerous_imports.append(callable_name)

        if callable_name in dangerous_callables:
            findings.append(
                Finding(
                    "PICKLE002",
                    "critical",
                    f"Malicious callable: {callable_name}",
                    pos,
                )
            )
            dangerous_imports.append(callable_name)

    for opcode, arg, pos in ops:
        op_name = opcode.name

        if op_name == "STOP":
            continue

        # Track strings pushed to stack
        if op_name in (
            "SHORT_BINUNICODE",
            "BINUNICODE",
            "SHORT_BINSTRING",
            "BINSTRING",
            "STRING",
            "UNICODE",
        ):
            if isinstance(arg, str):
                stack_strings.append(arg)

        # === Memo tracking (MEMOWNED detection) ===
        if track_memo:
            if op_name in ("BINPUT", "LONG_BINPUT", "PUT") and isinstance(arg, int):
                # Store top of stack in memo
                memo[arg] = stack_strings[-1] if stack_strings else None
            elif op_name == "MEMOIZE":
                memo[len(memo)] = stack_strings[-1] if stack_strings else None
            elif op_name in ("BINGET", "LONG_BINGET", "GET") and isinstance(arg, int):
                # Retrieve from memo and push (preserving for STACK_GLOBAL)
                if arg in memo and memo[arg] is not None:
                    stack_strings.append(memo[arg])

        # === GLOBAL (protocol 0-2) ===
        if op_name == "GLOBAL" and isinstance(arg, str):
            parts = arg.split()
            module = parts[0] if parts else ""
            name = parts[1] if len(parts) > 1 else ""
            last_imported_module = module
            _check_callable(module, name, pos, "GLOBAL")

        # === STACK_GLOBAL (protocol 4+) ===
        if op_name == "STACK_GLOBAL" and len(stack_strings) >= 2:
            module = stack_strings[-2]
            name = stack_strings[-1]
            last_imported_module = module
            _check_callable(module, name, pos, "STACK_GLOBAL")

            # MEMOWNED detection: if codecs.decode was used to construct names,
            # and STACK_GLOBAL pulls from memo, that's the attack signature
            if codecs_decode_used and track_memo:
                findings.append(
                    Finding(
                        "PICKLE006",
                        "critical",
                        "MEMOWNED-style attack: STACK_GLOBAL after codecs.decode (memo desync)",
                        pos,
                    )
                )

        # === INST (protocol 0) ===
        if op_name == "INST" and isinstance(arg, str):
            parts = arg.split()
            module = parts[0] if parts else ""
            name = parts[1] if len(parts) > 1 else ""
            last_imported_module = module
            _check_callable(module, name, pos, "INST")

        # === REDUCE ===
        if op_name == "REDUCE":
            reduce_depth += 1  # CUMULATIVE — does not reset on new GLOBAL
            if dangerous_imports:
                findings.append(
                    Finding(
                        "PICKLE002",
                        "critical",
                        f"Code execution via REDUCE (chain depth {reduce_depth})",
                        pos,
                    )
                )
            if reduce_depth > max_reduce_depth:
                findings.append(
                    Finding(
                        "PICKLE004",
                        "high",
                        f"Suspicious REDUCE chain depth: {reduce_depth} (max {max_reduce_depth})",
                        pos,
                    )
                )

        # === OBJ ===
        if op_name == "OBJ" and dangerous_imports:
            findings.append(
                Finding(
                    "PICKLE002",
                    "critical",
                    "Code execution via OBJ opcode",
                    pos,
                )
            )

        # === NEWOBJ / NEWOBJ_EX ===
        if op_name in ("NEWOBJ", "NEWOBJ_EX") and dangerous_imports:
            findings.append(
                Finding(
                    "PICKLE002",
                    "critical",
                    f"Code execution via {op_name}",
                    pos,
                )
            )

        # === BUILD ===
        if op_name == "BUILD":
            risk, _ = _classify_module(last_imported_module, rules)
            if risk != "safe":
                findings.append(
                    Finding(
                        "PICKLE003",
                        "high",
                        f"State injection via BUILD (module: {last_imported_module})",
                        pos,
                    )
                )

        # Reset stack_strings on stack-consuming ops
        if op_name in (
            "REDUCE",
            "TUPLE",
            "TUPLE1",
            "TUPLE2",
            "TUPLE3",
            "LIST",
            "DICT",
            "MARK",
            "INST",
            "OBJ",
            "NEWOBJ",
            "NEWOBJ_EX",
        ):
            stack_strings = []

    # Determine risk level
    severities = [f.severity for f in findings]
    if "critical" in severities:
        risk_level = "malicious"
    elif "high" in severities or "medium" in severities:
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
    """Scan a pickle file from disk. Handles .pt/.pth ZIP archives (including nested)."""
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    data = path.read_bytes()

    if data[:4] == b"PK\x03\x04":
        return _scan_zip_archive(path, data, rules, depth=0)

    return scan_pickle_bytes(data, rules)


def _scan_zip_archive(
    path: Path, data: bytes, rules: dict[str, Any] | None, depth: int = 0
) -> PickleScanResult:
    """Extract and scan pickle files from ZIP archive. Recurses into nested archives."""
    all_findings: list[Finding] = []
    all_imports: list[str] = []
    scanned: list[str] = []
    max_nest_depth = 5

    if depth > max_nest_depth:
        return PickleScanResult(
            is_malicious=False,
            risk_level="error",
            findings=[
                Finding("PICKLE008", "high", f"Archive nesting too deep ({depth} levels)", 0)
            ],
            scanned_files=[str(path)],
        )

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for entry in zf.namelist():
                entry_lower = entry.lower()
                pkl_data = zf.read(entry)

                # Recurse into nested ZIPs
                if pkl_data[:4] == b"PK\x03\x04":
                    all_findings.append(
                        Finding(
                            "PICKLE009",
                            "medium",
                            f"Nested archive at depth {depth + 1}: {entry}",
                            0,
                        )
                    )
                    nested = _scan_zip_archive(path, pkl_data, rules, depth + 1)
                    scanned.extend(f"{entry}/{n}" for n in nested.scanned_files)
                    all_findings.extend(nested.findings)
                    all_imports.extend(nested.dangerous_imports)
                    continue

                # Direct pickle by extension
                if any(
                    entry_lower.endswith(ext) for ext in (".pkl", ".pickle", ".joblib", ".data")
                ):
                    result = scan_pickle_bytes(pkl_data, rules)
                    scanned.append(entry)
                    all_findings.extend(result.findings)
                    all_imports.extend(result.dangerous_imports)
                # Pickle by magic byte detection
                elif (
                    not any(entry_lower.endswith(ext) for ext in (".json", ".txt"))
                    and len(pkl_data) >= 2
                    and pkl_data[0] == 0x80
                    and pkl_data[1] <= 5
                ):
                    result = scan_pickle_bytes(pkl_data, rules)
                    scanned.append(entry)
                    all_findings.extend(result.findings)
                    all_imports.extend(result.dangerous_imports)
    except zipfile.BadZipFile:
        return PickleScanResult(
            is_malicious=False,
            risk_level="error",
            findings=[
                Finding(
                    "PICKLE000",
                    "info",
                    "Malformed ZIP archive (possible CVE-2025-10156 evasion)",
                    0,
                )
            ],
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
