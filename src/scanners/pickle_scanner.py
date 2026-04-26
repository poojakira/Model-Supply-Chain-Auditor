"""
Pickle Malware Scanner

Scans Python pickle files for malicious payloads by disassembling
the pickle bytecode and detecting dangerous operations.

Background: Python's pickle module can execute arbitrary code during
deserialization via __reduce__. This is a known supply chain attack
vector for ML models distributed as .pkl/.pt files.

Real-world incidents:
- HuggingFace model repos found with malicious pickles (2023)
- PyTorch model files (.pt) are ZIP archives containing pickles
- Backdoored models distributed via model hubs

Detection method: Parse pickle opcodes and flag:
- REDUCE/GLOBAL opcodes that invoke dangerous modules (os, subprocess, etc.)
- STACK_GLOBAL with dangerous callables
- Nested function calls that could execute shell commands
"""
import pickle
import pickletools
import io
from dataclasses import dataclass, field


@dataclass
class PickleScanResult:
    is_malicious: bool
    risk_level: str  # "safe", "suspicious", "malicious"
    findings: list = field(default_factory=list)
    dangerous_imports: list = field(default_factory=list)


# Modules that should NEVER appear in a legitimate ML model pickle
DANGEROUS_MODULES = {
    "os", "subprocess", "sys", "shutil", "socket", "http",
    "urllib", "requests", "ftplib", "smtplib", "ctypes",
    "importlib", "runpy", "code", "codeop", "compile",
    "exec", "eval", "builtins", "pty", "commands",
    "webbrowser", "antigravity",
    "nt", "posix",  # os.system resolves to nt.system (Windows) or posix (Linux)
}

# Dangerous callables that indicate code execution
DANGEROUS_CALLABLES = {
    "os.system", "os.popen", "os.exec", "os.execl", "os.execle",
    "os.execv", "os.execve", "os.execvp", "os.execvpe",
    "os.spawn", "os.spawnl", "os.spawnle",
    "subprocess.call", "subprocess.run", "subprocess.Popen",
    "subprocess.check_output", "subprocess.check_call",
    "eval", "exec", "compile",
    "builtins.eval", "builtins.exec", "builtins.__import__",
    "webbrowser.open", "ctypes.CDLL",
}

# Legitimate modules expected in ML model pickles
SAFE_MODULES = {
    "torch", "numpy", "sklearn", "collections", "copy",
    "torch.nn", "torch._utils", "torch.nn.modules",
    "_codecs", "copyreg", "array",
}


def scan_pickle_bytes(data: bytes) -> PickleScanResult:
    """
    Scan pickle bytecode for malicious operations.

    Args:
        data: Raw pickle bytes

    Returns:
        PickleScanResult with security assessment
    """
    findings = []
    dangerous_imports = []

    try:
        # Disassemble pickle opcodes
        ops = []
        for opcode, arg, pos in pickletools.genops(data):
            ops.append((opcode.name, arg, pos))
    except Exception as e:
        return PickleScanResult(
            is_malicious=False,
            risk_level="error",
            findings=[f"Failed to parse pickle: {e}"],
        )

    # Analyze opcodes - track stack for STACK_GLOBAL pattern (protocol 4+)
    stack_strings = []  # Track recent string pushes

    for op_name, arg, pos in ops:
        # Track string values pushed to stack
        if op_name in ("SHORT_BINUNICODE", "BINUNICODE", "SHORT_BINSTRING", "BINSTRING"):
            stack_strings.append(arg)

        # GLOBAL opcode (protocol 0-2): "module\nname" format
        if op_name == "GLOBAL" and isinstance(arg, str):
            parts = arg.split("\n")
            module = parts[0]
            callable_name = ".".join(parts)

            if module in DANGEROUS_MODULES:
                findings.append(f"DANGEROUS import at byte {pos}: {arg}")
                dangerous_imports.append(callable_name)
            if callable_name in DANGEROUS_CALLABLES:
                findings.append(f"MALICIOUS callable at byte {pos}: {callable_name}")
                dangerous_imports.append(callable_name)

        # STACK_GLOBAL (protocol 4+): module and name are on stack
        if op_name == "STACK_GLOBAL" and len(stack_strings) >= 2:
            module = stack_strings[-2]
            name = stack_strings[-1]
            callable_name = f"{module}.{name}"

            if module in DANGEROUS_MODULES:
                findings.append(f"DANGEROUS import at byte {pos}: {callable_name}")
                dangerous_imports.append(callable_name)
            if callable_name in DANGEROUS_CALLABLES:
                findings.append(f"MALICIOUS callable at byte {pos}: {callable_name}")
                dangerous_imports.append(callable_name)

        # REDUCE executes a callable
        if op_name == "REDUCE" and dangerous_imports:
            findings.append(f"Code execution via REDUCE at byte {pos}")

        # Clear stack tracking on operations that consume stack
        if op_name in ("REDUCE", "TUPLE", "TUPLE1", "TUPLE2", "TUPLE3",
                       "LIST", "DICT", "MARK"):
            stack_strings = []

    # Determine risk level
    if any("MALICIOUS" in f for f in findings):
        risk_level = "malicious"
    elif any("DANGEROUS" in f for f in findings):
        risk_level = "suspicious"
    else:
        risk_level = "safe"

    return PickleScanResult(
        is_malicious=risk_level == "malicious",
        risk_level=risk_level,
        findings=findings,
        dangerous_imports=dangerous_imports,
    )


def scan_pickle_file(filepath: str) -> PickleScanResult:
    """Scan a pickle file from disk."""
    with open(filepath, "rb") as f:
        data = f.read()
    return scan_pickle_bytes(data)
