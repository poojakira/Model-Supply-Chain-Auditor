# Threat Model

## Threat Actors

| Actor | Motivation | Capability |
|-------|-----------|------------|
| Malicious model publisher | Distribute backdoored models for RCE | Crafts pickle payloads, uploads to HuggingFace/PyTorch Hub |
| Compromised registry | Inject malware into legitimate model repos | Modifies existing model files, uses leaked API keys |
| Man-in-the-middle | Tamper with models during download | Intercepts HTTP transfers, modifies bytes in transit |
| Supply chain attacker | Poison dependencies of model training pipelines | Compromises upstream packages used during training |

## Attack Vectors

### 1. Pickle RCE via `__reduce__` (GLOBAL + REDUCE)

The most common attack. Attacker defines a class with `__reduce__` returning `(os.system, ("malicious_command",))`. When deserialized, pickle calls the function.

**Opcodes involved:** GLOBAL, STACK_GLOBAL, REDUCE
**Detection:** ✅ Detected — dangerous module/callable matching

### 2. State Injection via BUILD

Attacker uses BUILD opcode to call `__setstate__` on an object, injecting arbitrary state that triggers code execution in subsequent operations.

**Opcodes involved:** BUILD
**Detection:** ⚠️ Partial — flagged for non-safe modules, suppressed for torch/numpy to avoid false positives

### 3. ZIP Archive Evasion (CVE-2025-1944, CVE-2025-1945)

Attacker modifies ZIP headers in .pt files to crash scanners while PyTorch's more forgiving ZIP implementation still loads the file.

**Opcodes involved:** N/A (format-level attack)
**Detection:** ⚠️ Partial — malformed ZIPs reported as errors, not silently passed

### 4. Post-STOP Hidden Payloads

Attacker appends a second pickle stream after the STOP opcode. If the loading code calls `pickle.load()` multiple times, the hidden payload executes.

**Opcodes involved:** Any opcodes after STOP
**Detection:** ✅ Detected — scanner continues past STOP

### 5. Indirect Import Chains (CVE-2025-1716)

Attacker uses `pip.main(['install', 'evil-package'])` or `importlib.import_module("os")` — functions not on traditional denylists.

**Opcodes involved:** GLOBAL/STACK_GLOBAL with non-obvious callables
**Detection:** ✅ Detected — `pip.main` and `importlib.import_module` are in dangerous_callables

## Detection Matrix

| Attack Pattern | Detected | Confidence |
|---------------|----------|------------|
| Direct `os.system` / `subprocess.Popen` | ✅ Yes | High |
| `nt.system` / `posix.system` (platform-specific) | ✅ Yes | High |
| `builtins.eval` / `builtins.exec` | ✅ Yes | High |
| `importlib.import_module` | ✅ Yes | High |
| `pip.main` (CVE-2025-1716) | ✅ Yes | High |
| BUILD with non-safe module | ⚠️ Partial | Medium |
| REDUCE chain depth > 3 | ⚠️ Flagged | Medium |
| Post-STOP payload | ✅ Yes | High |
| `typing.ForwardRef` eval bypass | ❌ No | — |
| `operator.attrgetter` chains | ❌ No | — |
| Character-by-character string construction | ❌ No | — |
| Neural backdoors (poisoned weights) | ❌ No | — |
| Gadgets within allowlisted functions | ❌ No | — |

## Mitigations

1. **Use SafeTensors** — eliminates pickle RCE entirely for new models
2. **Combine with Fickling runtime hook** — catches attacks at load time
3. **Verify signatures** — Ed25519 signing ensures model integrity
4. **Scan before loading** — this tool as a CI/CD gate

## CVE References

| CVE | Tool Affected | Technique | Our Status |
|-----|--------------|-----------|------------|
| CVE-2025-1716 | picklescan | `pip.main()` bypass | ✅ Detected |
| CVE-2025-1889 | picklescan | Hidden file extension bypass | ⚠️ Partial (ZIP extraction) |
| CVE-2025-1944 | picklescan | ZIP filename tampering | ⚠️ Reports as error |
| CVE-2025-1945 | picklescan | ZIP flag bit modification | ⚠️ Reports as error |
| CVE-2026-22612 | Fickling | builtins blindness | ✅ Detected (builtins in denylist) |
