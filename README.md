# Model-Supply-Chain-Auditor

![CI](https://github.com/poojakira/Model-Supply-Chain-Auditor/actions/workflows/ci.yml/badge.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![Tests 51](https://img.shields.io/badge/tests-51_passing-green.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

**Detects malicious code in ML model files before they execute.** Static analysis of pickle bytecode + Ed25519 cryptographic model signing + SARIF output for CI/CD.

```
$ msca scan model.pt
[MALICIOUS] model.pt
  - [PICKLE001] Dangerous import: subprocess.Popen (byte 25)
  - [PICKLE002] Code execution via REDUCE (depth 1) (byte 38)
  Scanned: archive/data.pkl
```

---

## Why This Exists

ML models are distributed as serialized files (`.pkl`, `.pt`). Python's pickle format can execute arbitrary code during deserialization — a malicious model achieves Remote Code Execution on the victim's machine.

**Real-world context (2025-2026):**
- 44.9% of HuggingFace models still use pickle format ([arxiv 2508.15987](https://arxiv.org/abs/2508.15987))
- 95% of confirmed malicious models target PyTorch pickle serialization
- 7+ CVEs in pickle scanners (picklescan, Fickling) disclosed in 2025-2026
- PickleScan has documented 89% bypass rate against sophisticated attacks

## Features

| Feature | Description |
|---------|-------------|
| **Pickle scanning** | Detects all 6 code-execution opcodes: GLOBAL, STACK_GLOBAL, REDUCE, INST, OBJ, BUILD |
| **ZIP extraction** | Scans inside `.pt`/`.pth` PyTorch archives (ZIP containing pickle) |
| **Ed25519 signing** | Cryptographic model provenance — sign after scan, verify before load |
| **SafeTensors validation** | Header integrity, tensor bounds, suspicious metadata detection |
| **SARIF output** | Machine-readable results for GitHub Code Scanning and CI/CD pipelines |
| **Configurable rules** | Externalized YAML rules — customize dangerous/safe module lists |
| **Post-STOP detection** | Catches hidden payloads appended after pickle STOP opcode |
| **Chain depth tracking** | Flags suspicious REDUCE chains (depth > 3) |

## Installation

```bash
pip install -e ".[dev]"
```

## Usage

```bash
# Scan a model file
msca scan model.pkl
msca scan model.pt --format json
msca scan model.pt --format sarif --output results.sarif

# Sign a model (Ed25519)
msca sign model.pt --signer "training-pipeline-v1"

# Verify signature before loading
msca verify model.pt --signature model.pt.sig --key model.pt.pub
```

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
│ • ZIP extraction    │ │ SHA-256 hash            │
│ • 6 opcode types    │ │ → Ed25519 sign          │
│ • YAML rules engine │ │ → .sig + .pub files     │
│ • Chain depth       │ │                         │
│ • Post-STOP detect  │ │ Verify before loading:  │
│ • SARIF output      │ │ hash match + sig valid  │
└─────────────────────┘ └─────────────────────────┘
```

## Detection Coverage

Based on documented CVEs and attack research:

| Attack Pattern | Status | Reference |
|---------------|--------|-----------|
| `os.system` / `subprocess.Popen` | ✅ Detected | Standard pickle RCE |
| `nt.system` / `posix.system` | ✅ Detected | Platform-specific variants |
| `builtins.eval` / `builtins.exec` | ✅ Detected | Direct code execution |
| `importlib.import_module` | ✅ Detected | CVE-2025-1716 class |
| `pip.main(['install', 'evil'])` | ✅ Detected | CVE-2025-1716 |
| BUILD state injection | ⚠️ Partial | Suppressed for safe modules |
| Post-STOP hidden payload | ✅ Detected | Appended payload technique |
| REDUCE chain depth > 3 | ⚠️ Flagged | Structural anomaly |
| `typing.ForwardRef` eval | ❌ Not detected | Requires taint analysis |
| Neural backdoors | ❌ Not detected | Requires weight analysis |

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for full threat model.

## Testing

```bash
pytest                    # 51 tests
pytest --cov=src          # With coverage report
make test-cov             # Via Makefile
```

## Project Structure

```
├── src/
│   ├── scanners/
│   │   ├── pickle_scanner.py   # Core scanner (6 opcodes, ZIP, chain depth)
│   │   └── sarif.py            # SARIF v2.1.0 output formatter
│   ├── signing/
│   │   └── model_signer.py     # Ed25519 sign/verify
│   ├── safetensors_scanner.py  # SafeTensors format validator
│   └── cli.py                  # CLI entry point (scan/sign/verify)
├── tests/                      # 51 tests (scanner, signing, SARIF, CLI)
├── rules.yaml                  # Configurable detection rules
├── docs/
│   ├── DESIGN.md               # Engineering decisions
│   └── THREAT_MODEL.md         # What we detect vs. don't
├── SECURITY.md                 # Vulnerability reporting
├── CONTRIBUTING.md             # Development guide
└── Makefile                    # Developer commands
```

## References

1. Trail of Bits, [Fickling](https://github.com/trailofbits/fickling) (2021)
2. OWASP, [LLM05: Supply Chain Vulnerabilities](https://owasp.org/www-project-machine-learning-security-top-10/)
3. Bernstein et al., "High-speed high-security signatures" (2012) — Ed25519
4. HuggingFace, [Pickle Scanning](https://huggingface.co/docs/hub/security-pickle) (2023)
5. Sonatype, [Bypassing picklescan: 4 Vulnerabilities](https://www.sonatype.com/blog/bypassing-picklescan-sonatype-discovers-four-vulnerabilities) (2025)
6. Liu et al., [Making Pickle-Based Model Supply Chain Poisoning Stealthy Again](https://arxiv.org/abs/2508.19774) (2025)

## License

MIT — Pooja Kiran ([@poojakira](https://github.com/poojakira))
