# Model-Supply-Chain-Auditor

![CI](https://github.com/poojakira/Model-Supply-Chain-Auditor/actions/workflows/ci.yml/badge.svg)
![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)

**Detects executable payloads in ML model artifacts before they are loaded.** Static pickle bytecode analysis, SafeTensors validation, Ed25519 model signing, and SARIF output for CI/CD.

```text
$ msca scan model.pt
[MALICIOUS] model.pt
  - [PICKLE001] Dangerous import via GLOBAL: subprocess.Popen (byte 25)
  - [PICKLE002] Code execution via REDUCE (chain depth 1) (byte 38)
  Scanned: archive/data.pkl
```

## Why This Exists

ML model files are supply-chain artifacts. Pickle-backed formats such as `.pkl`, `.pt`, `.pth`, and some `.joblib` files can execute Python code during deserialization.

Verified public context:

| Claim | Source |
|-------|--------|
| 44.9% of popular Hugging Face models in the PickleBall dataset used pickle-backed formats | [PickleBall, arXiv:2508.15987](https://arxiv.org/abs/2508.15987) |
| The 2025 "Stealthy Again" paper reports 133 exploitable pickle gadgets and an 89% bypass rate against its best-performing evaluated scanner | [arXiv:2508.19774](https://arxiv.org/abs/2508.19774) |
| `pip.main()` was assigned CVE-2025-1716 as a picklescan unsafe-global bypass | [Sonatype advisory](https://www.sonatype.com/security-advisories/cve-2025-1716) |
| JFrog disclosed picklescan bypasses for extension mismatch, bad ZIP CRC, and unsafe submodule globals | [CVE-2025-10155](https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10155/), [CVE-2025-10156](https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10156/), [CVE-2025-10157](https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10157/) |

## Features

| Feature | Description |
|---------|-------------|
| Pickle scanning | Detects dangerous imports/callables and code-execution opcodes including GLOBAL, STACK_GLOBAL, REDUCE, INST, OBJ, BUILD, NEWOBJ, and NEWOBJ_EX |
| Archive extraction | Scans pickle payloads inside PyTorch ZIP archives, including nested ZIP archives |
| SafeTensors validation | Checks header integrity, tensor bounds, and suspicious metadata |
| Ed25519 signing | Signs model hashes and emits public keys for verification; CLI does not write private keys by default |
| Provenance gate | Generates SLSA-style provenance and evaluates signer, builder, source, age, and material policy before promotion |
| SARIF output | Produces GitHub Code Scanning-compatible SARIF v2.1.0 |
| Configurable rules | Uses external YAML rules for safe modules, dangerous modules, and dangerous callables |
| Post-STOP detection | Flags likely hidden payloads after pickle STOP |
| Allowlist mode | Optional strict mode for environments that only permit known-safe modules |

## Usage

```bash
# Scan a model file
msca scan model.pkl
msca scan model.pt --format json
msca scan model.pt --format sarif --output results.sarif

# Sign with an ephemeral Ed25519 key; private key is not written
msca sign model.pt --signer "training-pipeline-v1"

# Sign with an existing PEM private key
msca sign model.pt --key signing.pem --signer "training-pipeline-v1"

# Sign with an encrypted PEM private key
MSCA_KEY_PASSPHRASE="..." msca sign model.pt --key signing.pem

# Verify signature before loading
msca verify model.pt --signature model.pt.sig --key model.pub

# Generate provenance and enforce promotion policy
msca attest model.pt \
  --builder-id github-actions://poojakira/model-release \
  --source-repo https://github.com/poojakira/Model-Supply-Chain-Auditor \
  --source-ref refs/heads/main \
  --run-id "$GITHUB_RUN_ID" \
  --material training-data=data/train.csv \
  --output model.provenance.json

msca policy model.pt \
  --signature model.pt.sig \
  --key model.pub \
  --provenance model.provenance.json \
  --policy docs/policy.example.yaml
```

## Detection Coverage

| Attack Pattern | Status | Reference |
|----------------|--------|-----------|
| `os.system` / `subprocess.Popen` | Detected | Standard pickle RCE |
| `nt.system` / `posix.system` | Detected | Platform-specific variants |
| `builtins.eval` / `builtins.exec` | Detected | Direct code execution |
| `pip.main(['install', 'evil'])` | Detected | CVE-2025-1716 |
| `typing.ForwardRef` / `typing._eval_type` | Detected by callable denylist | Public bypass research |
| `operator.methodcaller` / `operator.attrgetter` | Detected by callable denylist | Public bypass research |
| Nested ZIP containing pickle | Detected recursively | Archive evasion class |
| Post-STOP hidden payload | Detected heuristically | Appended payload technique |
| REDUCE chain depth above configured threshold | Flagged | Structural anomaly |
| Neural backdoors in weights | Out of scope | Requires model-behavior/weight analysis |

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for threat boundaries and framework mapping.
See [docs/POLICY_GATE.md](docs/POLICY_GATE.md) for the release-gate architecture and Mermaid diagram.

## Testing

```bash
python -m pytest
python -m pytest --cov=src --cov-report=term-missing
ruff check src/ tests/
ruff format --check src/ tests/
```

## Project Structure

```text
src/
  scanners/
    pickle_scanner.py      # Pickle bytecode/archive scanner
    sarif.py               # SARIF v2.1.0 formatter
  signing/
    model_signer.py        # Ed25519 sign/verify
  provenance.py            # SLSA-style provenance + YAML policy gate
  safetensors_scanner.py   # SafeTensors validator
  cli.py                   # scan/sign/verify CLI
tests/                     # scanner, signing, SARIF, SafeTensors, CLI tests
rules.yaml                 # Configurable detection rules
docs/
  DESIGN.md
  POLICY_GATE.md
  THREAT_MODEL.md
  policy.example.yaml
```

## References

1. Trail of Bits, [Fickling](https://github.com/trailofbits/fickling)
2. Hugging Face, [Pickle Scanning](https://huggingface.co/docs/hub/security-pickle)
3. Sonatype, [CVE-2025-1716](https://www.sonatype.com/security-advisories/cve-2025-1716)
4. JFrog, [CVE-2025-10155](https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10155/), [CVE-2025-10156](https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10156/), [CVE-2025-10157](https://research.jfrog.com/vulnerabilities/picklescan-cve-2025-10157/)
5. Liu et al., [The Art of Hide and Seek: Making Pickle-Based Model Supply Chain Poisoning Stealthy Again](https://arxiv.org/abs/2508.19774)
6. Chong et al., [PickleBall: Secure Deserialization of Pickle-based Machine Learning Models](https://arxiv.org/abs/2508.15987)
7. OWASP, [Machine Learning Security Top 10](https://owasp.org/www-project-machine-learning-security-top-10/)
8. MITRE, [ATLAS](https://atlas.mitre.org/)
9. NIST, [AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework) and [SSDF](https://csrc.nist.gov/projects/ssdf)

## License

MIT - Pooja Kiran ([@poojakira](https://github.com/poojakira))
