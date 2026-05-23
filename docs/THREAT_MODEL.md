# Threat Model

## Scope

This project evaluates ML model artifacts before deserialization. It focuses on executable payloads embedded in pickle-backed formats and on provenance checks for model files.

In scope:

- Pickle bytecode with dangerous imports/callables.
- PyTorch-style ZIP archives that contain pickle payloads.
- Nested ZIP archives up to the configured recursion limit.
- SafeTensors structural validation.
- Ed25519 model hash signing and verification.
- SARIF findings suitable for CI/CD gates.

Out of scope:

- Semantic neural backdoors in tensor weights.
- Runtime sandbox escape after a caller chooses to deserialize anyway.
- Dataset poisoning and training-pipeline compromise outside model artifact scanning.
- Trust decisions for key custody, signer identity proofing, or PKI.

## Threat Actors

| Actor | Motivation | Capability |
|-------|------------|------------|
| Malicious model publisher | Distribute model artifacts that execute code | Crafts pickle payloads and uploads to model registries |
| Compromised registry or mirror | Modify legitimate artifacts in transit or at rest | Replaces model bytes, metadata, or signatures |
| Supply-chain attacker | Poison training/deployment dependencies | Compromises packages, build steps, or artifact storage |
| Insider with signing access | Sign malicious or unreviewed artifacts | Uses legitimate credentials or keys |

## Attack Vectors

| Vector | Detection / Control | Residual Risk |
|--------|---------------------|---------------|
| Direct pickle RCE with `GLOBAL`/`STACK_GLOBAL` plus `REDUCE` | Dangerous module/callable rules flag imports and execution opcodes | Static analysis can miss unknown gadgets not in rules |
| `pip.main()` package-install gadget | `pip.main` and `pip._internal.cli.main.main` denied | Variants may need rule updates |
| Unsafe submodule globals | Prefix classification catches dangerous submodules such as `asyncio.*` | Safe-module prefixes must stay conservative |
| Operator or typing helper chains | Known helpers such as `operator.methodcaller`, `operator.attrgetter`, and `typing.ForwardRef` denied | Full taint analysis is not implemented |
| Post-STOP payload | Extra likely-pickle bytes after STOP flagged | Heuristic; loaders that read a single object may not execute trailing bytes |
| Archive evasion | ZIP contents and nested ZIPs scanned; malformed ZIP returns error | CRC-tolerant loader differences remain hard to model exactly |
| Artifact tampering after scan | Ed25519 signature verifies model hash | Key compromise or weak release process can still sign bad artifacts |
| SafeTensors corruption | Header and tensor offset validation | Does not prove model behavior is safe |

## Framework Mapping

| Project Control | OWASP Mapping | MITRE ATLAS Mapping | NIST Mapping | Evidence |
|-----------------|---------------|---------------------|--------------|----------|
| Static pickle/archive scan before load | OWASP ML06:2023 AI Supply Chain Attacks; OWASP LLM03:2025 Supply Chain | AI Supply Chain Compromise; Publish Poisoned Models | AI RMF MAP/MEASURE/MANAGE functions; SSDF PW.4 component review | `src/scanners/pickle_scanner.py`, `rules.yaml`, scanner tests |
| Denylist for known pickle gadgets and unsafe globals | OWASP ML06; OWASP LLM03 | Defense Evasion and Execution techniques involving poisoned AI artifacts | SSDF PW.8 security testing | `rules.yaml`, `tests/test_2026_attacks.py` |
| SARIF output for CI/CD | OWASP ML06 mitigation evidence | Detection/response support for poisoned artifacts | SSDF PW.8 and RV practices | `src/scanners/sarif.py`, `.github/workflows/ci.yml` |
| Ed25519 model hash signing | OWASP ML06 integrity/provenance controls; OWASP LLM03 model provenance | AI Supply Chain Compromise mitigation | SSDF PS.2 release integrity; PS.3 provenance data | `src/signing/model_signer.py`, `tests/test_signing.py` |
| CLI private-key non-persistence by default | OWASP LLM03 supply-chain hardening | Reduces key exposure during artifact publishing | SSDF PO.5 secure development environment; PS.2 integrity mechanism protection | `src/cli.py`, `tests/test_cli.py` |
| SafeTensors structural validation | OWASP ML06 safer artifact handling | Reduces pickle execution surface | AI RMF MANAGE risk treatment | `src/safetensors_scanner.py`, `tests/test_safetensors.py` |

References:

- OWASP Machine Learning Security Top 10: https://owasp.org/www-project-machine-learning-security-top-10/
- OWASP Top 10 for LLM Applications 2025: https://genai.owasp.org/
- MITRE ATLAS: https://atlas.mitre.org/
- NIST AI RMF: https://www.nist.gov/itl/ai-risk-management-framework
- NIST SSDF: https://csrc.nist.gov/projects/ssdf

## CVE / Research Mapping

| Reference | Technique | Project Status |
|-----------|-----------|----------------|
| CVE-2025-1716 | `pip.main()` unsafe-global bypass | Detected |
| CVE-2025-10155 | Pickle file supplied with PyTorch-related extension | Scans pickle magic and archive entries; covered by tests where feasible |
| CVE-2025-10156 | ZIP CRC/archive handling bypass | Malformed ZIP returns error instead of clean pass |
| CVE-2025-10157 | Unsafe globals check bypass via submodule imports | Prefix dangerous-module matching detects dangerous submodules |
| arXiv:2508.19774 | Broad pickle gadget surface and scanner bypasses | Curated subset included in denylist; not exhaustive |
| arXiv:2508.15987 | Pickle-backed model prevalence and policy-based loading limits | Context reference; not a direct scanner claim |

## Operating Guidance

1. Prefer SafeTensors for new model distribution.
2. Treat any malicious or error result as a CI/CD block until reviewed.
3. Sign only after scan and review; verify immediately before deployment.
4. Store signing private keys outside the repository and inject encrypted-key passphrases through CI secrets.
5. Update `rules.yaml` when new public pickle gadgets or scanner bypass CVEs are verified.
