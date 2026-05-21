# Changelog

All notable changes to this project will be documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [0.4.0] - 2026-05-20

### Added
- PyTorch `.pt`/`.pth` ZIP archive extraction and scanning
- Detection of BUILD, INST, OBJ, NEWOBJ, NEWOBJ_EX opcodes
- REDUCE chain depth tracking (flags depth > 3)
- Post-STOP payload detection
- SARIF v2.1.0 JSON output for CI/CD integration
- Externalized rules in `rules.yaml` (configurable dangerous/safe modules)
- Structured `Finding` objects with rule_id, severity, byte_offset
- CLI subcommands: `msca scan`, `msca sign`, `msca verify`
- `--format text/json/sarif` output flag
- `--version` flag
- Proper exit codes (0=clean, 1=malicious, 2=error)
- SECURITY.md, CONTRIBUTING.md, docs/THREAT_MODEL.md
- Makefile, Dockerfile, .pre-commit-config.yaml
- Dependabot configuration
- PR and issue templates
- `py.typed` marker for PEP 561

### Changed
- Scanner refactored from string findings to structured Finding dataclass
- CI matrix: Python 3.11 + 3.12, Ubuntu + Windows
- Coverage threshold set to 80%

## [0.3.0] - 2026-05-14

### Added
- pytest test suite: 28 tests covering pickle scanner, model signing, SafeTensors
- pytest-cov configuration
- `docs/DESIGN.md` documenting engineering decisions

## [0.2.0] - 2026-05-03

### Added
- SafeTensors file format validator
- GitHub composite action for CI/CD model scanning

## [0.1.0] - 2026-04-25

### Added
- Pickle malware scanner using `pickletools.genops()` static analysis
- Ed25519 model signing and verification
- CLI interface (`scan.py`)
- Detection of GLOBAL, STACK_GLOBAL, REDUCE opcodes
- Blocklist of 30+ dangerous modules and 20+ dangerous callables
