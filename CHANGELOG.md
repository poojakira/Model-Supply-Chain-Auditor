# Changelog

## [0.3.0] - 2026-05-20

### Added
- pytest test suite: 28 tests covering pickle scanner, model signing, and SafeTensors validation
- pytest-cov configuration with 80% minimum coverage threshold
- CI matrix testing on Python 3.11 and 3.12
- `docs/DESIGN.md` documenting engineering decisions

### Changed
- CI workflow now runs pytest with coverage instead of just verify.py

## [0.2.0] - 2026-05-19

### Added
- SafeTensors file format validator (`src/safetensors_scanner.py`)
- GitHub composite action for CI/CD model scanning (`.github/actions/scan/`)
- Header bounds checking, tensor alignment validation, suspicious metadata detection

## [0.1.0] - 2026-05-18

### Added
- Pickle malware scanner using `pickletools.genops()` static analysis
- Detection of GLOBAL, STACK_GLOBAL, and REDUCE opcodes with dangerous modules
- Ed25519 model signing and verification via `cryptography` library
- CLI interface (`scan.py`) for scanning pickle files
- Integration verification script (`verify.py`)
- Blocklist of 30+ dangerous modules and 20+ dangerous callables
