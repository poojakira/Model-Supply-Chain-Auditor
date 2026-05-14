# Design Decisions

Engineering decisions made during development, with rationale.

## Why pickletools.genops() for scanning

**Decision:** Parse pickle bytecode using Python's built-in `pickletools.genops()` rather than executing the pickle or building a custom parser.

**Alternatives considered:**
- `pickle.loads()` with restricted `Unpickler.find_class()` — still executes some opcodes, risk of bypass
- Custom bytecode parser — reinventing what stdlib already provides
- AST analysis of pickle source — pickles are binary, not source code

**Rationale:** `pickletools.genops()` yields `(opcode, arg, position)` tuples without executing anything. This is the same approach used by Trail of Bits' Fickling and HuggingFace's production scanner. Zero execution risk.

## Why Ed25519 over RSA or ECDSA

**Decision:** Ed25519 for model signing.

**Alternatives considered:**
- RSA-2048/4096 — larger keys (256+ bytes vs 32), slower, requires padding scheme selection
- ECDSA (P-256) — vulnerable to nonce reuse (Sony PS3 hack, 2010), requires secure RNG at sign time
- HMAC — symmetric, can't separate signing authority from verification

**Rationale:** Ed25519 is deterministic (no nonce), fast (62k sigs/sec), compact (32-byte keys, 64-byte sigs), and used by SSH, TLS 1.3, Signal, and Tor. The `cryptography` library provides a production-grade implementation.

## Why a blocklist approach for dangerous modules

**Decision:** Maintain explicit lists of `DANGEROUS_MODULES` and `DANGEROUS_CALLABLES`.

**Alternatives considered:**
- Allowlist (only permit known-safe modules) — too restrictive, breaks legitimate models using custom classes
- Taint analysis / data flow tracking — complex, high false-positive rate for a static tool
- ML-based classification of opcodes — circular dependency (using ML to secure ML)

**Rationale:** Blocklist catches the known attack surface (`os`, `subprocess`, `eval`, `builtins`) with zero false positives on legitimate models. The tradeoff is that novel obfuscation (e.g., `types.FunctionType` construction) can evade detection. This is acknowledged in the README.

## Why SHA-256 for model hashing

**Decision:** SHA-256 hash of the entire model file before signing.

**Alternatives considered:**
- SHA-3 — newer but no practical security advantage for this use case
- BLAKE3 — faster but adds a dependency; SHA-256 is in Python stdlib
- Hashing individual tensors — more granular but adds complexity without security benefit

**Rationale:** SHA-256 is universally supported, collision-resistant, and the hash is what gets signed by Ed25519. Using `hashlib.sha256()` means zero additional dependencies.

## Why SafeTensors validation is separate

**Decision:** SafeTensors scanner is a standalone module (`src/safetensors_scanner.py`), not integrated into the pickle scanner.

**Rationale:** SafeTensors is designed to be safe-by-default (no code execution). The scanner validates format integrity (header bounds, tensor alignment) rather than detecting malware. Different threat model = different module.

## File structure: src/ with subpackages

**Decision:** `src/scanners/` and `src/signing/` as separate packages.

**Rationale:** Separation of concerns. Scanning (detecting threats) and signing (proving provenance) are independent operations that can be used separately. A CI pipeline might only need scanning; a training pipeline might only need signing.
