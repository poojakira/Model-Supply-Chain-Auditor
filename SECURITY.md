# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | ✅ Active support  |
| < 0.4   | ❌ No support      |

## Reporting Vulnerabilities

If you discover a security vulnerability in this tool, please report it responsibly:

1. **DO NOT** open a public GitHub issue for security vulnerabilities.
2. Use [GitHub Security Advisories](https://github.com/poojakira/Model-Supply-Chain-Auditor/security/advisories/new) to report privately.
3. Or email: poojakira@users.noreply.github.com

We will acknowledge receipt within 48 hours and provide a fix timeline within 7 days.

## Known Limitations

This tool has documented limitations that are **not** considered vulnerabilities:

| Limitation | Description | Mitigation |
|-----------|-------------|------------|
| Blocklist bypass via indirect imports | Attackers can use `importlib.import_module()` or `operator.attrgetter()` to reach dangerous functions without directly importing them | Use allowlist mode; combine with Fickling runtime hook |
| BUILD opcode false positives | PyTorch state_dicts use BUILD legitimately; we suppress for safe modules but edge cases exist | Review findings manually for BUILD alerts |
| No neural backdoor detection | Poisoned model weights (trigger patterns) are not detectable by static analysis of serialization format | Use Neural Cleanse or Spectral Signatures for weight-level analysis |
| No dynamic analysis | We parse opcodes statically; we cannot detect time-of-check/time-of-use attacks | Combine with sandboxed execution |
| String concatenation evasion | Attackers building module names character-by-character may evade string-level detection | Known limitation of all static pickle scanners |
| ZIP header manipulation | CVE-2025-1944/1945 style attacks modifying ZIP headers may cause scan failures | We report malformed ZIPs as errors rather than passing them |

## Scope

**In scope** for security reports:
- Bypasses that allow malicious pickle files to be classified as "safe"
- Crashes or denial-of-service via crafted input files
- Vulnerabilities in the signing/verification logic

**Out of scope** (file as feature requests instead):
- Detection of novel attack patterns not in rules.yaml
- Neural backdoor detection
- Performance issues on large files
