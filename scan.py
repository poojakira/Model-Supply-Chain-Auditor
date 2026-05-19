"""CLI interface for Model Supply Chain Auditor."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.scanners.pickle_scanner import scan_pickle_file, _load_rules
from src.scanners.sarif import sarif_json


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="msca",
        description="Model Supply Chain Auditor — scan ML model files for malicious payloads",
    )
    parser.add_argument("file", help="Path to model file (.pkl, .pt, .pth, .ckpt)")
    parser.add_argument("--format", choices=["text", "json", "sarif"], default="text",
                        help="Output format (default: text)")
    parser.add_argument("--rules", type=Path, default=None,
                        help="Path to custom rules.yaml")
    parser.add_argument("--output", "-o", type=Path, default=None,
                        help="Write output to file instead of stdout")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    rules = _load_rules(args.rules) if args.rules else _load_rules()
    result = scan_pickle_file(args.file, rules=rules)

    if args.format == "sarif":
        output = sarif_json(result, args.file)
    elif args.format == "json":
        output = json.dumps({
            "file": args.file,
            "risk_level": result.risk_level,
            "is_malicious": result.is_malicious,
            "findings": [
                {"rule_id": f.rule_id, "severity": f.severity,
                 "message": f.message, "byte_offset": f.byte_offset}
                for f in result.findings
            ],
            "dangerous_imports": result.dangerous_imports,
            "scanned_files": result.scanned_files,
        }, indent=2)
    else:
        status = "MALICIOUS" if result.is_malicious else result.risk_level.upper()
        lines = [f"[{status}] {args.file}"]
        if args.verbose or result.findings:
            for f in result.findings:
                lines.append(f"  - {f}")
        if result.scanned_files:
            lines.append(f"  Scanned entries: {', '.join(result.scanned_files)}")
        output = "\n".join(lines)

    if args.output:
        args.output.write_text(output)
    else:
        print(output)

    sys.exit(1 if result.is_malicious else 0)


if __name__ == "__main__":
    main()
