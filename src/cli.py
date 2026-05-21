"""Model Supply Chain Auditor — CLI entry point.

Usage:
    msca scan model.pt [--format text|json|sarif] [--rules rules.yaml]
    msca sign model.pt --signer "training-pipeline-v1"
    msca verify model.pt --signature model.pt.sig --key public.pem
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

__version__ = "0.4.0"

EXIT_CLEAN = 0
EXIT_MALICIOUS = 1
EXIT_ERROR = 2


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan a model file for malicious payloads."""
    from src.scanners.pickle_scanner import scan_pickle_file, _load_rules
    from src.scanners.sarif import sarif_json

    rules = _load_rules(args.rules) if args.rules else _load_rules()

    try:
        result = scan_pickle_file(args.file, rules=rules)
    except FileNotFoundError:
        print(f"Error: file not found: {args.file}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR

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
            lines.append(f"  Scanned: {', '.join(result.scanned_files)}")
        output = "\n".join(lines)

    if args.output:
        Path(args.output).write_text(output)
    else:
        print(output)

    return EXIT_MALICIOUS if result.is_malicious else EXIT_CLEAN


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a model file with Ed25519."""
    from src.signing import generate_signing_keypair, sign_model, export_public_key

    try:
        private_key, public_key = generate_signing_keypair()
        sig = sign_model(args.file, private_key, signer=args.signer)

        sig_path = Path(args.output) if args.output else Path(args.file + ".sig")
        sig_data = {
            "model_hash": sig.model_hash,
            "signature": sig.signature.hex(),
            "signer": sig.signer,
            "timestamp": sig.timestamp,
            "metadata": sig.metadata,
        }
        sig_path.write_text(json.dumps(sig_data, indent=2))

        key_path = sig_path.with_suffix(".pub")
        key_path.write_bytes(export_public_key(public_key))

        print(f"Signed: {args.file}")
        print(f"  Signature: {sig_path}")
        print(f"  Public key: {key_path}")
        print(f"  Signer: {sig.signer}")
        return EXIT_CLEAN
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a model file against its signature."""
    from src.signing import verify_model, compute_model_hash, ModelSignature
    from src.signing.model_signer import load_public_key

    try:
        sig_data = json.loads(Path(args.signature).read_text())
        pub_key = load_public_key(Path(args.key).read_bytes())

        sig = ModelSignature(
            model_hash=sig_data["model_hash"],
            signature=bytes.fromhex(sig_data["signature"]),
            signer=sig_data["signer"],
            timestamp=sig_data["timestamp"],
            metadata=sig_data.get("metadata", {}),
        )

        valid = verify_model(args.file, sig, pub_key)
        if valid:
            print(f"[VALID] {args.file} — signature verified (signer: {sig.signer})")
            return EXIT_CLEAN
        else:
            print(f"[INVALID] {args.file} — signature verification FAILED")
            return EXIT_MALICIOUS
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="msca",
        description="Model Supply Chain Auditor — scan, sign, and verify ML model files",
    )
    parser.add_argument("--version", action="version", version=f"msca {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    # scan subcommand
    scan_parser = subparsers.add_parser("scan", help="Scan model file for malicious payloads")
    scan_parser.add_argument("file", help="Path to model file (.pkl, .pt, .pth)")
    scan_parser.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan_parser.add_argument("--rules", type=Path, default=None, help="Custom rules.yaml")
    scan_parser.add_argument("--output", "-o", help="Write output to file")
    scan_parser.add_argument("--verbose", "-v", action="store_true")

    # sign subcommand
    sign_parser = subparsers.add_parser("sign", help="Sign a model file with Ed25519")
    sign_parser.add_argument("file", help="Path to model file")
    sign_parser.add_argument("--signer", default="unknown", help="Signer identity")
    sign_parser.add_argument("--output", "-o", help="Signature output path")

    # verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify model signature")
    verify_parser.add_argument("file", help="Path to model file")
    verify_parser.add_argument("--signature", "-s", required=True, help="Signature file path")
    verify_parser.add_argument("--key", "-k", required=True, help="Public key PEM file")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "sign":
        sys.exit(cmd_sign(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    else:
        parser.print_help()
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
