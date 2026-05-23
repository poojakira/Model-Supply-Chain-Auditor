"""Model Supply Chain Auditor — CLI entry point.

Usage:
    msca scan model.pt [--format text|json|sarif] [--rules rules.yaml]
    msca sign model.pt --signer "training-pipeline-v1"
    msca verify model.pt --signature model.pt.sig --key public.pem
    msca attest model.pt --builder-id ... --source-repo ... --source-ref ... --run-id ...
    msca policy model.pt --signature model.pt.sig --key public.pem --provenance prov.json --policy policy.yaml
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

__version__ = "0.4.0"

EXIT_CLEAN = 0
EXIT_MALICIOUS = 1
EXIT_ERROR = 2


def cmd_scan(args: argparse.Namespace) -> int:
    """Scan a model file for malicious payloads."""
    from src.scanners.pickle_scanner import _load_rules, scan_pickle_file
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
        output = json.dumps(
            {
                "file": args.file,
                "risk_level": result.risk_level,
                "is_malicious": result.is_malicious,
                "findings": [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "message": f.message,
                        "byte_offset": f.byte_offset,
                    }
                    for f in result.findings
                ],
                "dangerous_imports": result.dangerous_imports,
                "scanned_files": result.scanned_files,
            },
            indent=2,
        )
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
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from src.signing import export_public_key, generate_signing_keypair, sign_model

    try:
        if args.key:
            key_path = Path(args.key)
            if not key_path.exists():
                raise FileNotFoundError(f"private key not found: {key_path}")
            password_value = os.environ.get(args.key_pass_env)
            password = password_value.encode("utf-8") if password_value else None
            private_key = serialization.load_pem_private_key(
                key_path.read_bytes(),
                password=password,
            )
            if not isinstance(private_key, Ed25519PrivateKey):
                raise ValueError("Signing key must be an Ed25519 private key")
            public_key = private_key.public_key()
            print(f"Loaded signing key: {key_path}")
        else:
            private_key, public_key = generate_signing_keypair()
            print("Generated ephemeral signing key; private key was not written to disk")

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

        pub_path = sig_path.with_suffix(".pub")
        pub_path.write_bytes(export_public_key(public_key))

        print(f"Signed: {args.file}")
        print(f"  Signature: {sig_path}")
        print(f"  Public key: {pub_path}")
        print(f"  Signer: {sig.signer}")
        return EXIT_CLEAN
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify a model file against its signature."""
    from src.signing import verify_model
    from src.signing.model_signer import load_public_key

    try:
        sig = _load_signature(args.signature)
        pub_key = load_public_key(Path(args.key).read_bytes())

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


def cmd_attest(args: argparse.Namespace) -> int:
    """Generate SLSA-style provenance for a model artifact."""
    from src.provenance import build_provenance

    try:
        materials = []
        for material in args.material:
            name, path = _parse_material(material)
            materials.append(
                {
                    "uri": name,
                    "digest": {"sha256": _hash_file(path)},
                }
            )
        provenance = build_provenance(
            args.file,
            builder_id=args.builder_id,
            source_repo=args.source_repo,
            source_ref=args.source_ref,
            run_id=args.run_id,
            materials=materials,
        )
        output = json.dumps(provenance, indent=2)
        if args.output:
            Path(args.output).write_text(output)
        else:
            print(output)
        return EXIT_CLEAN
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR


def cmd_policy(args: argparse.Namespace) -> int:
    """Evaluate signature and provenance against a YAML promotion policy."""
    from src.provenance import evaluate_policy, load_json, load_policy
    from src.signing.model_signer import load_public_key

    try:
        sig = _load_signature(args.signature)
        pub_key = load_public_key(Path(args.key).read_bytes())
        provenance = load_json(args.provenance)
        policy = load_policy(args.policy)
        decision = evaluate_policy(
            artifact_path=args.file,
            signature=sig,
            public_key=pub_key,
            provenance=provenance,
            policy=policy,
        )

        payload = {
            "allowed": decision.allowed,
            "reasons": decision.reasons,
            "warnings": decision.warnings,
        }
        if args.format == "json":
            print(json.dumps(payload, indent=2))
        else:
            status = "ALLOW" if decision.allowed else "DENY"
            print(f"[{status}] {args.file}")
            for reason in decision.reasons:
                print(f"  - {reason}")
            for warning in decision.warnings:
                print(f"  warning: {warning}")
        return EXIT_CLEAN if decision.allowed else EXIT_MALICIOUS
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return EXIT_ERROR


def _load_signature(path: str):
    from src.signing import ModelSignature

    sig_data = json.loads(Path(path).read_text())
    return ModelSignature(
        model_hash=sig_data["model_hash"],
        signature=bytes.fromhex(sig_data["signature"]),
        signer=sig_data["signer"],
        timestamp=sig_data["timestamp"],
        metadata=sig_data.get("metadata", {}),
    )


def _parse_material(value: str) -> tuple[str, Path]:
    if "=" not in value:
        path = Path(value)
        return (path.name, path)
    name, path = value.split("=", 1)
    if not name:
        raise ValueError("material name must not be empty")
    return (name, Path(path))


def _hash_file(path: Path) -> str:
    from src.signing import compute_model_hash

    if not path.exists():
        raise FileNotFoundError(f"material not found: {path}")
    return compute_model_hash(str(path))


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
    sign_parser.add_argument("--key", help="Existing Ed25519 private key PEM to use")
    sign_parser.add_argument(
        "--key-pass-env",
        default="MSCA_KEY_PASSPHRASE",
        help="Environment variable containing encrypted private-key passphrase",
    )
    sign_parser.add_argument("--output", "-o", help="Signature output path")

    # verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify model signature")
    verify_parser.add_argument("file", help="Path to model file")
    verify_parser.add_argument("--signature", "-s", required=True, help="Signature file path")
    verify_parser.add_argument("--key", "-k", required=True, help="Public key PEM file")

    # attest subcommand
    attest_parser = subparsers.add_parser("attest", help="Generate SLSA-style provenance")
    attest_parser.add_argument("file", help="Path to model file")
    attest_parser.add_argument("--builder-id", required=True, help="Trusted builder identity")
    attest_parser.add_argument("--source-repo", required=True, help="Source repository URL")
    attest_parser.add_argument("--source-ref", required=True, help="Source git ref or commit")
    attest_parser.add_argument("--run-id", required=True, help="CI/training run identifier")
    attest_parser.add_argument(
        "--material",
        action="append",
        default=[],
        help="Material as name=path or path. May be repeated.",
    )
    attest_parser.add_argument("--output", "-o", help="Provenance JSON output path")

    # policy subcommand
    policy_parser = subparsers.add_parser("policy", help="Evaluate model promotion policy")
    policy_parser.add_argument("file", help="Path to model file")
    policy_parser.add_argument("--signature", "-s", required=True, help="Signature file path")
    policy_parser.add_argument("--key", "-k", required=True, help="Public key PEM file")
    policy_parser.add_argument("--provenance", "-p", required=True, help="Provenance JSON path")
    policy_parser.add_argument("--policy", required=True, help="Promotion policy YAML path")
    policy_parser.add_argument("--format", choices=["text", "json"], default="text")

    args = parser.parse_args()

    if args.command == "scan":
        sys.exit(cmd_scan(args))
    elif args.command == "sign":
        sys.exit(cmd_sign(args))
    elif args.command == "verify":
        sys.exit(cmd_verify(args))
    elif args.command == "attest":
        sys.exit(cmd_attest(args))
    elif args.command == "policy":
        sys.exit(cmd_policy(args))
    else:
        parser.print_help()
        sys.exit(EXIT_ERROR)


if __name__ == "__main__":
    main()
