""""""CLI interface for model scanning and signing.""""""
import argparse
import sys
sys.path.insert(0, ".")
from src.scanners import scan_pickle_file

def main():
    parser = argparse.ArgumentParser(description="Model Supply Chain Auditor")
    parser.add_argument("file", help="Path to model file (.pkl, .pt)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    result = scan_pickle_file(args.file)
    status = "MALICIOUS" if result.is_malicious else result.risk_level.upper()
    print(f"[{status}] {args.file}")
    if args.verbose or result.findings:
        for f in result.findings:
            print(f"  - {f}")

if __name__ == "__main__":
    main()
