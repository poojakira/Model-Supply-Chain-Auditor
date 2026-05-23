"""Integration tests for CLI."""

import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class TestCLIScan:
    def test_scan_safe_file(self, safe_pkl_file):
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "scan", safe_pkl_file],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "SAFE" in result.stdout

    def test_scan_malicious_file(self, malicious_pkl_file):
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "scan", malicious_pkl_file],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "MALICIOUS" in result.stdout or "SUSPICIOUS" in result.stdout

    def test_scan_json_output(self, malicious_pkl_file):
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "scan", malicious_pkl_file, "--format", "json"],
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        assert "risk_level" in data
        assert "findings" in data
        assert len(data["findings"]) > 0

    def test_scan_sarif_output(self, malicious_pkl_file):
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "scan", malicious_pkl_file, "--format", "sarif"],
            capture_output=True,
            text=True,
        )
        data = json.loads(result.stdout)
        assert data["version"] == "2.1.0"
        assert len(data["runs"][0]["results"]) > 0

    def test_scan_nonexistent_file(self):
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "scan", "/nonexistent/file.pkl"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2

    def test_version_flag(self):
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "--version"],
            capture_output=True,
            text=True,
        )
        assert "0.4.0" in result.stdout


class TestCLISign:
    def test_sign_creates_files(self, safe_pkl_file, tmp_path):
        sig_path = str(tmp_path / "model.sig")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.cli",
                "sign",
                safe_pkl_file,
                "--signer",
                "test-ci",
                "--output",
                sig_path,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "Signed" in result.stdout
        assert (tmp_path / "model.sig").exists()
        assert (tmp_path / "model.pub").exists()

    def test_sign_default_does_not_write_private_key(self, safe_pkl_file, tmp_path):
        sig_path = str(tmp_path / "model.sig")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.cli",
                "sign",
                safe_pkl_file,
                "--signer",
                "test-ci",
                "--output",
                sig_path,
            ],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0
        assert "private key was not written to disk" in result.stdout
        assert not (tmp_path / "safe.pkl.key").exists()
        assert not (tmp_path / "model.key").exists()

    def test_sign_missing_key_path_fails_without_creating_key(self, safe_pkl_file, tmp_path):
        key_path = tmp_path / "missing.pem"
        result = subprocess.run(
            [sys.executable, "-m", "src.cli", "sign", safe_pkl_file, "--key", str(key_path)],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2
        assert "private key not found" in result.stderr
        assert not key_path.exists()

    def test_sign_loads_encrypted_private_key_from_env(self, safe_pkl_file, tmp_path):
        key_path = tmp_path / "signing.pem"
        private_key = Ed25519PrivateKey.generate()
        key_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(b"correct horse"),
            )
        )

        sig_path = str(tmp_path / "model.sig")
        env = os.environ.copy()
        env["MSCA_KEY_PASSPHRASE"] = "correct horse"
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "src.cli",
                "sign",
                safe_pkl_file,
                "--key",
                str(key_path),
                "--output",
                sig_path,
            ],
            capture_output=True,
            text=True,
            env=env,
        )
        assert result.returncode == 0
        assert "Loaded signing key" in result.stdout
        assert (tmp_path / "model.sig").exists()
        assert (tmp_path / "model.pub").exists()
