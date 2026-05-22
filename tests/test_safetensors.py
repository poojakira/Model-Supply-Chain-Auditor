"""Tests for SafeTensors scanner."""

import json
import struct
from pathlib import Path

import pytest
from src.safetensors_scanner import SafeTensorsScanner


@pytest.fixture
def scanner():
    return SafeTensorsScanner()


def _create_safetensors_file(path: Path, tensors: dict, metadata: dict | None = None):
    """Create a minimal valid .safetensors file."""
    header = {}
    if metadata:
        header["__metadata__"] = metadata

    offset = 0
    for name, (dtype, shape, size) in tensors.items():
        header[name] = {"dtype": dtype, "shape": shape, "data_offsets": [offset, offset + size]}
        offset += size

    header_bytes = json.dumps(header).encode("utf-8")
    with open(path, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        f.write(b"\x00" * offset)  # dummy tensor data


def test_valid_safetensors(scanner, tmp_path):
    filepath = tmp_path / "model.safetensors"
    _create_safetensors_file(filepath, {"weight": ("F32", [10, 5], 200)})
    result = scanner.scan(filepath)
    assert result["safe"] is True
    assert result["tensor_count"] == 1
    assert result["issues"] == []


def test_file_not_found(scanner):
    result = scanner.scan("/nonexistent/model.safetensors")
    assert result["safe"] is False
    assert "File not found" in result["issues"][0]


def test_suspicious_metadata(scanner, tmp_path):
    filepath = tmp_path / "model.safetensors"
    _create_safetensors_file(filepath, {"weight": ("F32", [10], 40)}, metadata={"__exec_payload": "malicious"})
    result = scanner.scan(filepath)
    assert result["safe"] is False
    assert any("Suspicious metadata" in i for i in result["issues"])


def test_invalid_offsets(scanner, tmp_path):
    filepath = tmp_path / "model.safetensors"
    # Create file with tensor that extends beyond file
    header = {"weight": {"dtype": "F32", "shape": [1000000], "data_offsets": [0, 99999999]}}
    header_bytes = json.dumps(header).encode()
    with open(filepath, "wb") as f:
        f.write(struct.pack("<Q", len(header_bytes)))
        f.write(header_bytes)
        f.write(b"\x00" * 100)  # Much less data than claimed
    result = scanner.scan(filepath)
    assert result["safe"] is False
    assert any("extends beyond" in i for i in result["issues"])


def test_truncated_file(scanner, tmp_path):
    filepath = tmp_path / "model.safetensors"
    with open(filepath, "wb") as f:
        f.write(b"\x00" * 4)  # Too small
    result = scanner.scan(filepath)
    assert result["safe"] is False
