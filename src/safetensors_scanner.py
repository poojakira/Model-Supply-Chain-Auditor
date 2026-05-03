"""SafeTensors model scanning — validates safe serialization format.

SafeTensors (2026 standard) eliminates arbitrary code execution risk
present in pickle-based formats. This scanner validates:
1. File header integrity (JSON metadata)
2. Tensor alignment and bounds
3. No embedded executable payloads in metadata
"""

import json
import struct
from pathlib import Path
from typing import Any


class SafeTensorsScanner:
    """Validates SafeTensors files for integrity and safety."""

    def scan(self, filepath: str | Path) -> dict[str, Any]:
        """Scan a .safetensors file for integrity issues.

        Returns:
            dict with keys: safe, issues, metadata, tensor_count
        """
        filepath = Path(filepath)
        issues: list[str] = []

        if not filepath.exists():
            return {"safe": False, "issues": ["File not found"], "metadata": {}, "tensor_count": 0}

        if not filepath.suffix == ".safetensors":
            issues.append(f"Unexpected extension: {filepath.suffix}")

        try:
            with open(filepath, "rb") as f:
                # SafeTensors format: 8-byte header length (little-endian uint64) + JSON header + tensor data
                header_size_bytes = f.read(8)
                if len(header_size_bytes) < 8:
                    return {"safe": False, "issues": ["File too small for SafeTensors format"], "metadata": {}, "tensor_count": 0}

                header_size = struct.unpack("<Q", header_size_bytes)[0]

                # Sanity check: header shouldn't be larger than file
                file_size = filepath.stat().st_size
                if header_size > file_size - 8:
                    issues.append(f"Header size ({header_size}) exceeds file size ({file_size})")
                    return {"safe": False, "issues": issues, "metadata": {}, "tensor_count": 0}

                # Cap header read at 100MB to prevent memory exhaustion
                if header_size > 100 * 1024 * 1024:
                    issues.append(f"Header suspiciously large: {header_size} bytes")
                    return {"safe": False, "issues": issues, "metadata": {}, "tensor_count": 0}

                header_bytes = f.read(header_size)
                header = json.loads(header_bytes)

                # Check for suspicious metadata keys
                metadata = header.pop("__metadata__", {})
                suspicious_keys = [k for k in metadata if k.startswith("__") or "exec" in k.lower() or "eval" in k.lower()]
                if suspicious_keys:
                    issues.append(f"Suspicious metadata keys: {suspicious_keys}")

                # Validate tensor entries
                tensor_count = 0
                data_start = 8 + header_size

                for name, info in header.items():
                    tensor_count += 1
                    dtype = info.get("dtype", "")
                    shape = info.get("shape", [])
                    offsets = info.get("data_offsets", [])

                    if not dtype or not shape or len(offsets) != 2:
                        issues.append(f"Tensor '{name}': malformed entry")
                        continue

                    start, end = offsets
                    if start > end:
                        issues.append(f"Tensor '{name}': invalid offsets ({start} > {end})")
                    if end + data_start > file_size:
                        issues.append(f"Tensor '{name}': data extends beyond file")

        except json.JSONDecodeError as e:
            issues.append(f"Invalid JSON header: {e}")
            return {"safe": False, "issues": issues, "metadata": {}, "tensor_count": 0}
        except Exception as e:
            issues.append(f"Scan error: {e}")
            return {"safe": False, "issues": issues, "metadata": {}, "tensor_count": 0}

        return {
            "safe": len(issues) == 0,
            "issues": issues,
            "metadata": metadata,
            "tensor_count": tensor_count,
        }
