"""Shared test fixtures."""

import os
import pickle

import pytest


@pytest.fixture
def safe_pickle_bytes():
    """Minimal safe pickle — a plain dict."""
    return pickle.dumps({"weights": [0.1, 0.2, 0.3], "bias": 0.0})


@pytest.fixture
def malicious_pickle_bytes():
    """Pickle with os.system RCE payload (never executed)."""
    class Exploit:
        def __reduce__(self):
            return (os.system, ("id",))
    return pickle.dumps(Exploit())


@pytest.fixture
def safe_pkl_file(tmp_path, safe_pickle_bytes):
    """Write safe pickle to a temp file."""
    path = tmp_path / "safe.pkl"
    path.write_bytes(safe_pickle_bytes)
    return str(path)


@pytest.fixture
def malicious_pkl_file(tmp_path, malicious_pickle_bytes):
    """Write malicious pickle to a temp file."""
    path = tmp_path / "evil.pkl"
    path.write_bytes(malicious_pickle_bytes)
    return str(path)
