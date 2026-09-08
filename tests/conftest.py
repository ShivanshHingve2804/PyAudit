"""Shared test fixtures for PyAudit test suite."""

import ast
import pytest
import tempfile
import os


@pytest.fixture
def parse_code():
    """Fixture that returns a helper to parse Python code into an AST."""
    def _parse(code: str) -> ast.Module:
        return ast.parse(code)
    return _parse


@pytest.fixture
def tmp_python_file():
    """Fixture that creates a temporary Python file with given content."""
    created_files = []
    
    def _create(content: str, filename: str = "test_sample.py") -> str:
        tmpdir = tempfile.mkdtemp()
        filepath = os.path.join(tmpdir, filename)
        with open(filepath, "w") as f:
            f.write(content)
        created_files.append(filepath)
        return filepath
    
    yield _create
    
    for f in created_files:
        try:
            os.unlink(f)
        except OSError:
            pass
