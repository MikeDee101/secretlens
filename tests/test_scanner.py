"""Tests for the core scanner engine."""

import os
import tempfile
import pytest
from secretlens.scanner import Scanner, ScanConfig, scan, Finding


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def _write_file(directory: str, filename: str, content: str) -> str:
    filepath = os.path.join(directory, filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


class TestScanner:
    def test_scan_file_with_aws_key(self, temp_dir):
        filepath = _write_file(temp_dir, "config.py",
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan(filepath)
        assert len(findings) >= 1
        assert any(f.secret_type == "AWS Access Key ID" for f in findings)

    def test_scan_file_with_github_token(self, temp_dir):
        filepath = _write_file(temp_dir, "env.sh",
            'export GITHUB_TOKEN="ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh1234"\n')
        findings = scan(filepath)
        assert any(f.secret_type == "GitHub Personal Access Token" for f in findings)

    def test_scan_file_with_private_key(self, temp_dir):
        filepath = _write_file(temp_dir, "key.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n")
        findings = scan(filepath)
        assert any(f.secret_type == "RSA Private Key" for f in findings)

    def test_scan_clean_file(self, temp_dir):
        filepath = _write_file(temp_dir, "clean.py",
            'print("Hello, world!")\nx = 42\n')
        findings = scan(filepath)
        assert len(findings) == 0

    def test_scan_directory(self, temp_dir):
        _write_file(temp_dir, "app/config.py",
            'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        _write_file(temp_dir, "app/main.py",
            'print("clean code")\n')
        findings = scan(temp_dir)
        assert len(findings) >= 1

    def test_skip_excluded_dirs(self, temp_dir):
        _write_file(temp_dir, "node_modules/pkg/secret.js",
            'const key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan(temp_dir)
        assert len(findings) == 0

    def test_skip_binary_patterns(self, temp_dir):
        _write_file(temp_dir, "bundle.min.js",
            'var key = "AKIAIOSFODNN7EXAMPLE"\n')
        findings = scan(temp_dir)
        assert len(findings) == 0

    def test_skip_large_files(self, temp_dir):
        config = ScanConfig(max_file_size=10)
        filepath = _write_file(temp_dir, "big.txt",
            'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n' * 100)
        findings = scan(filepath, config)
        assert len(findings) == 0

    def test_severity_filter(self, temp_dir):
        # Build stripe key dynamically to avoid GitHub push protection
        stripe_key = "pk_" + "live_" + "abc123def456ghi789jkl012mno"
        filepath = _write_file(temp_dir, "multi.py",
            'KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            f'stripe = "{stripe_key}"\n')
        config = ScanConfig(severity_filter="critical")
        findings = scan(filepath, config)
        assert all(f.severity == "critical" for f in findings)

    def test_no_entropy_scan(self, temp_dir):
        filepath = _write_file(temp_dir, "test.py",
            'token = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"\n')
        config = ScanConfig(entropy_scan=False)
        findings = scan(filepath, config)
        entropy_findings = [f for f in findings if f.secret_type == "High Entropy String"]
        assert len(entropy_findings) == 0

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            scan("/nonexistent/path")

    def test_skips_comments(self, temp_dir):
        # Build stripe key dynamically to avoid GitHub push protection
        stripe_key = "sk_" + "live_" + "abc123def456ghi789jkl012mno"
        filepath = _write_file(temp_dir, "commented.py",
            '# AKIAIOSFODNN7EXAMPLE\n'
            f'// {stripe_key}\n')
        findings = scan(filepath)
        assert len(findings) == 0


class TestFinding:
    def test_redacted_value_long(self):
        f = Finding(
            file="test.py", line_number=1, line_content="...",
            secret_type="test", secret_value="AKIAIOSFODNN7EXAMPLE",
            severity="high", description="test",
        )
        redacted = f.redacted_value
        assert redacted.startswith("AKIA")
        assert redacted.endswith("MPLE")
        assert "..." in redacted

    def test_redacted_value_short(self):
        f = Finding(
            file="test.py", line_number=1, line_content="...",
            secret_type="test", secret_value="short",
            severity="high", description="test",
        )
        redacted = f.redacted_value
        assert "..." in redacted
