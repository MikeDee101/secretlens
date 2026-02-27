"""Tests for secret pattern detection."""

import pytest
from secretlens.patterns import PATTERNS


def _match(pattern_name: str, text: str) -> str | None:
    """Helper: try to match a named pattern against text, return matched secret or None."""
    for p in PATTERNS:
        if p.name == pattern_name:
            m = p.pattern.search(text)
            if m and "secret" in m.groupdict():
                return m.group("secret")
            elif m:
                return m.group(0)
            return None
    raise ValueError(f"Unknown pattern: {pattern_name}")


# Helper to build test tokens dynamically so GitHub push protection
# does not flag them as real secrets.
def _build(*parts: str) -> str:
    return "".join(parts)


class TestAWSPatterns:
    def test_aws_access_key_id(self):
        key = _build("AKIA", "IOSFODNN7EXAMPLE")
        assert _match("AWS Access Key ID", key) is not None

    def test_aws_access_key_id_in_config(self):
        key = _build("AKIA", "IOSFODNN7EXAMPLE")
        result = _match("AWS Access Key ID", f'aws_access_key_id = "{key}"')
        assert result is not None
        assert result.startswith("AKIA")

    def test_aws_secret_key(self):
        text = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert _match("AWS Secret Access Key", text) is not None

    def test_no_false_positive_on_akia_prefix_only(self):
        assert _match("AWS Access Key ID", "AKIA") is None


class TestGitHubPatterns:
    def test_github_pat(self):
        token = _build("ghp_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefgh1234")
        assert _match("GitHub Personal Access Token", token) is not None

    def test_github_oauth(self):
        token = _build("gho_", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefgh1234")
        assert _match("GitHub OAuth Access Token", token) is not None

    def test_github_fine_grained(self):
        token = _build("github_pat_", "A" * 82)
        assert _match("GitHub Fine-Grained Token", token) is not None


class TestStripePatterns:
    def test_stripe_secret_key(self):
        # Build dynamically to avoid GitHub push protection
        key = _build("sk_", "live_", "abc123def456ghi789jkl012mno")
        assert _match("Stripe Secret Key", key) is not None

    def test_stripe_publishable_key(self):
        key = _build("pk_", "live_", "abc123def456ghi789jkl012mno")
        assert _match("Stripe Publishable Key", key) is not None


class TestPrivateKeyPatterns:
    def test_rsa_private_key(self):
        assert _match("RSA Private Key", "-----BEGIN RSA PRIVATE KEY-----") is not None

    def test_openssh_private_key(self):
        assert _match("SSH Private Key (OpenSSH)", "-----BEGIN OPENSSH PRIVATE KEY-----") is not None

    def test_ec_private_key(self):
        assert _match("EC Private Key", "-----BEGIN EC PRIVATE KEY-----") is not None

    def test_generic_private_key(self):
        assert _match("Generic Private Key", "-----BEGIN PRIVATE KEY-----") is not None

    def test_pgp_private_key(self):
        assert _match("PGP Private Key", "-----BEGIN PGP PRIVATE KEY BLOCK-----") is not None


class TestDatabasePatterns:
    def test_postgres_uri(self):
        uri = _build("postgresql://user:password123@", "db.example.com:5432/mydb")
        assert _match("PostgreSQL Connection String", uri) is not None

    def test_mysql_uri(self):
        uri = _build("mysql://root:secret@", "localhost:3306/app")
        assert _match("MySQL Connection String", uri) is not None

    def test_mongodb_uri(self):
        uri = _build("mongodb+srv://admin:p4ssw0rd@", "cluster.example.net/mydb")
        assert _match("MongoDB Connection String", uri) is not None


class TestGenericPatterns:
    def test_api_key_assignment(self):
        text = 'api_key = "sk_1234567890abcdefghij"'
        assert _match("Generic API Key Assignment", text) is not None

    def test_password_assignment(self):
        text = 'password = "SuperSecretP@ss123"'
        assert _match("Generic Password Assignment", text) is not None

    def test_bearer_token(self):
        text = '"Bearer eyJhbGciOiJIUzI1NiJ9.test"'
        assert _match("Bearer Token", text) is not None


class TestTokenPatterns:
    def test_sendgrid_api_key(self):
        key = _build("SG.", "abcdefghijklmnopqrstuv", ".", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrs")
        assert _match("SendGrid API Key", key) is not None

    def test_npm_token(self):
        token = _build("npm_", "abcdefghijklmnopqrstuvwxyz1234567890")
        assert _match("npm Access Token", token) is not None

    def test_google_api_key(self):
        key = _build("AIza", "SyA1234567890abcdefghijklmnopqrstuv")
        assert _match("Google API Key", key) is not None

    def test_jwt(self):
        jwt = _build(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0",
            ".Sfl",
        )
        assert _match("JSON Web Token", jwt) is not None


class TestSlackPatterns:
    def test_slack_bot_token(self):
        # Build dynamically to avoid GitHub push protection
        token = _build("xoxb-", "1234567890", "-", "1234567890123", "-", "AbCdEfGhIjKlMnOpQrStUvWx")
        assert _match("Slack Bot Token", token) is not None

    def test_slack_webhook(self):
        url = _build(
            "https://hooks.slack.com/",
            "services/T00000000/B00000000/",
            "XXXXXXXXXXXXXXXXXXXXXXXX",
        )
        assert _match("Slack Webhook URL", url) is not None
