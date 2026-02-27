"""Secret detection patterns for common credential types."""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern
    severity: str  # "critical", "high", "medium", "low"
    description: str


def _compile(pattern: str) -> re.Pattern:
    return re.compile(pattern, re.IGNORECASE)


# All patterns organized by category
PATTERNS: list[SecretPattern] = [
    # === AWS ===
    SecretPattern(
        name="AWS Access Key ID",
        pattern=_compile(r"(?:^|[^A-Z0-9])(?P<secret>AKIA[0-9A-Z]{16})(?:[^A-Z0-9]|$)"),
        severity="critical",
        description="AWS Access Key ID starting with AKIA",
    ),
    SecretPattern(
        name="AWS Secret Access Key",
        pattern=_compile(
            r"(?:aws_secret_access_key|aws_secret|secret_key)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?"
        ),
        severity="critical",
        description="AWS Secret Access Key (40-character base64)",
    ),

    # === GitHub ===
    SecretPattern(
        name="GitHub Personal Access Token",
        pattern=_compile(r"(?P<secret>ghp_[A-Za-z0-9]{36,})"),
        severity="critical",
        description="GitHub personal access token",
    ),
    SecretPattern(
        name="GitHub OAuth Access Token",
        pattern=_compile(r"(?P<secret>gho_[A-Za-z0-9]{36,})"),
        severity="critical",
        description="GitHub OAuth access token",
    ),
    SecretPattern(
        name="GitHub Fine-Grained Token",
        pattern=_compile(r"(?P<secret>github_pat_[A-Za-z0-9_]{82,})"),
        severity="critical",
        description="GitHub fine-grained personal access token",
    ),

    # === Google / GCP ===
    SecretPattern(
        name="Google API Key",
        pattern=_compile(r"(?P<secret>AIza[0-9A-Za-z\-_]{35})"),
        severity="high",
        description="Google API key",
    ),
    SecretPattern(
        name="Google OAuth Client Secret",
        pattern=_compile(
            r"(?:client_secret|google_secret)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9_\-]{24})['\"]?"
        ),
        severity="high",
        description="Google OAuth client secret",
    ),

    # === Stripe ===
    SecretPattern(
        name="Stripe Secret Key",
        pattern=_compile(r"(?P<secret>sk_live_[0-9a-zA-Z]{24,})"),
        severity="critical",
        description="Stripe live secret key",
    ),
    SecretPattern(
        name="Stripe Publishable Key",
        pattern=_compile(r"(?P<secret>pk_live_[0-9a-zA-Z]{24,})"),
        severity="medium",
        description="Stripe live publishable key",
    ),

    # === Slack ===
    SecretPattern(
        name="Slack Bot Token",
        pattern=_compile(r"(?P<secret>xoxb-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,})"),
        severity="critical",
        description="Slack bot token",
    ),
    SecretPattern(
        name="Slack Webhook URL",
        pattern=_compile(
            r"(?P<secret>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)"
        ),
        severity="high",
        description="Slack incoming webhook URL",
    ),

    # === Private Keys ===
    SecretPattern(
        name="RSA Private Key",
        pattern=_compile(r"(?P<secret>-----BEGIN RSA PRIVATE KEY-----)"),
        severity="critical",
        description="RSA private key header",
    ),
    SecretPattern(
        name="SSH Private Key (OpenSSH)",
        pattern=_compile(r"(?P<secret>-----BEGIN OPENSSH PRIVATE KEY-----)"),
        severity="critical",
        description="OpenSSH private key header",
    ),
    SecretPattern(
        name="PGP Private Key",
        pattern=_compile(r"(?P<secret>-----BEGIN PGP PRIVATE KEY BLOCK-----)"),
        severity="critical",
        description="PGP private key header",
    ),
    SecretPattern(
        name="EC Private Key",
        pattern=_compile(r"(?P<secret>-----BEGIN EC PRIVATE KEY-----)"),
        severity="critical",
        description="EC private key header",
    ),
    SecretPattern(
        name="Generic Private Key",
        pattern=_compile(r"(?P<secret>-----BEGIN PRIVATE KEY-----)"),
        severity="critical",
        description="Generic PKCS#8 private key header",
    ),

    # === Database ===
    SecretPattern(
        name="PostgreSQL Connection String",
        pattern=_compile(
            r"(?P<secret>postgres(?:ql)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+)"
        ),
        severity="critical",
        description="PostgreSQL connection URI with credentials",
    ),
    SecretPattern(
        name="MySQL Connection String",
        pattern=_compile(
            r"(?P<secret>mysql://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+)"
        ),
        severity="critical",
        description="MySQL connection URI with credentials",
    ),
    SecretPattern(
        name="MongoDB Connection String",
        pattern=_compile(
            r"(?P<secret>mongodb(?:\+srv)?://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+)"
        ),
        severity="critical",
        description="MongoDB connection URI with credentials",
    ),

    # === Generic Secrets ===
    SecretPattern(
        name="Generic API Key Assignment",
        pattern=_compile(
            r"(?:api_key|apikey|api_secret|apisecret)\s*[=:]\s*['\"](?P<secret>[a-zA-Z0-9_\-]{20,})['\"]"
        ),
        severity="high",
        description="Generic API key or secret in assignment",
    ),
    SecretPattern(
        name="Generic Password Assignment",
        pattern=_compile(
            r"(?:password|passwd|pwd)\s*[=:]\s*['\"](?P<secret>[^\s'\"]{8,})['\"]"
        ),
        severity="high",
        description="Password assigned as string literal",
    ),
    SecretPattern(
        name="Generic Secret Assignment",
        pattern=_compile(
            r"(?:secret|token|auth_token|access_token)\s*[=:]\s*['\"](?P<secret>[a-zA-Z0-9_\-/+=]{16,})['\"]"
        ),
        severity="high",
        description="Secret or token assigned as string literal",
    ),
    SecretPattern(
        name="Bearer Token",
        pattern=_compile(
            r"['\"](?P<secret>Bearer\s+[a-zA-Z0-9_\-\.]{20,})['\"]"
        ),
        severity="high",
        description="Hardcoded Bearer authentication token",
    ),

    # === Tokens & Keys ===
    SecretPattern(
        name="Heroku API Key",
        pattern=_compile(
            r"(?:heroku_api_key|heroku_key)\s*[=:]\s*['\"]?(?P<secret>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?"
        ),
        severity="high",
        description="Heroku API key (UUID format)",
    ),
    SecretPattern(
        name="SendGrid API Key",
        pattern=_compile(r"(?P<secret>SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})"),
        severity="critical",
        description="SendGrid API key",
    ),
    SecretPattern(
        name="Twilio API Key",
        pattern=_compile(r"(?P<secret>SK[0-9a-fA-F]{32})"),
        severity="high",
        description="Twilio API key",
    ),
    SecretPattern(
        name="npm Access Token",
        pattern=_compile(r"(?P<secret>npm_[a-zA-Z0-9]{36,})"),
        severity="critical",
        description="npm access token",
    ),
    SecretPattern(
        name="PyPI API Token",
        pattern=_compile(r"(?P<secret>pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})"),
        severity="critical",
        description="PyPI API token",
    ),

    # === JWT ===
    SecretPattern(
        name="JSON Web Token",
        pattern=_compile(
            r"(?P<secret>eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_\-]+)"
        ),
        severity="medium",
        description="JSON Web Token (JWT)",
    ),

    # === Cloud ===
    SecretPattern(
        name="Azure Storage Account Key",
        pattern=_compile(
            r"(?:AccountKey|account_key)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9+/]{86}==)['\"]?"
        ),
        severity="critical",
        description="Azure Storage account key",
    ),
    SecretPattern(
        name="DigitalOcean Token",
        pattern=_compile(r"(?P<secret>dop_v1_[a-f0-9]{64})"),
        severity="critical",
        description="DigitalOcean personal access token",
    ),
]


def get_patterns_by_severity(severity: str) -> list[SecretPattern]:
    """Return patterns filtered by severity level."""
    return [p for p in PATTERNS if p.severity == severity]
