# secretlens

A fast, lightweight secret scanner for codebases. Detects accidentally committed API keys, tokens, passwords, and private keys before they cause a breach.

## Why?

Leaked secrets in source code are one of the top causes of security incidents. **secretlens** catches them early — in your editor, in CI, or as a pre-commit hook — with zero configuration required.

## Features

- **30+ built-in patterns** for AWS, GitHub, Stripe, Google, Slack, database URIs, private keys, JWTs, and more
- **Shannon entropy analysis** catches secrets that don't match known patterns
- **Zero config** — works out of the box on any codebase
- **Fast** — skips binaries, lock files, node_modules, and other noise automatically
- **Pre-commit hook** support via [pre-commit](https://pre-commit.com)
- **Multiple output formats** — colored terminal output or JSON for CI pipelines
- **No dependencies** — pure Python, stdlib only

## Installation

```bash
pip install secretlens
```

## Quick Start

```bash
# Scan current directory
secretlens .

# Scan a specific file
secretlens src/config.py

# Only show critical findings
secretlens . --severity critical

# Output as JSON (for CI)
secretlens . --json

# Disable entropy-based detection
secretlens . --no-entropy
```

## Pre-commit Hook

Add to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/MikeDee101/secretlens
    rev: v0.1.0
    hooks:
      - id: secretlens
```

## What It Detects

| Category | Examples |
|----------|----------|
| **Cloud Providers** | AWS access keys, Google API keys, Azure storage keys, DigitalOcean tokens |
| **Code Platforms** | GitHub tokens (PAT, OAuth, fine-grained), npm tokens, PyPI tokens |
| **Payment** | Stripe secret/publishable keys |
| **Communication** | Slack bot tokens, webhook URLs |
| **Databases** | PostgreSQL, MySQL, MongoDB connection strings with credentials |
| **Cryptographic** | RSA, SSH, EC, PGP private keys |
| **Authentication** | JWTs, Bearer tokens, generic passwords/secrets/API keys |
| **High Entropy** | Any suspiciously random strings in quotes (via Shannon entropy) |

## CLI Options

```
usage: secretlens [-h] [--version] [--json] [--no-color] [--no-entropy]
                  [--severity {critical,high,medium,low}]
                  [--max-file-size BYTES] [--exclude-dir DIR]
                  [--exclude-pattern PATTERN]
                  [path]

positional arguments:
  path                  File or directory to scan (default: .)

options:
  --json                Output results as JSON
  --no-color            Disable colored output
  --no-entropy          Disable Shannon entropy-based detection
  --severity LEVEL      Only show findings of this severity level
  --max-file-size BYTES Skip files larger than this (default: 1MB)
  --exclude-dir DIR     Additional directories to exclude (repeatable)
  --exclude-pattern PAT Additional file patterns to exclude (repeatable)
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No secrets found |
| `1` | Secrets detected |
| `2` | Error (file not found, etc.) |

This makes it easy to integrate into CI pipelines — a non-zero exit fails the build.

## Contributing

Contributions are welcome! Some areas where help is appreciated:

- Adding new secret patterns
- Reducing false positives
- Adding new output formats (SARIF, CSV)
- Performance improvements

```bash
# Setup development environment
git clone https://github.com/MikeDee101/secretlens.git
cd secretlens
pip install -e ".[dev]"

# Run tests
pytest
```

## License

MIT
