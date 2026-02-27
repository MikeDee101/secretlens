"""Shannon entropy analysis for detecting high-entropy strings (potential secrets)."""

import math
import re
import string

# Minimum length for a string to be checked for entropy
MIN_LENGTH = 20

# Entropy thresholds (bits per character)
HEX_THRESHOLD = 3.0
BASE64_THRESHOLD = 4.2

HEX_CHARS = set(string.hexdigits)
BASE64_CHARS = set(string.ascii_letters + string.digits + "+/=_-")

# Regex to extract candidate strings
CANDIDATE_PATTERN = re.compile(r"['\"]([a-zA-Z0-9+/=_\-]{20,})['\"]")


def shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy of a string in bits per character."""
    if not data:
        return 0.0

    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(data)
    entropy = 0.0
    for count in freq.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def is_hex_string(s: str) -> bool:
    """Check if a string is composed of hex characters."""
    return all(c in HEX_CHARS for c in s)


def is_base64_string(s: str) -> bool:
    """Check if a string is composed of base64 characters."""
    return all(c in BASE64_CHARS for c in s)


def _is_likely_code(s: str) -> bool:
    """Heuristic to filter out common code patterns that aren't secrets."""
    lower = s.lower()
    # Skip common programming patterns
    code_indicators = [
        "function", "return", "import", "export", "const", "class",
        "undefined", "null", "true", "false", "localhost", "example",
        "placeholder", "changeme", "password", "your_", "my_",
        "test", "dummy", "sample", "demo", "todo", "fixme",
    ]
    return any(indicator in lower for indicator in code_indicators)


def find_high_entropy_strings(line: str) -> list[dict]:
    """Find high-entropy strings in a line that may be secrets.

    Returns a list of dicts with keys: value, entropy, encoding.
    """
    results = []

    for match in CANDIDATE_PATTERN.finditer(line):
        candidate = match.group(1)

        if len(candidate) < MIN_LENGTH:
            continue

        if _is_likely_code(candidate):
            continue

        entropy = shannon_entropy(candidate)

        if is_hex_string(candidate) and entropy > HEX_THRESHOLD:
            results.append({
                "value": candidate,
                "entropy": round(entropy, 2),
                "encoding": "hex",
                "start": match.start(1),
                "end": match.end(1),
            })
        elif is_base64_string(candidate) and entropy > BASE64_THRESHOLD:
            results.append({
                "value": candidate,
                "entropy": round(entropy, 2),
                "encoding": "base64",
                "start": match.start(1),
                "end": match.end(1),
            })

    return results
