"""Tests for Shannon entropy analysis."""

import pytest
from secretlens.entropy import shannon_entropy, find_high_entropy_strings, is_hex_string, is_base64_string


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_character_repeated(self):
        assert shannon_entropy("aaaaaaa") == 0.0

    def test_two_characters_equal(self):
        entropy = shannon_entropy("ab" * 50)
        assert abs(entropy - 1.0) < 0.01

    def test_high_entropy_random(self):
        # A string with many unique characters should have high entropy
        s = "aB3$kL9#mN2@pQ5&rT8*vX1!yZ4"
        entropy = shannon_entropy(s)
        assert entropy > 3.0

    def test_low_entropy_repetitive(self):
        s = "aaaaabbbbb"
        entropy = shannon_entropy(s)
        assert entropy < 1.5


class TestIsHexString:
    def test_valid_hex(self):
        assert is_hex_string("0123456789abcdef") is True

    def test_uppercase_hex(self):
        assert is_hex_string("0123456789ABCDEF") is True

    def test_invalid_hex(self):
        assert is_hex_string("0123456789abcdefg") is False

    def test_with_special_chars(self):
        assert is_hex_string("abc-def") is False


class TestIsBase64String:
    def test_valid_base64(self):
        assert is_base64_string("ABCDEFGHabcdefgh12345678+/==") is True

    def test_with_url_safe_chars(self):
        assert is_base64_string("ABCDabcd1234_-") is True

    def test_invalid_base64(self):
        assert is_base64_string("abc def!@#") is False


class TestFindHighEntropyStrings:
    def test_finds_high_entropy_hex(self):
        line = 'secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"'
        results = find_high_entropy_strings(line)
        assert len(results) >= 1
        assert results[0]["encoding"] == "hex"

    def test_finds_high_entropy_base64(self):
        line = 'token = "ABCDeFgHiJkLmNoPqRsTuVwXyZ0123456789ABCD"'
        results = find_high_entropy_strings(line)
        # Should find it as base64 high entropy
        assert len(results) >= 1

    def test_ignores_low_entropy(self):
        line = 'value = "aaaaaaaaaaaaaaaaaaaaaaaaa"'
        results = find_high_entropy_strings(line)
        assert len(results) == 0

    def test_ignores_short_strings(self):
        line = 'key = "abc123"'
        results = find_high_entropy_strings(line)
        assert len(results) == 0

    def test_ignores_code_patterns(self):
        line = 'x = "functionReturnValueTest1234"'
        results = find_high_entropy_strings(line)
        assert len(results) == 0

    def test_no_quotes_no_match(self):
        line = "just some plain text without quotes"
        results = find_high_entropy_strings(line)
        assert len(results) == 0
