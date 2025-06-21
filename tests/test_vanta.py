"""
Tests for the Vanta URL validator.
"""

import pytest
import requests_mock
from halonex.vanta import VantaValidator, check_url, is_malicious, is_safe
from halonex.exceptions import InvalidURLError, VantaAPIError


class TestVantaValidator:
    """Test cases for VantaValidator class."""

    def test_extract_domain(self):
        """Test domain extraction from URLs."""
        validator = VantaValidator()

        test_cases = [
            ("https://example.com", "example.com"),
            ("http://sub.domain.com/path", "sub.domain.com"),
            ("https://test.com:8080/page?query=value", "test.com"),
            ("http://this.is.a.test.com/this/is/also/a/test?test=test", "this.is.a.test.com"),
            ("https://192.168.1.1:3000/api", "192.168.1.1"),
        ]

        for url, expected_domain in test_cases:
            assert validator._extract_domain(url) == expected_domain

    def test_generate_sha256(self):
        """Test SHA256 hash generation."""
        validator = VantaValidator()
        domain = "example.com"
        hash_result = validator._generate_sha256(domain)

        # SHA256 should be 64 characters long
        assert len(hash_result) == 64
        assert isinstance(hash_result, str)

        # Same domain should produce same hash
        assert validator._generate_sha256(domain) == hash_result

    @requests_mock.Mocker()
    def test_check_url_safe(self, m):
        """Test checking a safe URL."""
        validator = VantaValidator()

        # Mock API to return "false" as plain text
        m.get(
            requests_mock.ANY,
            text="false"
        )

        result = validator.check_url("https://example.com")
        assert result is False

    @requests_mock.Mocker()
    def test_check_url_malicious(self, m):
        """Test checking a malicious URL."""
        validator = VantaValidator()

        # Mock API to return "true" as plain text
        m.get(
            requests_mock.ANY,
            text="true"
        )

        result = validator.check_url("https://malicious.com")
        assert result is True

    @requests_mock.Mocker()
    def test_check_url_unexpected_response(self, m):
        """Test handling unexpected API response."""
        validator = VantaValidator()

        # Mock API to return unexpected response
        m.get(
            requests_mock.ANY,
            text="unexpected"
        )

        with pytest.raises(VantaAPIError):
            validator.check_url("https://example.com")

    @requests_mock.Mocker()
    def test_get_raw_api_response(self, m):
        """Test getting raw API response."""
        validator = VantaValidator()

        m.get(
            requests_mock.ANY,
            text="true"
        )

        response = validator.get_raw_api_response("https://example.com")
        assert response == "true"


if __name__ == "__main__":
    pytest.main([__file__])