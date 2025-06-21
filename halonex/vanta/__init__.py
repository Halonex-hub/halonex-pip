"""
Vanta URL Validation Module

This module provides URL validation and malicious content detection
using the Halonex Vanta API service.
"""

from .validator import VantaValidator

# Default validator instance
_default_validator = VantaValidator()

# Convenience functions using default validator
def check_url(url, timeout=30):
    """
    Check if a URL is malicious using the default Vanta validator.

    Args:
        url (str): The URL to check
        timeout (int): Request timeout in seconds

    Returns:
        bool: True if malicious, False if safe

    Raises:
        InvalidURLError: If the URL format is invalid
        VantaAPIError: If there's an API error
    """
    return _default_validator.check_url(url, timeout=timeout)


def is_malicious(url, timeout=30):
    """
    Alias for check_url() - checks if a URL is malicious.

    Args:
        url (str): The URL to check
        timeout (int): Request timeout in seconds

    Returns:
        bool: True if malicious, False if safe
    """
    return check_url(url, timeout=timeout)


def is_safe(url, timeout=30):
    """
    Check if a URL is safe (opposite of is_malicious).

    Args:
        url (str): The URL to check
        timeout (int): Request timeout in seconds

    Returns:
        bool: True if safe, False if malicious
    """
    return not check_url(url, timeout=timeout)


__all__ = [
    "VantaValidator",
    "check_url",
    "is_malicious",
    "is_safe"
]