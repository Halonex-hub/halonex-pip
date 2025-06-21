"""
Custom exceptions for the Halonex package.
"""


class HalonexError(Exception):
    """Base exception class for Halonex package."""
    pass


class VantaAPIError(HalonexError):
    """Exception raised when there's an API error with Vanta service."""
    pass


class InvalidURLError(HalonexError):
    """Exception raised when an invalid URL is provided."""
    pass


class APITimeoutError(VantaAPIError):
    """Exception raised when API request times out."""
    pass


class APIRateLimitError(VantaAPIError):
    """Exception raised when API rate limit is exceeded."""
    pass