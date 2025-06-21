"""
Halonex - URL Validation and Security Analysis Package

A Python package for validating URLs and detecting malicious content
using the Halonex Vanta API service.
"""

# Suppress urllib3 OpenSSL warning BEFORE any imports
import warnings
import sys

# Suppress the specific urllib3 warning
warnings.filterwarnings('ignore', message='urllib3 v2 only supports OpenSSL 1.1.1+')
warnings.filterwarnings('ignore', category=UserWarning, module='urllib3')

# Also suppress by category if available
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings('ignore', category=NotOpenSSLWarning)
except ImportError:
    pass

__version__ = "0.1.0"
__author__ = "Dominic"
__email__ = "dominic@halonex.app"

# Import main modules for easy access (after warning suppression)
from . import vanta
from .exceptions import HalonexError, VantaAPIError, InvalidURLError

__all__ = [
    "vanta",
    "HalonexError",
    "VantaAPIError",
    "InvalidURLError",
    "__version__"
]