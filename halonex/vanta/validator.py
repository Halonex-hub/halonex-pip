"""
Vanta URL Validator

Core validation logic for checking URLs against the Vanta API.
"""

# Suppress urllib3 warning before imports
import warnings
warnings.filterwarnings('ignore', message='urllib3 v2 only supports OpenSSL 1.1.1+')

import hashlib
import re
import requests
from urllib.parse import urlparse
from typing import Optional

from ..exceptions import VantaAPIError, InvalidURLError, APITimeoutError, APIRateLimitError


class VantaValidator:
    """
    URL validator using the Halonex Vanta API service.
    """

    def __init__(self, api_base_url: str = "https://api.vanta.halonex.app", api_key: Optional[str] = None):
        """
        Initialize the Vanta validator.

        Args:
            api_base_url (str): Base URL for the Vanta API
            api_key (str, optional): API key for authentication (if required)
        """
        self.api_base_url = api_base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()

        # Set default headers
        self.session.headers.update({
            'User-Agent': 'Halonex-Python-SDK/0.1.0'
        })

        if self.api_key:
            self.session.headers.update({
                'Authorization': f'Bearer {self.api_key}'
            })

    def _validate_url_format(self, url: str) -> bool:
        """
        Validate URL format.

        Args:
            url (str): URL to validate

        Returns:
            bool: True if valid format

        Raises:
            InvalidURLError: If URL format is invalid
        """
        if not url or not isinstance(url, str):
            raise InvalidURLError("URL must be a non-empty string")

        # Basic URL pattern validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)

        if not url_pattern.match(url):
            raise InvalidURLError(f"Invalid URL format: {url}")

        return True

    def _extract_domain(self, url: str) -> str:
        """
        Extract domain from URL (without protocol, path, query parameters).

        Args:
            url (str): Full URL to extract domain from

        Returns:
            str: Domain only (e.g., "example.com")

        Examples:
            "https://example.com/path?query=value" -> "example.com"
            "http://sub.domain.com:8080/test" -> "sub.domain.com"
        """
        # Parse the URL
        parsed = urlparse(url)

        # Get the netloc (domain + port)
        domain = parsed.netloc

        # Remove port if present (keep only domain)
        if ':' in domain:
            domain = domain.split(':')[0]

        return domain

    def _generate_sha256(self, domain: str) -> str:
        """
        Generate SHA256 hash of the domain.

        Args:
            domain (str): Domain to hash

        Returns:
            str: SHA256 hash of the domain
        """
        return hashlib.sha256(domain.encode('utf-8')).hexdigest()

    def check_url(self, url: str, timeout: int = 30) -> bool:
        """
        Check if a URL is malicious using the Vanta API.

        Args:
            url (str): The URL to check
            timeout (int): Request timeout in seconds

        Returns:
            bool: True if malicious, False if safe

        Raises:
            InvalidURLError: If the URL format is invalid
            VantaAPIError: If there's an API error
            APITimeoutError: If the request times out
        """
        # Validate URL format
        self._validate_url_format(url)

        # Extract domain from URL
        domain = self._extract_domain(url)

        # Generate SHA256 hash of the domain
        domain_hash = self._generate_sha256(domain)

        # Make API request using the endpoint format
        try:
            endpoint = f"{self.api_base_url}/block/phishing/sha256/{domain_hash}"

            response = self.session.get(
                endpoint,
                timeout=timeout
            )

            # Parse plain text response (ignoring status code)
            response_text = response.text.strip().lower()

            # API returns either "true" or "false" as plain text
            if response_text == "true":
                return True
            elif response_text == "false":
                return False
            else:
                # Unexpected response, log it and assume safe
                raise VantaAPIError(f"Unexpected API response: '{response.text}'. Expected 'true' or 'false'.")

        except requests.exceptions.Timeout:
            raise APITimeoutError(f"API request timed out after {timeout} seconds")

        except requests.exceptions.ConnectionError:
            raise VantaAPIError("Failed to connect to Vanta API")

        except requests.exceptions.RequestException as e:
            raise VantaAPIError(f"API request failed: {str(e)}")

    def check_multiple_urls(self, urls: list, timeout: int = 30) -> dict:
        """
        Check multiple URLs at once.

        Args:
            urls (list): List of URLs to check
            timeout (int): Request timeout in seconds

        Returns:
            dict: Dictionary with URL as key and malicious status as value
        """
        results = {}
        for url in urls:
            try:
                results[url] = self.check_url(url, timeout=timeout)
            except Exception as e:
                results[url] = f"Error: {str(e)}"

        return results

    def get_domain_info(self, url: str, timeout: int = 30) -> dict:
        """
        Get detailed information about a domain extracted from URL.

        Args:
            url (str): The URL to analyze
            timeout (int): Request timeout in seconds

        Returns:
            dict: Information including domain, hash, and malicious status
        """
        self._validate_url_format(url)
        domain = self._extract_domain(url)
        domain_hash = self._generate_sha256(domain)

        try:
            is_malicious = self.check_url(url, timeout=timeout)

            return {
                "original_url": url,
                "domain": domain,
                "domain_sha256": domain_hash,
                "is_malicious": is_malicious,
                "api_endpoint": f"{self.api_base_url}/block/phishing/sha256/{domain_hash}"
            }

        except Exception as e:
            return {
                "original_url": url,
                "domain": domain,
                "domain_sha256": domain_hash,
                "error": str(e),
                "api_endpoint": f"{self.api_base_url}/block/phishing/sha256/{domain_hash}"
            }

    def get_domain_hash(self, url: str) -> str:
        """
        Get the SHA256 hash of the domain extracted from a URL.

        Args:
            url (str): The URL to extract domain from

        Returns:
            str: SHA256 hash of the domain
        """
        self._validate_url_format(url)
        domain = self._extract_domain(url)
        return self._generate_sha256(domain)

    def get_raw_api_response(self, url: str, timeout: int = 30) -> str:
        """
        Get the raw API response for debugging purposes.

        Args:
            url (str): The URL to check
            timeout (int): Request timeout in seconds

        Returns:
            str: Raw API response text
        """
        self._validate_url_format(url)
        domain = self._extract_domain(url)
        domain_hash = self._generate_sha256(domain)

        try:
            endpoint = f"{self.api_base_url}/block/phishing/sha256/{domain_hash}"
            response = self.session.get(endpoint, timeout=timeout)
            return response.text

        except requests.exceptions.RequestException as e:
            raise VantaAPIError(f"API request failed: {str(e)}")