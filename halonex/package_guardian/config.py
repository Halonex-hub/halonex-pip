import os
from typing import Optional


class Plan:
    """
    Represents the validated plan / tier returned by the server after
    API-key verification.

    Tier hierarchy (cumulative):
        free  → env detection, package listing, ghost detection,
                secret scanning, CDN pattern updates, misconfig checks
        pro   → + vulnerability CVE lookup, outdated-version checking,
                  DB security audit

    Telemetry upload is NOT a tier feature — it is allowed for any
    valid API key regardless of plan.
    """

    TIERS = ("free", "pro")

    # Which scanner features each tier unlocks (cumulative).
    # Used only as a fallback when the server is unreachable.
    TIER_FEATURES = {
        "free": {
            "env_detection",
            "misconfiguration_check",
            "framework_detection",
            "package_listing",
            "file_structure_scan",
            "ghost_package_detection",
            "secret_scanning",
            "cdn_updates",
        },
        "pro": {
            "vuln_scanning",
            "version_scanning",
            "db_scanning",
        },
    }

    # Maps server-side feature flag names to the internal scanner feature
    # names used by plan.has().  The server is the authoritative source;
    # this mapping lets the client translate without hard-coding tier logic.
    _SERVER_FEATURE_MAP: dict = {
        "basic_scan":      {"env_detection", "misconfiguration_check",
                            "framework_detection", "package_listing",
                            "file_structure_scan"},
        "ghost_detection": {"ghost_package_detection"},
        "secret_scanning": {"secret_scanning"},
        "cdn_patterns":    {"cdn_updates"},
        "vulnerability_check": {"vuln_scanning"},
        "outdated_check":  {"version_scanning"},
        "db_security_audit": {"db_scanning"},
    }

    def __init__(self, tier: str = "free", features: Optional[dict] = None):
        self.tier = tier if tier in self.TIERS else "free"
        if features and isinstance(features, dict):
            # Server is the authoritative source — translate its feature
            # flags into the internal names used by plan.has().
            self.features = self._map_server_features(features)
        else:
            # Fallback: server unreachable or no key — use local tier defaults.
            self.features = self._cumulative_features(self.tier)

    # ------------------------------------------------------------------

    @classmethod
    def _map_server_features(cls, server_features: dict) -> set:
        """Translate the server's bool feature dict to internal scanner feature names."""
        result: set = set()
        for server_key, enabled in server_features.items():
            if enabled and server_key in cls._SERVER_FEATURE_MAP:
                result |= cls._SERVER_FEATURE_MAP[server_key]
        return result

    @classmethod
    def _cumulative_features(cls, tier: str) -> set:
        """Return every feature available at *tier* and below."""
        result: set = set()
        for t in cls.TIERS:
            result |= cls.TIER_FEATURES.get(t, set())
            if t == tier:
                break
        return result

    def has(self, feature: str) -> bool:
        """Check whether a specific feature is enabled."""
        return feature in self.features

    def __repr__(self):
        return f"Plan(tier={self.tier!r}, features={sorted(self.features)})"


class Config:
    """
    Central configuration for Package Guardian.
    Loads API keys and defines validation rules.
    """

    # The API Key identifier
    API_KEY_VAR = "PACKAGE_GUARDIAN_API_KEY"

    # API Configuration
    API_BASE_URL = "https://packageguardian.halonex.net"

    # Internal secret for server endpoint authentication
    INTERNAL_SECRET = "change-me-internal-secret"

    # ----- Runtime state (set after key validation) -----
    plan: Plan = Plan()       # defaults to free tier
    key_validated: bool = False  # True only after server confirms the key

    # Files to include in line counting
    SCAN_EXTENSIONS = {
        '.py', '.js', '.jsx', '.ts', '.tsx', 
        '.html', '.css', '.json', '.dockerfile'
    }

    # Files/Dirs to exclude from traversal
    IGNORE_DIRS = {
        '.git', 'venv', 'env', '.venv', '__pycache__', 
        'node_modules', '.idea', '.vscode', 'build', 'dist', 'egg-info'
    }

    # Known safe packages — populated exclusively by CDN via fetch_safe_list().
    # Empty until the CDN delivers data — ghost detection won't run without it.
    SAFE_LIST: set = set()

    @staticmethod
    def get_api_key():
        """Retrieve API Key from env vars."""
        return os.environ.get(Config.API_KEY_VAR)
