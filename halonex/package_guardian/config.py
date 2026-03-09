import os
from typing import Optional


class Plan:
    """
    Represents the validated plan / tier returned by the server after
    API-key verification.

    Tier hierarchy (cumulative):
        free  → env detection, package listing, local HTML report
        pro   → + ghost-package detection, secret scanning, DB scanning
        enterprise → + vulnerability CVE lookup, outdated-version checking,
                       CDN pattern updates

    Telemetry upload is NOT a tier feature — it is allowed for any
    valid API key regardless of plan.
    """

    TIERS = ("free", "pro", "enterprise")

    # Which scanner features each tier unlocks (cumulative)
    TIER_FEATURES = {
        "free": {
            "env_detection",
            "misconfiguration_check",
            "framework_detection",
            "package_listing",
            "file_structure_scan",
            "html_report",
            "ghost_package_detection",
            "secret_scanning",
            "db_scanning",
            "vuln_scanning",
            "version_scanning",
            "cdn_updates",
        },
        "pro": set(),
        "enterprise": set(),
    }

    def __init__(self, tier: str = "free", features: Optional[set] = None):
        self.tier = tier if tier in self.TIERS else "free"
        # Always use the local cumulative feature set for the tier.
        # Server-provided features are ignored so the client-side
        # TIER_FEATURES dict remains the single source of truth.
        self.features = self._cumulative_features(self.tier)

    # ------------------------------------------------------------------

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

    # Known safe packages — top ~120 PyPI packages by download count.
    # Used for typo-squat / ghost-package detection.
    SAFE_LIST = {
        # Web frameworks
        'requests', 'flask', 'django', 'fastapi', 'tornado', 'starlette',
        'sanic', 'bottle', 'falcon', 'aiohttp', 'quart', 'litestar',
        'uvicorn', 'gunicorn', 'hypercorn', 'waitress',
        # Data / ML
        'numpy', 'pandas', 'scipy', 'scikit-learn', 'matplotlib',
        'tensorflow', 'torch', 'keras', 'xgboost', 'lightgbm',
        'pillow', 'opencv-python', 'seaborn', 'plotly',
        # AWS / Cloud
        'boto3', 'botocore', 'awscli', 's3transfer',
        # Database
        'sqlalchemy', 'psycopg2', 'psycopg2-binary', 'pymongo', 'redis',
        'alembic', 'pymysql',
        # Utils / Core
        'urllib3', 'six', 'certifi', 'idna', 'charset-normalizer',
        'python-dateutil', 'pytz', 'packaging', 'typing-extensions',
        'pyyaml', 'toml', 'tomli', 'attrs', 'cattrs',
        # CLI / Config
        'click', 'rich', 'colorama', 'tqdm', 'argparse',
        # Build / Packaging
        'setuptools', 'wheel', 'pip', 'build', 'twine', 'flit',
        'poetry', 'hatchling', 'pdm',
        # Web utilities
        'jinja2', 'markupsafe', 'werkzeug', 'itsdangerous',
        'httpx', 'httpcore', 'httptools', 'websockets',
        # Crypto / Auth
        'cryptography', 'pyjwt', 'paramiko', 'pyopenssl',
        'bcrypt', 'passlib', 'python-jose',
        # Async
        'celery', 'dramatiq', 'kombu', 'billiard',
        # Serialization
        'protobuf', 'grpcio', 'msgpack', 'orjson', 'ujson',
        # Validation
        'pydantic', 'marshmallow', 'cerberus', 'voluptuous',
        # Testing
        'pytest', 'pytest-cov', 'coverage', 'tox', 'nox',
        'mock', 'faker', 'factory-boy', 'hypothesis',
        # Linting / Formatting
        'pylint', 'flake8', 'black', 'isort', 'mypy', 'ruff', 'bandit',
        # Docs
        'sphinx', 'mkdocs',
        # Misc popular
        'lxml', 'beautifulsoup4', 'soupsieve', 'scrapy',
        'regex', 'chardet', 'filelock', 'platformdirs',
        'wrapt', 'decorator', 'more-itertools', 'multidict',
        'frozenlist', 'aiosignal', 'yarl',
        'docutils', 'pygments', 'babel',
        'importlib-metadata', 'importlib-resources', 'zipp',
        'distlib', 'virtualenv', 'pipenv',
        'greenlet', 'gevent', 'eventlet',
        'cffi', 'pycparser',
        'google-auth', 'google-api-core', 'google-cloud-storage',
        'azure-core', 'azure-storage-blob',
    }

    @staticmethod
    def get_api_key():
        """Retrieve API Key from env vars."""
        return os.environ.get(Config.API_KEY_VAR)
