import os

class Config:
    """
    Central configuration for Package Guardian.
    Loads API keys and defines validation rules.
    """
    
    # The API Key identifier
    API_KEY_VAR = "PACKAGE_GUARDIAN_API_KEY"
    
    # API Configuration
    API_BASE_URL = os.environ.get("PACKAGE_GUARDIAN_API_URL", "https://api.halonex.app/v1")
    
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
