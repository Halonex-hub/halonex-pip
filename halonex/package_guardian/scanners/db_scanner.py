import os
import re
import math
from collections import Counter


class DBScanner:
    """
    Scans for database misconfigurations and connection strings.
    """

    DB_PATTERNS = {
        "postgres": r"postgresql://[^:]+:([^@]+)@([^:]+):(\d+)/(.+)",
        "mysql": r"mysql://[^:]+:([^@]+)@([^:]+):(\d+)/(.+)",
        "mongo": r"mongodb://([^:]+):([^@]+)@([^:]+):(\d+)/(.+)",
        "redis": r"redis://:([^@]+)@([^:]+):(\d+)/(\d+)",
        "sqlite": r"sqlite:///(.+)",
    }

    @staticmethod
    def _build_warning(code: str, message: str, severity: str) -> dict:
        return {"code": code, "message": message, "severity": severity}

    @staticmethod
    def _is_weak_password(pw: str) -> bool:
        """Heuristic: short OR low entropy."""
        if len(pw) < 10:
            return True
        if not pw:
            return True
        counts = Counter(pw)
        length = len(pw)
        entropy = -sum((c / length) * math.log2(c / length) for c in counts.values())
        return entropy < 2.5

    @staticmethod
    def _engine_from_str(conn_str: str):
        for prefix, name in (
            ("postgresql", "postgres"), ("mysql", "mysql"),
            ("mongodb", "mongo"), ("redis", "redis"), ("sqlite", "sqlite"),
        ):
            if conn_str.startswith(prefix):
                return name
        return None

    @classmethod
    def scan_environment(cls):
        """
        Checks environment variables for database connection strings.

        Returns:
            list: List of issues found.
        """
        issues = []
        for key, value in os.environ.items():
            if "DATABASE_URL" in key or "DB_URL" in key or "CONNECTION_STRING" in key:
                issue = cls._analyze_connection_string(value, key)
                if issue:
                    issues.append(issue)
        return issues

    @classmethod
    def _analyze_connection_string(cls, conn_str: str, source: str):
        """Analyse a DB connection string and return a structured issue dict, or None."""
        redacted = re.sub(r":([^@]+)@", ":***@", conn_str)

        engine = cls._engine_from_str(conn_str)

        warnings: list = []

        # SSL check (postgres / mysql)
        if engine in ("postgres", "mysql"):
            if "sslmode=require" not in conn_str and "ssl=true" not in conn_str:
                warnings.append(cls._build_warning(
                    "no-ssl", "Missing SSL enforcement (sslmode=require).", "high"
                ))

        # Default port check
        port_sev_map = {
            ":5432":  ("postgres", "Using default PostgreSQL port (5432)."),
            ":3306":  ("mysql",    "Using default MySQL port (3306)."),
            ":27017": ("mongo",    "Using default MongoDB port (27017)."),
            ":6379":  ("redis",    "Using default Redis port (6379)."),
        }
        for port_str, (_eng, msg) in port_sev_map.items():
            if port_str in conn_str:
                warnings.append(cls._build_warning("default-port", msg, "low"))

        # Password strength
        pw_match = re.search(r"://[^:]+:([^@]+)@", conn_str)
        if pw_match:
            pw = pw_match.group(1)
            if cls._is_weak_password(pw):
                warnings.append(cls._build_warning(
                    "weak-password", "DB password fails entropy check.", "medium"
                ))

        # No-auth check
        if engine in ("postgres", "mysql", "mongo") and "://" in conn_str:
            after = conn_str.split("://", 1)[1]
            if "@" not in after:
                warnings.append(cls._build_warning(
                    "no-auth", "Connection string contains no credentials.", "critical"
                ))

        if not warnings:
            return None

        return {
            "source": source,
            "engine": engine,
            "connection_string_redacted": redacted,
            "warnings": warnings,
        }

    @classmethod
    def scan_config_files(cls, root_dir: str) -> list:
        """Walk `root_dir` and extract DB connection strings from common config files."""
        issues: list = []
        seen = set()

        targets = {
            ".env", ".env.local", ".env.production",
            "config.yaml", "config.yml", "config.json",
            "docker-compose.yml", "docker-compose.yaml",
            "database.ini", "application.properties",
            "settings.py",
        }

        CONN_RE = re.compile(
            r"(postgresql|mysql|mongodb|redis|sqlite)://\S+",
            re.IGNORECASE,
        )

        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames[:] = [d for d in dirnames if d not in {"node_modules", ".git", "__pycache__", ".venv", "venv"}]
            for name in filenames:
                if name not in targets:
                    continue
                path = os.path.join(dirpath, name)
                try:
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    continue

                for match in CONN_RE.finditer(content):
                    conn_str = match.group(0).rstrip(",;\"'")
                    key = (name, conn_str)
                    if key in seen:
                        continue
                    seen.add(key)

                    issue = cls._analyze_connection_string(conn_str, f"config:{path}")
                    if issue is None:
                        redacted = re.sub(r":([^@]+)@", ":***@", conn_str)
                        issue = {
                            "source": f"config:{path}",
                            "engine": cls._engine_from_str(conn_str),
                            "connection_string_redacted": redacted,
                            "warnings": [],
                        }
                    issue["warnings"].append(cls._build_warning(
                        "hardcoded-in-repo",
                        f"Connection string hardcoded in tracked file {name}.",
                        "critical",
                    ))
                    issues.append(issue)

        return issues
