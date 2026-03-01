import os
import re

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
    def scan_environment():
        """
        Checks environment variables for database connection strings.
        
        Returns:
            list: List of issues found.
        """
        issues = []
        
        for key, value in os.environ.items():
            if "DATABASE_URL" in key or "DB_URL" in key or "CONNECTION_STRING" in key:
                issue = DBScanner._analyze_connection_string(value, key)
                if issue:
                    issues.append(issue)
                    
        return issues

    @staticmethod
    def _analyze_connection_string(conn_str: str, source: str):
        """
        Analyzes a connection string for security best practices.
        """
        # Redact the password for the report
        redacted_conn_str = re.sub(r":([^@]+)@", ":***@", conn_str)
        
        issue = {
            "source": source,
            "connection_string": redacted_conn_str,
            "warnings": []
        }
        
        # Check for SSL/TLS enforcement
        if "postgresql" in conn_str or "mysql" in conn_str:
            if "sslmode=require" not in conn_str and "ssl=true" not in conn_str:
                issue["warnings"].append("Missing SSL enforcement (sslmode=require).")
        
        # Check for default ports (heuristic)
        if ":5432" in conn_str:
            issue["warnings"].append("Using default PostgreSQL port (5432). Consider changing for obscurity.")
        if ":3306" in conn_str:
            issue["warnings"].append("Using default MySQL port (3306).")
        if ":27017" in conn_str:
            issue["warnings"].append("Using default MongoDB port (27017).")
            
        if not issue["warnings"]:
            return None
            
        return issue

    @staticmethod
    def scan_config_files(root_dir: str):
        """
        Scans config files for hardcoded database credentials.
        """
        # This is partially covered by SecretScanner, but specific DB checks go here.
        # For now, we rely on SecretScanner for file content and scan_environment for runtime config.
        return []
