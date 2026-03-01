import re
import os
import math
import time
from collections import Counter
from pathlib import Path


class SecretPattern:
    """Represents a single secret detection pattern loaded from the patterns file."""

    __slots__ = ("severity", "name", "regex", "_compiled")

    def __init__(self, severity: str, name: str, regex: str):
        self.severity = severity.upper()
        self.name = name
        self.regex = regex
        self._compiled = re.compile(regex)

    def finditer(self, text: str):
        return self._compiled.finditer(text)

    def __repr__(self):
        return f"SecretPattern({self.severity}, {self.name!r})"


class SecretScanner:
    """
    Full-featured scanner that detects hardcoded API keys, tokens, private keys,
    and other secrets in source code and configuration files.

    Patterns are loaded from an external ``secret_patterns.txt`` file so users
    can add / remove rules without touching Python code.
    """

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    # Maximum file size to scan (1 MB)
    MAX_FILE_SIZE: int = 1 * 1024 * 1024

    # Extensions considered "text" and worth scanning for secrets
    SCAN_EXTENSIONS: set = {
        ".py", ".js", ".jsx", ".ts", ".tsx",
        ".json", ".yml", ".yaml", ".xml", ".toml", ".ini", ".cfg",
        ".env", ".env.local", ".env.production", ".env.development",
        ".sh", ".bash", ".zsh", ".bat", ".ps1", ".cmd",
        ".tf", ".tfvars", ".hcl",
        ".properties", ".conf", ".config",
        ".md", ".rst", ".txt",
        ".html", ".htm", ".css",
        ".sql",
        ".rb", ".go", ".java", ".cs", ".php", ".swift", ".kt",
        ".dockerfile",
        ".r", ".rmd",
    }

    # Also scan files with NO extension (e.g. ``Dockerfile``, ``.env``, ``Makefile``)
    EXTENSIONLESS_SCANNABLE: set = {
        "dockerfile", "makefile", "vagrantfile", "procfile",
        "gemfile", "rakefile", "brewfile",
        ".env", ".gitconfig", ".npmrc", ".pypirc",
    }

    # Shannon entropy threshold for flagging random-looking strings
    ENTROPY_THRESHOLD: float = 4.0

    # Severity ordering (higher index = more severe)
    SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

    # Singleton cache for loaded patterns
    _patterns_cache: list = []
    _patterns_loaded: bool = False

    # ------------------------------------------------------------------
    # Pattern Loading
    # ------------------------------------------------------------------

    @classmethod
    def _default_patterns_path(cls) -> str:
        """Return the path to ``secret_patterns.txt`` shipped alongside this module."""
        return str(Path(__file__).resolve().parent.parent / "secret_patterns.txt")

    @classmethod
    def load_patterns(cls, filepath: str = None) -> list:
        """
        Parse ``secret_patterns.txt`` and return a list of ``SecretPattern`` objects.

        Args:
            filepath: Explicit path to a patterns file.  When *None* the
                      default file bundled with the package is used.

        Returns:
            list[SecretPattern]: Parsed patterns ready for matching.
        """
        if cls._patterns_loaded and not filepath:
            return cls._patterns_cache

        filepath = filepath or cls._default_patterns_path()
        patterns = []

        try:
            with open(filepath, "r", encoding="utf-8") as fh:
                for lineno, raw_line in enumerate(fh, start=1):
                    line = raw_line.strip()
                    # skip blanks and comments
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split("|", maxsplit=2)
                    if len(parts) != 3:
                        continue  # malformed line
                    severity, name, regex = (p.strip() for p in parts)
                    try:
                        patterns.append(SecretPattern(severity, name, regex))
                    except re.error as exc:
                        print(f"[SECRET SCANNER WARNING]: Bad regex on line {lineno} "
                              f"of {filepath}: {exc}")
        except FileNotFoundError:
            print(f"[SECRET SCANNER WARNING]: Patterns file not found at {filepath}. "
                  "Using built-in fallback patterns.")
            patterns = cls._builtin_fallback_patterns()

        cls._patterns_cache = patterns
        cls._patterns_loaded = True
        return patterns

    @staticmethod
    def _builtin_fallback_patterns() -> list:
        """Minimal set of patterns used when the external file is missing."""
        raw = [
            ("CRITICAL", "AWS Access Key ID", r"AKIA[0-9A-Z]{16}"),
            ("CRITICAL", "Private Key Header", r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----"),
            ("HIGH", "Generic API Key", r"(?i)(?:api_key|apikey|secret|token)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})['\"]?"),
            ("HIGH", "Slack Token", r"xox[baprs]-[0-9a-zA-Z]{10,48}"),
            ("CRITICAL", "GitHub PAT", r"ghp_[0-9a-zA-Z]{36}"),
        ]
        return [SecretPattern(s, n, r) for s, n, r in raw]

    # ------------------------------------------------------------------
    # Entropy Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string — high entropy ≈ random / secret."""
        if not data:
            return 0.0
        counter = Counter(data)
        length = len(data)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )

    @classmethod
    def _has_high_entropy(cls, text: str, min_length: int = 8) -> bool:
        """Return *True* when *text* looks sufficiently random."""
        if len(text) < min_length:
            return False
        return cls.shannon_entropy(text) >= cls.ENTROPY_THRESHOLD

    # ------------------------------------------------------------------
    # Redaction
    # ------------------------------------------------------------------

    @staticmethod
    def redact(value: str, visible_chars: int = 4) -> str:
        """Redact a secret keeping only the first/last *visible_chars* characters."""
        if len(value) <= visible_chars * 2:
            return "*" * len(value)
        return value[:visible_chars] + "*" * (len(value) - visible_chars * 2) + value[-visible_chars:]

    # ------------------------------------------------------------------
    # File-Level Scanning
    # ------------------------------------------------------------------

    @classmethod
    def _should_scan(cls, filename: str) -> bool:
        """Decide whether a file is worth scanning based on extension / name."""
        lower = filename.lower()
        _, ext = os.path.splitext(lower)
        if ext in cls.SCAN_EXTENSIONS:
            return True
        if lower in cls.EXTENSIONLESS_SCANNABLE:
            return True
        # files with no extension that aren't in the allow-list are skipped
        return False

    @classmethod
    def scan_file(cls, file_path: str, patterns: list = None) -> list:
        """
        Scan a single file for leaked secrets.

        Args:
            file_path:  Path to the file to scan.
            patterns:   Pre-loaded patterns (avoids re-parsing the txt every call).

        Returns:
            list[dict]: Each finding is a dict with keys:
                type, severity, file, line, redacted_snippet, entropy, match_preview
        """
        patterns = patterns or cls.load_patterns()
        findings: list = []

        try:
            if os.path.getsize(file_path) > cls.MAX_FILE_SIZE:
                return []

            with open(file_path, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        except (OSError, PermissionError):
            return []

        # Build full content for multi-line patterns (e.g. private key blocks)
        full_content = "".join(lines)

        # We also keep a mapping of char-offset → line number for fast lookup.
        line_offsets = []
        offset = 0
        for line in lines:
            line_offsets.append(offset)
            offset += len(line)

        def _offset_to_lineno(match_start: int) -> int:
            """Binary-search for the line number that contains *match_start*."""
            lo, hi = 0, len(line_offsets) - 1
            while lo <= hi:
                mid = (lo + hi) // 2
                if line_offsets[mid] <= match_start:
                    lo = mid + 1
                else:
                    hi = mid - 1
            return lo  # 1-based

        seen_positions: set = set()  # avoid duplicate findings at same position

        for pat in patterns:
            for match in pat.finditer(full_content):
                start = match.start()
                # De-duplicate by (pattern name, start position)
                key = (pat.name, start)
                if key in seen_positions:
                    continue
                seen_positions.add(key)

                captured = match.group(1) if match.lastindex else match.group(0)
                lineno = _offset_to_lineno(start)

                # Optional: compute entropy for the captured value
                entropy = cls.shannon_entropy(captured)

                # Build a short line preview (the line where the match starts)
                preview_line = lines[lineno - 1].rstrip() if lineno <= len(lines) else ""
                if len(preview_line) > 120:
                    preview_line = preview_line[:120] + "…"

                findings.append({
                    "type": pat.name,
                    "severity": pat.severity,
                    "file": file_path,
                    "line": lineno,
                    "redacted_snippet": cls.redact(captured),
                    "entropy": round(entropy, 2),
                    "match_preview": preview_line,
                })

        return findings

    # ------------------------------------------------------------------
    # Directory Scanning
    # ------------------------------------------------------------------

    @classmethod
    def scan_directory(cls, root_dir: str, ignore_dirs: set, patterns_file: str = None) -> list:
        """
        Recursively scan a directory tree for leaked secrets.

        Args:
            root_dir:      Starting directory.
            ignore_dirs:   Set of directory names to skip.
            patterns_file: Optional custom patterns file path.

        Returns:
            list[dict]: Aggregated findings from all scanned files.
        """
        patterns = cls.load_patterns(patterns_file)
        all_findings: list = []
        files_scanned: int = 0

        for root, dirs, files in os.walk(root_dir):
            # Prune ignored & hidden directories
            dirs[:] = [d for d in dirs if d not in ignore_dirs and not d.startswith(".")]

            for filename in files:
                if not cls._should_scan(filename):
                    continue

                file_path = os.path.join(root, filename)
                file_findings = cls.scan_file(file_path, patterns)
                if file_findings:
                    all_findings.extend(file_findings)
                files_scanned += 1

        return all_findings

    # ------------------------------------------------------------------
    # Summary / Reporting Helpers
    # ------------------------------------------------------------------

    @classmethod
    def summarize(cls, findings: list) -> dict:
        """
        Produce a summary dict from a list of raw findings.

        Returns:
            dict: {
                total_secrets, by_severity, by_type, affected_files, highest_severity
            }
        """
        if not findings:
            return {
                "total_secrets": 0,
                "by_severity": {},
                "by_type": {},
                "affected_files": [],
                "highest_severity": None,
            }

        by_severity: dict = {}
        by_type: dict = {}
        affected: set = set()
        max_sev = -1
        max_sev_label: str = "LOW"

        for f in findings:
            sev = f["severity"]
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_type[f["type"]] = by_type.get(f["type"], 0) + 1
            affected.add(f["file"])

            sev_idx = cls.SEVERITY_ORDER.get(sev, 0)
            if sev_idx > max_sev:
                max_sev = sev_idx
                max_sev_label = sev

        return {
            "total_secrets": len(findings),
            "by_severity": by_severity,
            "by_type": by_type,
            "affected_files": sorted(affected),
            "highest_severity": max_sev_label,
        }

    @classmethod
    def print_report(cls, findings: list) -> None:
        """Pretty-print a tabular report of findings to stdout."""
        summary = cls.summarize(findings)

        print("\n" + "=" * 70)
        print("  SECRET SCAN REPORT")
        print("=" * 70)

        if summary["total_secrets"] == 0:
            print("  ✅ No secrets or API keys detected.")
            print("=" * 70 + "\n")
            return

        print(f"  Total secrets found : {summary['total_secrets']}")
        print(f"  Highest severity    : {summary['highest_severity']}")
        print(f"  Affected files      : {len(summary['affected_files'])}")
        print("-" * 70)

        # Group by severity (descending)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            sev_findings = [f for f in findings if f["severity"] == sev]
            if not sev_findings:
                continue
            print(f"\n  [{sev}] ({len(sev_findings)} finding(s))")
            for f in sev_findings:
                print(f"    • {f['type']}")
                print(f"      File    : {f['file']}:{f['line']}")
                print(f"      Redacted: {f['redacted_snippet']}")
                print(f"      Entropy : {f['entropy']}")

        print("\n" + "=" * 70 + "\n")
