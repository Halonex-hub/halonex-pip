import os
import re
import importlib.metadata
import json
from .config import Config
from .utils import calculate_similarity, is_safe_package
from .analyzers import NPMAnalyzer


class Scanner:
    """
    Analyzes the project structure, installed packages, and detects potential
    supply-chain risks such as typo-squatting (ghost packages), suspicious
    metadata, and namespace confusion.
    """

    # ------------------------------------------------------------------
    # Heuristic thresholds
    # ------------------------------------------------------------------
    TYPOSQUAT_THRESHOLD: float = 0.85   # name similarity to flag
    HIGH_CONFIDENCE_THRESHOLD: float = 0.95

    # Common "confusable" transformations used in typo-squatting
    _CONFUSABLE_SUBS = [
        ("-", "_"), ("_", "-"), ("-", ""), ("_", ""),
        ("py", ""), ("python-", ""), ("python_", ""),
        ("0", "o"), ("1", "l"), ("l", "1"),
    ]

    # ------------------------------------------------------------------
    #  scan_installed_packages
    # ------------------------------------------------------------------

    @classmethod
    def scan_installed_packages(cls) -> dict:
        """
        Comprehensive scan of every installed Python package and any NPM
        dependencies discovered via ``package.json``.

        For each Python package the scanner collects:
        * Name, version, install location, homepage, author, license
        * Whether it is a **ghost / typo-squat** of a known safe package
        * Metadata **anomaly flags** (missing homepage, missing author, etc.)

        Returns:
            dict with keys ``python``, ``npm``, ``total_packages``, ``ghost_packages``
        """
        # --- Python Scan ---
        py_installed: list = []
        ghosts: list = []
        anomalies: list = []

        dists = list(importlib.metadata.distributions())
        dist_map: dict = {}  # name_lower -> metadata dict

        for dist in dists:
            meta = dist.metadata
            name = meta["Name"]
            name_lower = name.lower()
            version = meta.get("Version", "0.0.0")
            summary = meta.get("Summary", "")
            author = meta.get("Author", "") or meta.get("Author-email", "")
            homepage = (
                meta.get("Home-page", "")
                or meta.get("Project-URL", "")
            )
            license_str = meta.get("License", "")

            # Location on disk
            location = ""
            if dist._path:
                location = str(dist._path)

            pkg_info = {
                "name": name,
                "version": version,
                "summary": summary[:120] if summary else "",
                "author": author,
                "homepage": homepage,
                "license": license_str[:60] if license_str else "",
                "location": location,
            }

            py_installed.append(pkg_info)
            dist_map[name_lower] = pkg_info

            # --- Typo-squat / Ghost detection ---
            if not is_safe_package(name):
                cls._check_typosquat(name, name_lower, ghosts)

            # --- Metadata anomaly checks ---
            cls._check_metadata_anomalies(name, pkg_info, anomalies)

        # Sort installed list alphabetically for readability
        py_installed.sort(key=lambda p: p["name"].lower())

        # Deduplicate ghosts (same package can match multiple safe names)
        seen_ghosts = set()
        unique_ghosts = []
        for g in ghosts:
            key = g["name"].lower()
            if key not in seen_ghosts:
                seen_ghosts.add(key)
                unique_ghosts.append(g)

        python_report = {
            "total_packages": len(py_installed),
            "installed_list": [p["name"] for p in py_installed],
            "installed_details": py_installed,
            "ghost_packages": unique_ghosts,
            "anomalies": anomalies,
        }

        # --- NPM Scan ---
        npm_report = NPMAnalyzer.analyze_package_json(".")

        # Also check for npm typo-squatting against popular packages
        npm_ghosts = cls._check_npm_ghosts(npm_report)

        return {
            "python": python_report,
            "npm": npm_report,
            "npm_ghosts": npm_ghosts,
            "total_packages": len(py_installed) + len(npm_report.get("dependencies", {})),
            "ghost_packages": unique_ghosts,  # backward compat
        }

    # ------------------------------------------------------------------
    #  Typo-squat helpers
    # ------------------------------------------------------------------

    @classmethod
    def _check_typosquat(cls, name: str, name_lower: str, ghosts: list):
        """Compare *name* against every entry in ``Config.SAFE_LIST``."""
        for safe_pkg in Config.SAFE_LIST:
            if name_lower == safe_pkg:
                continue  # exact match = legitimate

            # Direct similarity
            sim = calculate_similarity(name_lower, safe_pkg)
            if sim >= cls.TYPOSQUAT_THRESHOLD:
                confidence = "high" if sim >= cls.HIGH_CONFIDENCE_THRESHOLD else "medium"
                ghosts.append({
                    "name": name,
                    "similar_to": safe_pkg,
                    "score": round(sim, 4),
                    "confidence": confidence,
                    "technique": "name-similarity",
                    "warning": f"Potential typo-squatting detected ({confidence} confidence).",
                })
                continue  # don't double-flag with confusable check

            # Confusable substitutions (e.g. python-requests vs requests)
            for old, new in cls._CONFUSABLE_SUBS:
                variant = name_lower.replace(old, new)
                if variant == safe_pkg and variant != name_lower:
                    ghosts.append({
                        "name": name,
                        "similar_to": safe_pkg,
                        "score": 0.95,
                        "confidence": "high",
                        "technique": f"confusable-substitution ({old!r}→{new!r})",
                        "warning": "Name becomes a known package after character substitution.",
                    })
                    break

    # ------------------------------------------------------------------
    #  Metadata anomaly heuristics
    # ------------------------------------------------------------------

    @classmethod
    def _check_metadata_anomalies(cls, name: str, info: dict, anomalies: list):
        """Flag packages with suspicious or missing metadata."""
        flags: list = []

        if not info.get("author"):
            flags.append("missing-author")
        if not info.get("homepage"):
            flags.append("missing-homepage")
        if not info.get("summary"):
            flags.append("missing-summary")
        if not info.get("license"):
            flags.append("missing-license")

        # Very short name (2 chars) — common in squatting
        if len(name) <= 2:
            flags.append("very-short-name")

        # Name contains both hyphens and underscores (unusual)
        if "-" in name and "_" in name:
            flags.append("mixed-separators")

        if flags:
            anomalies.append({
                "package": name,
                "version": info.get("version", "?"),
                "flags": flags,
            })

    # ------------------------------------------------------------------
    #  NPM ghost detection
    # ------------------------------------------------------------------

    # Top npm packages to check typo-squatting against
    _NPM_SAFE_LIST = {
        "express", "react", "react-dom", "vue", "angular", "next",
        "lodash", "axios", "moment", "webpack", "babel", "typescript",
        "eslint", "prettier", "jest", "mocha", "chai", "npm",
        "node-fetch", "chalk", "commander", "inquirer", "mongoose",
        "socket.io", "cors", "dotenv", "jsonwebtoken", "bcrypt",
        "passport", "sequelize", "pg", "mysql2", "redis",
    }

    @classmethod
    def update_npm_safe_list(cls, packages: set) -> None:
        """Hot-swap the npm safe list with a CDN-provided set."""
        cls._NPM_SAFE_LIST = packages

    @classmethod
    def _check_npm_ghosts(cls, npm_report: dict) -> list:
        """Check npm deps for typo-squatting against popular packages."""
        ghosts: list = []
        if not npm_report.get("exists"):
            return ghosts

        all_deps = set()
        all_deps.update(npm_report.get("dependencies", {}).keys())
        all_deps.update(npm_report.get("devDependencies", {}).keys())

        for dep in all_deps:
            dep_lower = dep.lower()
            for safe in cls._NPM_SAFE_LIST:
                if dep_lower == safe:
                    continue
                sim = calculate_similarity(dep_lower, safe)
                if sim >= cls.TYPOSQUAT_THRESHOLD:
                    ghosts.append({
                        "name": dep,
                        "similar_to": safe,
                        "score": round(sim, 4),
                        "ecosystem": "npm",
                        "warning": "Potential npm typo-squatting.",
                    })
        return ghosts

    # ------------------------------------------------------------------
    #  File structure scan (unchanged)
    # ------------------------------------------------------------------

    @staticmethod
    def scan_file_structure(root_dir="."):
        """
        Recursively scans the directory to build a file tree with line counts.

        Args:
            root_dir (str): The root directory to start scanning from.

        Returns:
            dict: A nested dictionary representing the file structure.
        """
        structure = {}

        try:
            entries = os.listdir(root_dir)
        except PermissionError:
            return structure

        for item in entries:
            path = os.path.join(root_dir, item)

            if item in Config.IGNORE_DIRS or item.startswith("."):
                continue

            if os.path.isdir(path):
                structure[item] = Scanner.scan_file_structure(path)
            elif os.path.isfile(path):
                _, ext = os.path.splitext(item)
                if ext in Config.SCAN_EXTENSIONS:
                    try:
                        with open(path, "r", encoding="utf-8", errors="ignore") as f:
                            lines = sum(1 for _ in f)
                        structure[item] = {"lines": lines, "type": "file"}
                    except Exception as e:
                        structure[item] = {"error": str(e), "type": "file"}

        return structure
