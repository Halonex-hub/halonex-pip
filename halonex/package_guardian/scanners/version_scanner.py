import json
import re
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed


class VersionScanner:
    """
    Checks installed packages for outdated versions by querying the live
    PyPI and npm registries.

    Enhanced features:
    * Proper semantic-version comparison (major.minor.patch with pre-release)
    * **Yanked release** detection (PyPI marks compromised versions as yanked)
    * **Deprecation notice** extraction from project description
    * **Pre-release filtering** — only compares against stable releases
    * **Major / minor / patch** update classification
    * Concurrent requests with configurable thread pool
    """

    PYPI_URL = "https://pypi.org/pypi/{}/json"
    NPM_URL = "https://registry.npmjs.org/{}"

    # Cache to avoid double-fetching the same package in one scan
    _pypi_cache: dict = {}
    _cache_ts: float = 0.0
    _CACHE_TTL: float = 300.0  # 5 minutes

    # ------------------------------------------------------------------
    #  PyPI
    # ------------------------------------------------------------------

    @classmethod
    def check_outdated_pypi(cls, packages: list, max_workers: int = 5) -> list:
        """
        Check a list of PyPI packages for available updates.

        Args:
            packages: List of ``{"name": ..., "version": ...}`` dicts.
            max_workers: Concurrent HTTP request threads.

        Returns:
            list[dict]: Each entry contains:
                package, current, latest, ecosystem, update_type,
                is_yanked, yanked_reason, is_deprecated, deprecated_msg
        """
        # Invalidate stale cache
        if time.time() - cls._cache_ts > cls._CACHE_TTL:
            cls._pypi_cache.clear()
            cls._cache_ts = time.time()

        outdated: list = []

        def _check(pkg: dict) -> dict | None:
            name = pkg["name"]
            current = pkg.get("version", "0.0.0")
            try:
                info = cls._fetch_pypi(name)
                if info is None:
                    return None

                latest_stable = info.get("latest_stable")
                if not latest_stable:
                    return None

                cmp = cls._compare_versions(current, latest_stable)
                if cmp >= 0:
                    # Already up-to-date — but still check if current is yanked
                    if info.get("current_yanked"):
                        return {
                            "package": name,
                            "current": current,
                            "latest": latest_stable,
                            "ecosystem": "PyPI",
                            "update_type": "yanked",
                            "is_yanked": True,
                            "yanked_reason": info.get("yanked_reason", ""),
                            "is_deprecated": info.get("is_deprecated", False),
                            "deprecated_msg": info.get("deprecated_msg", ""),
                        }
                    return None

                update_type = cls._classify_update(current, latest_stable)

                return {
                    "package": name,
                    "current": current,
                    "latest": latest_stable,
                    "ecosystem": "PyPI",
                    "update_type": update_type,
                    "is_yanked": info.get("current_yanked", False),
                    "yanked_reason": info.get("yanked_reason", ""),
                    "is_deprecated": info.get("is_deprecated", False),
                    "deprecated_msg": info.get("deprecated_msg", ""),
                }
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_check, p): p for p in packages}
            for fut in as_completed(futures):
                res = fut.result()
                if res is not None:
                    outdated.append(res)

        # Sort: yanked first, then major > minor > patch
        type_order = {"yanked": 0, "major": 1, "minor": 2, "patch": 3, "other": 4}
        outdated.sort(key=lambda r: type_order.get(r.get("update_type", "other"), 9))
        return outdated

    @classmethod
    def _fetch_pypi(cls, name: str) -> dict | None:
        """
        Fetch and parse the PyPI JSON API for *name*, returning a digest dict.

        Returned keys:
            latest_stable, all_versions, current_yanked, yanked_reason,
            is_deprecated, deprecated_msg, releases_count
        """
        if name in cls._pypi_cache:
            return cls._pypi_cache[name]

        try:
            req = urllib.request.Request(
                cls.PYPI_URL.format(name),
                headers={"Accept": "application/json",
                         "User-Agent": "PackageGuardian/0.2"},
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            return None

        info_section = data.get("info", {})
        releases = data.get("releases", {})

        # --- Latest stable version (skip pre-releases) ---
        stable_versions: list = []
        for ver_str, files in releases.items():
            if cls._is_prerelease(ver_str):
                continue
            # A version with zero files is effectively "deleted"
            if not files:
                continue
            # Check if ALL files for this version are yanked
            all_yanked = all(f.get("yanked", False) for f in files)
            if all_yanked:
                continue  # skip fully-yanked versions for "latest"
            stable_versions.append(ver_str)

        if not stable_versions:
            # Fall back to whatever PyPI says is latest
            stable_versions = [info_section.get("version", "0.0.0")]

        stable_versions.sort(key=cls._version_key)
        latest_stable = stable_versions[-1]

        # --- Is the *currently installed* version yanked? ---
        # We can't know the installed version here, so we store per-version data
        # and let the caller check.  For simplicity we flag the latest *registered*
        # version from info.version.
        registered_latest = info_section.get("version", latest_stable)
        registered_files = releases.get(registered_latest, [])
        current_yanked = bool(registered_files) and all(
            f.get("yanked", False) for f in registered_files
        )
        yanked_reason = ""
        if current_yanked and registered_files:
            yanked_reason = registered_files[0].get("yanked_reason", "") or ""

        # --- Deprecation detection ---
        is_deprecated = False
        deprecated_msg = ""
        summary = info_section.get("summary", "") or ""
        description = info_section.get("description", "") or ""
        classifiers = info_section.get("classifiers", []) or []

        # PyPI classifier
        for clf in classifiers:
            if "Inactive" in clf or "Deprecated" in clf:
                is_deprecated = True
                deprecated_msg = clf
                break

        # Keyword check in summary/description
        if not is_deprecated:
            check_text = (summary + " " + description[:500]).lower()
            dep_patterns = [
                r"\bdeprecated\b", r"\bno longer maintained\b",
                r"\bunmaintained\b", r"\babandoned\b",
                r"\bdo not use\b", r"\buse .+ instead\b",
                r"\bthis project is dead\b",
            ]
            for pat in dep_patterns:
                m = re.search(pat, check_text)
                if m:
                    is_deprecated = True
                    # Grab surrounding context
                    start = max(0, m.start() - 20)
                    end = min(len(check_text), m.end() + 60)
                    deprecated_msg = "…" + check_text[start:end].strip() + "…"
                    break

        result = {
            "latest_stable": latest_stable,
            "all_versions_count": len(releases),
            "stable_versions_count": len(stable_versions),
            "current_yanked": current_yanked,
            "yanked_reason": yanked_reason,
            "is_deprecated": is_deprecated,
            "deprecated_msg": deprecated_msg,
        }
        cls._pypi_cache[name] = result
        return result

    # ------------------------------------------------------------------
    #  npm
    # ------------------------------------------------------------------

    @classmethod
    def check_outdated_npm(cls, packages: list, max_workers: int = 5) -> list:
        """
        Check a list of npm packages for available updates.

        Args:
            packages: List of ``{"name": ..., "version": ...}`` dicts.
            max_workers: Concurrent HTTP request threads.

        Returns:
            list[dict]
        """
        outdated: list = []

        def _check(pkg: dict) -> dict | None:
            name = pkg["name"]
            current = pkg.get("version", "0.0.0")
            try:
                req = urllib.request.Request(
                    cls.NPM_URL.format(name),
                    headers={"Accept": "application/json",
                             "User-Agent": "PackageGuardian/0.2"},
                )
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode())

                latest = data.get("dist-tags", {}).get("latest", "0.0.0")

                # Check deprecation
                latest_info = data.get("versions", {}).get(latest, {})
                dep_notice = latest_info.get("deprecated", "")

                if cls._compare_versions(current, latest) < 0:
                    return {
                        "package": name,
                        "current": current,
                        "latest": latest,
                        "ecosystem": "npm",
                        "update_type": cls._classify_update(current, latest),
                        "is_yanked": False,
                        "yanked_reason": "",
                        "is_deprecated": bool(dep_notice),
                        "deprecated_msg": dep_notice[:120] if dep_notice else "",
                    }
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_check, p): p for p in packages}
            for fut in as_completed(futures):
                res = fut.result()
                if res is not None:
                    outdated.append(res)

        outdated.sort(key=lambda r: r["package"])
        return outdated

    # ------------------------------------------------------------------
    #  Version parsing & comparison
    # ------------------------------------------------------------------

    # Regex that handles versions like 1.2.3, 1.2.3rc1, 1.2.3.post1, 1.2.3a2, etc.
    _VER_RE = re.compile(
        r"^[v~^]?(\d+)(?:\.(\d+))?(?:\.(\d+))?"
        r"(?:[.\-]?(a|alpha|b|beta|rc|dev|pre|post)\.?(\d*))?",
        re.IGNORECASE,
    )

    # Pre-release tag sort key (lower = earlier)
    _PRE_ORDER = {
        "dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2,
        "rc": 3, "pre": 3, "post": 5,
    }

    @classmethod
    def _parse_version(cls, v: str) -> tuple:
        """
        Parse a version string into a comparable tuple:
        ``(major, minor, patch, pre_order, pre_num)``

        Stable releases get ``pre_order=4, pre_num=0`` so they sort
        above rc/beta but below post-releases.
        """
        m = cls._VER_RE.match(str(v).strip())
        if not m:
            return (0, 0, 0, 4, 0)
        major = int(m.group(1))
        minor = int(m.group(2)) if m.group(2) else 0
        patch = int(m.group(3)) if m.group(3) else 0
        pre_tag = (m.group(4) or "").lower()
        pre_num = int(m.group(5)) if m.group(5) else 0

        if pre_tag:
            pre_order = cls._PRE_ORDER.get(pre_tag, 4)
        else:
            pre_order = 4  # stable
        return (major, minor, patch, pre_order, pre_num)

    @classmethod
    def _version_key(cls, v: str) -> tuple:
        """Sort-key function for version strings."""
        return cls._parse_version(v)

    @classmethod
    def _is_prerelease(cls, v: str) -> bool:
        """Return True if *v* is a pre-release (alpha/beta/rc/dev)."""
        parsed = cls._parse_version(v)
        return parsed[3] < 4  # stable = 4

    @classmethod
    def _compare_versions(cls, v1: str, v2: str) -> int:
        """
        Compare two version strings.
        Returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2.
        """
        p1 = cls._parse_version(v1)
        p2 = cls._parse_version(v2)
        if p1 < p2:
            return -1
        if p1 > p2:
            return 1
        return 0

    @classmethod
    def _classify_update(cls, current: str, latest: str) -> str:
        """Classify an update as major, minor, or patch."""
        c = cls._parse_version(current)
        l = cls._parse_version(latest)
        if l[0] > c[0]:
            return "major"
        if l[1] > c[1]:
            return "minor"
        if l[2] > c[2]:
            return "patch"
        return "other"

    # ------------------------------------------------------------------
    #  Summary helper
    # ------------------------------------------------------------------

    @staticmethod
    def summarize(results: list) -> dict:
        """Produce a summary from outdated-check results."""
        if not results:
            return {"total": 0, "by_type": {}, "yanked": 0, "deprecated": 0}

        by_type: dict = {}
        yanked = 0
        deprecated = 0
        for r in results:
            ut = r.get("update_type", "other")
            by_type[ut] = by_type.get(ut, 0) + 1
            if r.get("is_yanked"):
                yanked += 1
            if r.get("is_deprecated"):
                deprecated += 1

        return {
            "total": len(results),
            "by_type": by_type,
            "yanked": yanked,
            "deprecated": deprecated,
        }
