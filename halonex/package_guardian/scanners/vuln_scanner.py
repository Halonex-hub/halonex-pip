import json
import re
import time
import urllib.request
import urllib.error

from ..telemetry import _log


class VulnScanner:
    """
    Scans installed packages for known vulnerabilities using the OSV API.
    """

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    # ------------------------------------------------------------------
    #  Public API
    # ------------------------------------------------------------------

    @classmethod
    def check_vulnerabilities(cls, packages: list, ecosystem: str) -> list:
        """
        Query OSV for vulnerabilities affecting the given packages.

        Args:
            packages: list of {"name": str, "version": str} dicts.
            ecosystem: "PyPI" or "npm".

        Returns:
            list of vulnerability dicts matching the design-spec shape.
            Empty list on any failure (never raises).
        """
        if not packages:
            return []

        # Normalise input — require dict with name + version
        clean = []
        for pkg in packages:
            if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
                clean.append({"name": pkg["name"], "version": pkg["version"]})
        if not clean:
            return []

        out = []
        seen = {}  # (package, id) -> index in out

        BATCH = 100
        for start in range(0, len(clean), BATCH):
            chunk = clean[start:start + BATCH]
            queries = [{
                "package": {"name": p["name"], "ecosystem": ecosystem},
                "version": p["version"],
            } for p in chunk]

            body = cls._post_with_retry(cls.OSV_BATCH_URL, {"queries": queries})
            if not body:
                continue

            results = body.get("results") or []
            for idx, result in enumerate(results):
                if idx >= len(chunk):
                    break
                pkg_name = chunk[idx]["name"]
                pkg_version = chunk[idx]["version"]
                for vuln in (result.get("vulns") or []):
                    vid = vuln.get("id")
                    if not vid:
                        continue

                    score, bucket = cls._extract_cvss(vuln.get("severity"))
                    fixed = cls._extract_fixed_version(vuln.get("affected"))

                    if cls._is_patched(pkg_version, fixed):
                        continue

                    refs = [r.get("url") for r in (vuln.get("references") or []) if r.get("url")]

                    entry = {
                        "package":       pkg_name,
                        "version":       pkg_version,
                        "ecosystem":     ecosystem,
                        "id":            vid,
                        "aliases":       list(vuln.get("aliases") or []),
                        "summary":       vuln.get("summary", "") or "",
                        "severity":      bucket,
                        "cvss_score":    score,
                        "fixed_version": fixed,
                        "references":    refs,
                    }

                    key = (pkg_name, vid)
                    if key in seen:
                        # Keep the higher-severity duplicate
                        existing = out[seen[key]]
                        if cls._severity_rank(bucket) > cls._severity_rank(existing["severity"]):
                            out[seen[key]] = entry
                    else:
                        seen[key] = len(out)
                        out.append(entry)

        return out

    # ------------------------------------------------------------------
    #  CVSS helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _bucket_severity(cvss_score):
        """Map a CVSS base score to a five-bucket severity label."""
        if cvss_score is None:
            return "info"
        try:
            score = float(cvss_score)
        except (TypeError, ValueError):
            return "info"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score > 0:
            return "low"
        return "info"

    @classmethod
    def _extract_cvss(cls, severity_list):
        """
        Pull highest base score from an OSV-style severity array.
        Accepts numeric scores or CVSS vector strings.
        Returns (score_or_None, bucket_label).
        """
        if not severity_list:
            return None, "info"
        best = None
        for entry in severity_list:
            if not isinstance(entry, dict):
                continue
            raw = entry.get("score")
            score = None
            if isinstance(raw, (int, float)):
                score = float(raw)
            elif isinstance(raw, str):
                try:
                    score = float(raw)
                except ValueError:
                    m = re.search(r"(?:BS|baseScore)[:=]\s*(\d+\.?\d*)", raw)
                    if m:
                        score = float(m.group(1))
            if score is not None and (best is None or score > best):
                best = score
        return best, cls._bucket_severity(best)

    @staticmethod
    def _extract_fixed_version(affected):
        """Walk OSV affected[].ranges[].events[] and return the first 'fixed' value."""
        if not affected:
            return None
        for a in affected:
            for rng in (a.get("ranges") or []):
                for event in (rng.get("events") or []):
                    if "fixed" in event:
                        return event["fixed"]
        return None

    @staticmethod
    def _is_patched(installed, fixed):
        """True if installed version >= fixed version."""
        if not installed or not fixed:
            return False
        try:
            from .version_scanner import VersionScanner
            return VersionScanner._compare_versions(installed, fixed) >= 0
        except Exception:
            return False

    @staticmethod
    def _severity_rank(sev):
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)

    # ------------------------------------------------------------------
    #  HTTP helper
    # ------------------------------------------------------------------

    @staticmethod
    def _post_with_retry(url, payload, retries=2, timeout=15):
        """POST JSON with exponential backoff. Returns parsed response dict or None."""
        delay = 0.5
        for attempt in range(retries + 1):
            try:
                data = json.dumps(payload).encode("utf-8")
                req = urllib.request.Request(url, data=data, method="POST")
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    if getattr(resp, "status", 200) == 200:
                        return json.loads(resp.read().decode("utf-8"))
            except Exception as e:
                if attempt == retries:
                    _log(f"[VULN SCAN WARNING]: OSV unreachable after {retries + 1} attempts: {e}")
                    return None
                time.sleep(delay)
                delay *= 3
        return None
