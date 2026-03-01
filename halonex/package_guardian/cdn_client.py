"""
cdn_client.py — Remote resource loader for Package Guardian.

Instead of relying solely on locally‑bundled pattern files and safe‑lists,
this module fetches the latest versions from a private CDN.  It provides:

  • Authenticated HTTPS fetching (Bearer token or custom header).
  • ETag / If‑Modified‑Since conditional requests so unchanged files are
    never re‑downloaded.
  • Disk caching — downloaded resources are persisted under a platform‑
    appropriate cache directory so the scanner still works offline.
  • Automatic fallback — if the CDN is unreachable and no cache exists,
    the library falls back to the local files shipped with the package.
  • Thread‑safety — a module‑level lock guards the cache so concurrent
    scans don't corrupt state.

Usage
-----
    from halonex.packageguardian.cdn_client import CDNClient

    # One‑time init (usually in __init__.py or early in the scan thread)
    CDNClient.configure(
        base_url="https://cdn.example.com/packageguardian",
        auth_token=os.environ.get("PG_CDN_TOKEN"),   # optional Bearer token
    )

    # Fetch latest secret patterns (returns local path to the file)
    patterns_path = CDNClient.fetch_secret_patterns()

    # Fetch latest safe‑list (returns a set of package names)
    safe_set = CDNClient.fetch_safe_list()
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Set
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


# ---------------------------------------------------------------------------
# Module‑level defaults
# ---------------------------------------------------------------------------

_DEFAULT_BASE_URL = os.environ.get(
    "PG_CDN_BASE_URL",
    "https://cdn.halonex.app/packages",
)

_DEFAULT_TIMEOUT = int(os.environ.get("PG_CDN_TIMEOUT", "15"))

# Resource filenames on the CDN
_RESOURCE_SECRET_PATTERNS = "secret_patterns.txt"
_RESOURCE_SAFE_LIST       = "safe_list.json"        # JSON array of package names
_RESOURCE_NPM_SAFE_LIST   = "npm_safe_list.json"    # JSON array of npm packages

# ---------------------------------------------------------------------------
# Cache directory
# ---------------------------------------------------------------------------

def _default_cache_dir() -> Path:
    """Return a platform‑appropriate cache folder."""
    if platform.system() == "Windows":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    elif platform.system() == "Darwin":
        base = Path.home() / "Library" / "Caches"
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME", Path.home() / ".cache"))
    return base / "package-guardian"


# ---------------------------------------------------------------------------
# CDNClient
# ---------------------------------------------------------------------------

class CDNClient:
    """
    Fetches pattern files and safe‑lists from a private CDN, with
    caching, conditional requests, and graceful fallback.
    """

    # Class‑level state (configured once, shared across calls)
    _base_url: str           = _DEFAULT_BASE_URL
    _auth_token: Optional[str] = os.environ.get("PG_CDN_TOKEN")
    _auth_header: str        = "Authorization"       # header name
    _timeout: int            = _DEFAULT_TIMEOUT
    _cache_dir: Path         = _default_cache_dir()
    _etags: Dict[str, str]   = {}                    # resource → etag
    _last_modified: Dict[str, str] = {}              # resource → date string
    _refresh_interval: int   = 3600                  # seconds between re‑checks
    _last_fetch_ts: Dict[str, float] = {}            # resource → epoch
    _lock = threading.Lock()
    _configured = False

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    @classmethod
    def configure(
        cls,
        base_url: str     = None,
        auth_token: str   = None,
        auth_header: str  = None,
        timeout: int      = None,
        cache_dir: str    = None,
        refresh_interval: int = None,
    ) -> None:
        """
        Set connection parameters.  Call once during initialisation.

        Args:
            base_url:         Root URL of the CDN (no trailing slash).
            auth_token:       Bearer token (or raw value for a custom header).
            auth_header:      Header name.  Defaults to ``Authorization``.
                              When using ``Authorization`` the value is sent as
                              ``Bearer <token>``.  Any other header name sends
                              the raw token value.
            timeout:          HTTP timeout in seconds.
            cache_dir:        Override the platform‑default cache directory.
            refresh_interval: Minimum seconds between CDN checks for the same
                              resource (default 3600 = 1 hour).
        """
        with cls._lock:
            if base_url is not None:
                cls._base_url = base_url.rstrip("/")
            if auth_token is not None:
                cls._auth_token = auth_token
            if auth_header is not None:
                cls._auth_header = auth_header
            if timeout is not None:
                cls._timeout = timeout
            if cache_dir is not None:
                cls._cache_dir = Path(cache_dir)
            if refresh_interval is not None:
                cls._refresh_interval = refresh_interval
            cls._configured = True

            # Ensure cache directory exists
            cls._cache_dir.mkdir(parents=True, exist_ok=True)

            # Load persisted ETags / Last‑Modified from a metadata file
            cls._load_meta()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def fetch_secret_patterns(cls, force: bool = False) -> str:
        """
        Download the latest ``secret_patterns.txt`` from the CDN.

        Returns:
            Absolute path to the local (cached) file.  The caller can
            pass this straight to ``SecretScanner.load_patterns(path)``.

        Falls back to the patterns file shipped with the package when
        neither the CDN nor a cached copy is available.
        """
        local_path = cls._fetch_resource(_RESOURCE_SECRET_PATTERNS, force=force)
        if local_path and local_path.exists():
            return str(local_path)

        # Fallback: bundled file
        bundled = Path(__file__).resolve().parent / "secret_patterns.txt"
        if bundled.exists():
            return str(bundled)

        return ""  # let the scanner use its builtin fallback

    @classmethod
    def fetch_safe_list(cls, force: bool = False) -> Set[str]:
        """
        Download the latest Python safe‑list from the CDN.

        Returns:
            A set of lowercase package names.  If the CDN and cache are
            both unavailable, returns an empty set (the caller should
            fall back to ``Config.SAFE_LIST``).
        """
        return cls._fetch_json_set(_RESOURCE_SAFE_LIST, force=force)

    @classmethod
    def fetch_npm_safe_list(cls, force: bool = False) -> Set[str]:
        """
        Download the latest npm safe‑list from the CDN.

        Returns:
            A set of lowercase package names.
        """
        return cls._fetch_json_set(_RESOURCE_NPM_SAFE_LIST, force=force)

    # ------------------------------------------------------------------
    # Internal — HTTP
    # ------------------------------------------------------------------

    @classmethod
    def _build_request(cls, url: str, resource: str) -> Request:
        """Build a ``urllib.request.Request`` with auth + conditional headers."""
        req = Request(url, method="GET")
        req.add_header("User-Agent", "PackageGuardian/1.0")

        # Authentication
        if cls._auth_token:
            if cls._auth_header == "Authorization":
                req.add_header("Authorization", f"Bearer {cls._auth_token}")
            else:
                req.add_header(cls._auth_header, cls._auth_token)

        # Conditional request headers (避免 re‑downloading unchanged files)
        etag = cls._etags.get(resource)
        if etag:
            req.add_header("If-None-Match", etag)
        last_mod = cls._last_modified.get(resource)
        if last_mod:
            req.add_header("If-Modified-Since", last_mod)

        return req

    @classmethod
    def _fetch_resource(cls, resource: str, *, force: bool = False) -> Optional[Path]:
        """
        Fetch *resource* from the CDN and cache it locally.

        Returns the ``Path`` to the cached file, or ``None`` on failure.
        """
        cls._ensure_cache_dir()

        cache_path = cls._cache_dir / resource

        # Throttle: skip the network call if we checked recently
        if not force:
            last_ts = cls._last_fetch_ts.get(resource, 0)
            if (time.time() - last_ts) < cls._refresh_interval and cache_path.exists():
                return cache_path

        url = f"{cls._base_url}/{resource}"
        req = cls._build_request(url, resource)

        try:
            with cls._lock:
                resp = urlopen(req, timeout=cls._timeout)
                data = resp.read()

                # Persist to cache
                cache_path.write_bytes(data)

                # Store conditional‑request tokens
                etag = resp.headers.get("ETag")
                if etag:
                    cls._etags[resource] = etag
                last_mod = resp.headers.get("Last-Modified")
                if last_mod:
                    cls._last_modified[resource] = last_mod

                cls._last_fetch_ts[resource] = time.time()
                cls._save_meta()

                print(f"[CDN]: Updated {resource} from CDN.")
                return cache_path

        except HTTPError as exc:
            if exc.code == 304:
                # Not Modified — cached version is still current
                cls._last_fetch_ts[resource] = time.time()
                return cache_path if cache_path.exists() else None
            print(f"[CDN WARNING]: HTTP {exc.code} fetching {url}")
        except (URLError, OSError) as exc:
            print(f"[CDN WARNING]: Could not reach CDN ({exc}). Using cached/local copy.")
        except Exception as exc:
            print(f"[CDN WARNING]: Unexpected error fetching {resource}: {exc}")

        # Return cache if it exists, else None
        return cache_path if cache_path.exists() else None

    @classmethod
    def _fetch_json_set(cls, resource: str, *, force: bool = False) -> Set[str]:
        """
        Fetch a JSON array resource and return a ``set`` of lowercase strings.
        """
        local_path = cls._fetch_resource(resource, force=force)
        if local_path and local_path.exists():
            try:
                raw = local_path.read_text(encoding="utf-8")
                data = json.loads(raw)
                if isinstance(data, list):
                    return {str(item).lower().strip() for item in data if item}
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                print(f"[CDN WARNING]: Failed to parse {resource}: {exc}")
        return set()

    # ------------------------------------------------------------------
    # Internal — Cache metadata persistence
    # ------------------------------------------------------------------

    @classmethod
    def _meta_path(cls) -> Path:
        return cls._cache_dir / ".cdn_meta.json"

    @classmethod
    def _save_meta(cls) -> None:
        """Persist ETags, Last‑Modified, and timestamps to disk."""
        meta = {
            "etags": cls._etags,
            "last_modified": cls._last_modified,
            "last_fetch_ts": {k: v for k, v in cls._last_fetch_ts.items()},
        }
        try:
            cls._meta_path().write_text(json.dumps(meta, indent=2), encoding="utf-8")
        except OSError:
            pass  # non‑critical

    @classmethod
    def _load_meta(cls) -> None:
        """Restore cached metadata from disk."""
        mp = cls._meta_path()
        if not mp.exists():
            return
        try:
            meta = json.loads(mp.read_text(encoding="utf-8"))
            cls._etags = meta.get("etags", {})
            cls._last_modified = meta.get("last_modified", {})
            cls._last_fetch_ts = {k: float(v) for k, v in meta.get("last_fetch_ts", {}).items()}
        except (json.JSONDecodeError, OSError):
            pass

    @classmethod
    def _ensure_cache_dir(cls) -> None:
        cls._cache_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @classmethod
    def clear_cache(cls) -> None:
        """Delete all cached resources and metadata."""
        import shutil
        with cls._lock:
            if cls._cache_dir.exists():
                shutil.rmtree(cls._cache_dir, ignore_errors=True)
            cls._etags.clear()
            cls._last_modified.clear()
            cls._last_fetch_ts.clear()
            cls._cache_dir.mkdir(parents=True, exist_ok=True)
            print("[CDN]: Cache cleared.")

    @classmethod
    def cache_info(cls) -> Dict:
        """Return a summary of cached resources and their freshness."""
        info = {"cache_dir": str(cls._cache_dir), "resources": {}}
        cls._ensure_cache_dir()
        for fp in cls._cache_dir.iterdir():
            if fp.name.startswith("."):
                continue
            age_secs = time.time() - fp.stat().st_mtime
            info["resources"][fp.name] = {
                "size_bytes": fp.stat().st_size,
                "age_seconds": round(age_secs),
                "etag": cls._etags.get(fp.name),
                "last_modified": cls._last_modified.get(fp.name),
            }
        return info

    @classmethod
    def is_configured(cls) -> bool:
        return cls._configured
