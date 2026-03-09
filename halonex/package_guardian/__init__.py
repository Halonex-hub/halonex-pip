import threading
import time
import importlib.metadata
from typing import Optional
from .config import Config, Plan
from .cdn_client import CDNClient
from .sensor import Sensor
from .scanner import Scanner
from .telemetry import Telemetry
from .scanners.secret_scanner import SecretScanner
from .scanners.db_scanner import DBScanner
from .scanners.vuln_scanner import VulnScanner
from .scanners.version_scanner import VersionScanner

__all__ = ["init"]


def _run_scan_thread(api_key: Optional[str], generate_report: bool):
    """
    Internal function executed by the daemon thread.

    Flow
    ----
    1. Validate the API key against the server -> get a ``Plan``.
    2. Run only the scanners permitted by the plan's feature set.
    3. Send telemetry with the API key (any valid key, regardless of tier).
    """
    try:
        # ==============================================================
        #  Phase 0 — Key validation
        # ==============================================================
        if api_key:
            plan = Telemetry.validate_key(api_key)
        else:
            plan = Plan()
            Config.key_validated = False

        Config.plan = plan

        # ==============================================================
        #  Phase 0b — CDN pattern updates
        # ==============================================================
        patterns_path = None
        if plan.has("cdn_updates"):
            try:
                CDNClient.configure()
                patterns_path = CDNClient.fetch_secret_patterns()
                cdn_safe = CDNClient.fetch_safe_list()
                if cdn_safe:
                    Config.SAFE_LIST = cdn_safe
                cdn_npm = CDNClient.fetch_npm_safe_list()
                if cdn_npm:
                    Scanner.update_npm_safe_list(cdn_npm)
            except Exception:
                patterns_path = None

        # ==============================================================
        #  Phase 1 — Environment Detection
        # ==============================================================
        env_data = {}
        misconfigs = {}
        framework = {}

        if plan.has("env_detection"):
            env_data = Sensor.detect_environment()

        if plan.has("misconfiguration_check"):
            misconfigs = Sensor.check_misconfigurations()

        if plan.has("framework_detection"):
            framework = Sensor.detect_framework()

        # ==============================================================
        #  Phase 2 — Package Analysis
        # ==============================================================
        package_report = {}
        if plan.has("package_listing"):
            package_report = Scanner.scan_installed_packages()

        detail_map = {}
        for pkg_detail in package_report.get('python', {}).get('installed_details', []):
            detail_map[pkg_detail['name'].lower()] = pkg_detail.get('version', '0.0.0')

        def get_version(name):
            ver = detail_map.get(name.lower())
            if ver:
                return ver
            try:
                return importlib.metadata.version(name)
            except Exception:
                return "0.0.0"

        # --- Ghost-package detection ---
        ghosts = []
        anomalies = []
        if plan.has("ghost_package_detection"):
            ghosts = package_report.get('python', {}).get('ghost_packages', [])
            anomalies = package_report.get('python', {}).get('anomalies', [])

        # --- Vulnerability scanning ---
        vulns = []
        if plan.has("vuln_scanning"):
            py_pkgs_names = package_report.get('python', {}).get('installed_list', [])[:30]
            py_pkgs = [{'name': p, 'version': get_version(p)} for p in py_pkgs_names]
            vulns = VulnScanner.check_vulnerabilities(py_pkgs, 'PyPI')

        # --- Version / outdated scanning ---
        outdated = []
        outdated_summary = {}
        if plan.has("version_scanning"):
            py_pkgs_names = package_report.get('python', {}).get('installed_list', [])[:30]
            py_pkgs = [{'name': p, 'version': get_version(p)} for p in py_pkgs_names]
            outdated = VersionScanner.check_outdated_pypi(py_pkgs, max_workers=3)
            outdated_summary = VersionScanner.summarize(outdated)

        # ==============================================================
        #  Phase 3 — File Structure Scan
        # ==============================================================
        file_tree = {}
        if plan.has("file_structure_scan"):
            file_tree = Scanner.scan_file_structure()

        # ==============================================================
        #  Phase 4 — Advanced Security Scan
        # ==============================================================
        secrets = []
        secrets_summary = {}
        db_issues = []

        if plan.has("secret_scanning"):
            if patterns_path:
                SecretScanner.load_patterns(patterns_path)
            secrets = SecretScanner.scan_directory(".", Config.IGNORE_DIRS)
            secrets_summary = SecretScanner.summarize(secrets)

        if plan.has("db_scanning"):
            db_issues = DBScanner.scan_environment()

        # ==============================================================
        #  Assemble payload
        # ==============================================================
        payload = {
            "api_key": api_key,
            "api_key_status": "present" if api_key else "missing",
            "plan_tier": plan.tier,
            "environment": env_data,
            "security_alerts": misconfigs,
            "project_type": framework,
            "package_analysis": package_report,
            "vulnerabilities": vulns,
            "outdated_packages": outdated,
            "outdated_summary": outdated_summary,
            "file_structure": file_tree,
            "secrets_detected": secrets,
            "secrets_summary": secrets_summary,
            "database_issues": db_issues,
            "timestamp": time.time(),
        }

        # ==============================================================
        #  Phase 5 — Reporting
        # ==============================================================
        Telemetry.send_report(payload, generate_html=generate_report)

    except Exception:
        pass


def init(api_key: Optional[str] = None, generate_report: bool = True):
    """
    Initializes the Package Guardian security scanner.

    Args:
        api_key: Your API key (created on the Halonex dashboard).
                 Falls back to the ``PACKAGE_GUARDIAN_API_KEY`` env var.
        generate_report: Ignored (HTML report generation removed).
    """
    if not api_key:
        api_key = Config.get_api_key()

    scan_thread = threading.Thread(
        target=_run_scan_thread,
        args=(api_key, generate_report),
        daemon=True,
        name="PackageGuardianScanner",
    )
    scan_thread.start()
    return scan_thread
