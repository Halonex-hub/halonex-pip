import threading
import time
import importlib.metadata
from typing import Optional
from .config import Config
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
    
    Args:
        api_key (Optional[str]): The provided API key.
        generate_report (bool): Whether to generate the HTML dashboard.
    """
    try:
        # Phase 0: Fetch latest resources from CDN (if configured)
        try:
            CDNClient.configure()  # reads env vars PG_CDN_BASE_URL / PG_CDN_TOKEN
            patterns_path = CDNClient.fetch_secret_patterns()
            cdn_safe = CDNClient.fetch_safe_list()
            if cdn_safe:
                Config.SAFE_LIST = cdn_safe  # hot-swap the safe list
            cdn_npm = CDNClient.fetch_npm_safe_list()
            if cdn_npm:
                Scanner.update_npm_safe_list(cdn_npm)
        except Exception as exc:
            patterns_path = None
            print(f"[CDN]: Skipped — {exc}")

        # Phase 1: Environment Detection
        env_data = Sensor.detect_environment()
        misconfigs = Sensor.check_misconfigurations()
        framework = Sensor.detect_framework()

        # Phase 2: Package Analysis
        package_report = Scanner.scan_installed_packages()
        
        # Helper to get version from installed detail records
        detail_map = {}
        for pkg_detail in package_report.get('python', {}).get('installed_details', []):
            detail_map[pkg_detail['name'].lower()] = pkg_detail.get('version', '0.0.0')

        def get_version(name):
            ver = detail_map.get(name.lower())
            if ver:
                return ver
            try:
                return importlib.metadata.version(name)
            except:
                return "0.0.0"

        # Check Python Vulns (limit to first 30 to avoid slow scan in demo)
        py_pkgs_names = package_report.get('python', {}).get('installed_list', [])[:30]
        py_pkgs = [{'name': p, 'version': get_version(p)} for p in py_pkgs_names]
        
        vulns = VulnScanner.check_vulnerabilities(py_pkgs, 'PyPI')
        
        # Check Outdated Packages (Python)
        outdated = VersionScanner.check_outdated_pypi(py_pkgs, max_workers=3)
        outdated_summary = VersionScanner.summarize(outdated)

        # Print package analysis summary
        ghosts = package_report.get('python', {}).get('ghost_packages', [])
        anomalies = package_report.get('python', {}).get('anomalies', [])
        if ghosts:
            print(f"\n[PACKAGE SCAN]: ⚠ {len(ghosts)} potential typo-squat package(s) detected!")
            for g in ghosts:
                print(f"  • {g['name']} → resembles '{g['similar_to']}' "
                      f"(score={g['score']}, {g.get('technique', 'similarity')})")
        if anomalies:
            print(f"[PACKAGE SCAN]: {len(anomalies)} package(s) with metadata anomalies.")

        if outdated:
            print(f"\n[VERSION SCAN]: {len(outdated)} outdated package(s) found.")
            yanked_count = outdated_summary.get('yanked', 0)
            dep_count = outdated_summary.get('deprecated', 0)
            if yanked_count:
                print(f"  🚨 {yanked_count} package(s) are YANKED (potentially compromised)!")
            if dep_count:
                print(f"  ⚠ {dep_count} package(s) are DEPRECATED.")
            for o in outdated[:10]:
                tag = ""
                if o.get('is_yanked'):
                    tag = " [YANKED]"
                elif o.get('is_deprecated'):
                    tag = " [DEPRECATED]"
                print(f"  • {o['package']}: {o['current']} → {o['latest']} "
                      f"({o.get('update_type', '?')}){tag}")
            if len(outdated) > 10:
                print(f"  ... and {len(outdated) - 10} more.")

        # Phase 3: File Structure Scan
        file_tree = Scanner.scan_file_structure()
        
        # Phase 4: Advanced Security Scan
        if patterns_path:
            SecretScanner.load_patterns(patterns_path)
        secrets = SecretScanner.scan_directory(".", Config.IGNORE_DIRS)
        secrets_summary = SecretScanner.summarize(secrets)
        SecretScanner.print_report(secrets)
        db_issues = DBScanner.scan_environment()
        
        # Combine everything into one JSON payload
        payload = {
            "api_key": api_key, # Include API key for authentication in Telemetry
            "api_key_status": "present" if api_key else "missing",
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
            "timestamp": time.time()
        }

        # Send Report & Generate Dashboard
        Telemetry.send_report(payload, generate_html=generate_report)

    except Exception as e:
        print(f"[PACKAGE GUARDIAN ERROR]: Scan failed: {e}")


def init(api_key: Optional[str] = None, generate_report: bool = True):
    """
    Initializes the Package Guardian security scanner.
    
    Starts a non-blocking background thread that:
    1. Detects the runtime environment and framework.
    2. Scans for misconfigurations and ghost packages.
    3. Analyzes the file structure.
    4. Sends a diagnostic report (mocked) and generates a local dashboard.
    
    Args:
        api_key (Optional[str], optional): Your unique API key. If not provided,
                                 defaults to PACKAGE_GUARDIAN_API_KEY env var.
        generate_report (bool, optional): Whether to create the security_report.html.
                                          Defaults to True.
    """
    # 1. Load Configuration
    if not api_key:
        api_key = Config.get_api_key()
    
    if not api_key:
        print("[PACKAGE GUARDIAN WARNING]: No API Key found. Scanning will proceed in demo mode.")

    # 2. Start Background Thread
    scan_thread = threading.Thread(
        target=_run_scan_thread,
        args=(api_key, generate_report),
        daemon=True,
        name="PackageGuardianScanner"
    )
    
    scan_thread.start()
    
    # 3. Return the thread object so consumers can join it if needed
    return scan_thread
