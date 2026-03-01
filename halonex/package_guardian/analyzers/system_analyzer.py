import os
import shutil
import subprocess
import platform
import re


class SystemAnalyzer:
    """
    Analyzes system-level package managers, tools, resources, and network
    configuration.  All methods degrade gracefully on permission errors or
    missing tools so the scanner never crashes.
    """

    # ------------------------------------------------------------------
    # Package managers
    # ------------------------------------------------------------------

    @staticmethod
    def detect_package_managers() -> dict:
        """
        Detect available system & language package managers.

        Returns:
            dict: ``{name: path}`` for every manager found on ``$PATH``.
        """
        managers = [
            # System
            "apt", "apt-get", "dnf", "yum", "pacman", "zypper",
            "apk", "brew", "port", "choco", "scoop", "winget",
            # Language / ecosystem
            "pip", "pip3", "pipx", "conda", "poetry", "pdm", "uv",
            "npm", "npx", "yarn", "pnpm", "bun",
            "cargo", "go", "gem", "bundler", "composer",
            "nuget", "dotnet", "maven", "gradle",
        ]
        return {m: shutil.which(m) for m in managers if shutil.which(m)}

    # ------------------------------------------------------------------
    # Development tools
    # ------------------------------------------------------------------

    @staticmethod
    def check_installed_tools() -> dict:
        """
        Probe for common dev-ops / development tools and capture versions.

        Returns:
            dict: ``{tool: {"path": ..., "version": ...}}``
        """
        tools = [
            "git", "docker", "docker-compose", "podman",
            "kubectl", "helm", "terraform", "ansible",
            "node", "python3", "python", "java", "go",
            "rustc", "ruby", "php", "dotnet",
            "aws", "az", "gcloud", "gh",
            "make", "cmake", "gcc", "g++", "clang",
            "openssl", "ssh", "curl", "wget",
        ]
        found: dict = {}
        for tool in tools:
            path = shutil.which(tool)
            if not path:
                continue
            version_str = "Unknown"
            try:
                result = subprocess.run(
                    [tool, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                # Some tools print to stderr (e.g. java)
                raw = result.stdout.strip() or result.stderr.strip()
                # Keep only the first line — many tools dump paragraphs
                version_str = raw.splitlines()[0] if raw else "Unknown"
            except Exception:
                pass
            found[tool] = {"path": path, "version": version_str}
        return found

    # ------------------------------------------------------------------
    # CPU / RAM / Disk
    # ------------------------------------------------------------------

    @staticmethod
    def get_resource_usage() -> dict:
        """
        Collect basic CPU, memory, and disk metrics **without** psutil.

        Returns:
            dict with keys ``cpu``, ``memory``, ``disk``.
        """
        info: dict = {"cpu": {}, "memory": {}, "disk": {}}

        # --- CPU ---
        info["cpu"]["logical_cores"] = os.cpu_count() or 0
        info["cpu"]["architecture"] = platform.machine()
        info["cpu"]["processor"] = platform.processor() or "Unknown"

        # On Linux, parse /proc/cpuinfo for model name
        if os.path.isfile("/proc/cpuinfo"):
            try:
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if line.startswith("model name"):
                            info["cpu"]["model"] = line.split(":", 1)[1].strip()
                            break
            except Exception:
                pass

        # On Windows, use PowerShell for CPU name (wmic is deprecated on Win11+)
        if platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command",
                     "(Get-CimInstance Win32_Processor).Name"],
                    text=True, timeout=10,
                )
                name = out.strip()
                if name:
                    info["cpu"]["model"] = name
            except Exception:
                pass

        # --- Memory ---
        if os.path.isfile("/proc/meminfo"):
            try:
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        key, _, val = line.partition(":")
                        val = val.strip()
                        if key == "MemTotal":
                            info["memory"]["total_kb"] = int(re.sub(r"[^\d]", "", val))
                        elif key == "MemAvailable":
                            info["memory"]["available_kb"] = int(re.sub(r"[^\d]", "", val))
            except Exception:
                pass
        elif platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    ["powershell", "-NoProfile", "-Command",
                     "$os = Get-CimInstance Win32_OperatingSystem; "
                     "Write-Output \"TotalVisibleMemorySize=$($os.TotalVisibleMemorySize)\"; "
                     "Write-Output \"FreePhysicalMemory=$($os.FreePhysicalMemory)\""],
                    text=True, timeout=10,
                )
                for line in out.splitlines():
                    if line.startswith("TotalVisibleMemorySize="):
                        info["memory"]["total_kb"] = int(line.split("=")[1])
                    elif line.startswith("FreePhysicalMemory="):
                        info["memory"]["available_kb"] = int(line.split("=")[1])
            except Exception:
                pass

        # Friendly MB/GB conversions
        total_kb = info["memory"].get("total_kb", 0)
        avail_kb = info["memory"].get("available_kb", 0)
        if total_kb:
            info["memory"]["total_mb"] = round(total_kb / 1024, 1)
            info["memory"]["total_gb"] = round(total_kb / 1024 / 1024, 2)
        if avail_kb:
            info["memory"]["available_mb"] = round(avail_kb / 1024, 1)
        if total_kb and avail_kb:
            info["memory"]["used_percent"] = round((1 - avail_kb / total_kb) * 100, 1)

        # --- Disk (CWD partition) ---
        try:
            usage = shutil.disk_usage(".")
            info["disk"]["total_gb"] = round(usage.total / (1024 ** 3), 2)
            info["disk"]["used_gb"] = round(usage.used / (1024 ** 3), 2)
            info["disk"]["free_gb"] = round(usage.free / (1024 ** 3), 2)
            info["disk"]["used_percent"] = round(usage.used / usage.total * 100, 1) if usage.total else 0
        except Exception:
            pass

        return info

    # ------------------------------------------------------------------
    # Virtualisation / container detection
    # ------------------------------------------------------------------

    @staticmethod
    def detect_virtualisation() -> dict:
        """
        Detect whether we're running inside Docker, a VM, WSL, or a CI runner.

        Returns:
            dict: ``{is_docker, is_wsl, is_vm, is_ci, ci_platform, container_runtime}``
        """
        result: dict = {
            "is_docker": False,
            "is_kubernetes": False,
            "is_wsl": False,
            "is_vm": False,
            "is_ci": False,
            "ci_platform": None,
            "container_runtime": None,
        }

        # --- Docker ---
        if os.path.exists("/.dockerenv"):
            result["is_docker"] = True
            result["container_runtime"] = "docker"
        elif os.path.isfile("/proc/1/cgroup"):
            try:
                with open("/proc/1/cgroup", "r") as f:
                    cg = f.read()
                if "docker" in cg:
                    result["is_docker"] = True
                    result["container_runtime"] = "docker"
                elif "kubepods" in cg:
                    result["is_kubernetes"] = True
                    result["container_runtime"] = "kubernetes"
            except Exception:
                pass

        # --- WSL ---
        if os.path.isfile("/proc/version"):
            try:
                with open("/proc/version", "r") as f:
                    if "microsoft" in f.read().lower():
                        result["is_wsl"] = True
            except Exception:
                pass

        # --- VM (Linux: check for hypervisor in cpuinfo or dmi) ---
        if os.path.isfile("/proc/cpuinfo"):
            try:
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read().lower()
                if any(h in cpuinfo for h in ("hypervisor", "vmware", "virtualbox", "kvm", "xen", "qemu")):
                    result["is_vm"] = True
            except Exception:
                pass

        # --- CI / CD platforms ---
        ci_map = {
            "GITHUB_ACTIONS": "GitHub Actions",
            "GITLAB_CI": "GitLab CI",
            "JENKINS_URL": "Jenkins",
            "CIRCLECI": "CircleCI",
            "TRAVIS": "Travis CI",
            "BITBUCKET_PIPELINE": "Bitbucket Pipelines",
            "CODEBUILD_BUILD_ID": "AWS CodeBuild",
            "AZURE_PIPELINE": "Azure DevOps Pipelines",
            "TF_BUILD": "Azure DevOps",
            "TEAMCITY_VERSION": "TeamCity",
            "BUILDKITE": "Buildkite",
            "DRONE": "Drone CI",
            "HEROKU_TEST_RUN_ID": "Heroku CI",
            "RENDER": "Render",
            "VERCEL": "Vercel",
            "NETLIFY": "Netlify",
            "CI": "Generic CI",
        }
        for env_var, name in ci_map.items():
            if os.environ.get(env_var):
                result["is_ci"] = True
                result["ci_platform"] = name
                break  # first match wins (most specific keys are listed first)

        return result

    # ------------------------------------------------------------------
    # Network interfaces (basic)
    # ------------------------------------------------------------------

    @staticmethod
    def get_network_info() -> dict:
        """
        Gather basic network interface information.

        Returns:
            dict with ``hostname``, ``fqdn``, and ``interfaces`` (list).
        """
        import socket

        info: dict = {
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "interfaces": [],
        }

        # Try to get local IPs via socket trick (no external connection made)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0)
            s.connect(("10.254.254.254", 1))
            info["local_ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            info["local_ip"] = "127.0.0.1"

        # Linux: parse /proc/net/if_inet6 or ip addr
        if platform.system() == "Linux":
            try:
                out = subprocess.check_output(
                    ["ip", "-brief", "addr"], text=True, timeout=5,
                )
                for line in out.strip().splitlines():
                    parts = line.split()
                    if len(parts) >= 3:
                        info["interfaces"].append({
                            "name": parts[0],
                            "state": parts[1],
                            "addresses": parts[2:],
                        })
            except Exception:
                pass

        # Windows: ipconfig (short summary only)
        elif platform.system() == "Windows":
            try:
                out = subprocess.check_output(
                    "ipconfig", text=True, timeout=5, shell=True,
                )
                current_adapter = None
                for line in out.splitlines():
                    line = line.rstrip()
                    if line and not line.startswith(" "):
                        current_adapter = line.rstrip(":")
                    elif "IPv4" in line or "IPv6" in line:
                        addr = line.split(":", 1)[1].strip() if ":" in line else line.strip()
                        info["interfaces"].append({
                            "name": current_adapter or "unknown",
                            "address": addr,
                        })
            except Exception:
                pass

        return info

    # ------------------------------------------------------------------
    # Python environment details
    # ------------------------------------------------------------------

    @staticmethod
    def get_python_details() -> dict:
        """
        Detailed Python runtime information (venv, sys paths, implementation).

        Returns:
            dict with keys ``executable``, ``prefix``, ``is_venv``, ``implementation``, etc.
        """
        import sys
        import sysconfig

        is_venv = (
            hasattr(sys, "real_prefix")  # old-style virtualenv
            or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)  # stdlib venv
        )

        return {
            "executable": sys.executable,
            "prefix": sys.prefix,
            "base_prefix": getattr(sys, "base_prefix", sys.prefix),
            "is_virtualenv": is_venv,
            "implementation": platform.python_implementation(),
            "compiler": platform.python_compiler(),
            "python_path_entries": len(sys.path),
            "site_packages": sysconfig.get_path("purelib"),
            "platform_tag": sysconfig.get_platform(),
        }

