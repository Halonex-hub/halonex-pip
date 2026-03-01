import os
import re
import platform
import sys
import time
import importlib.metadata
from .analyzers import SystemAnalyzer


class Sensor:
    """
    Detects the full runtime environment, audits misconfigurations, and
    identifies the project framework / tech-stack.
    """

    # ==================================================================
    #  Phase 1 — Environment Detection
    # ==================================================================

    @staticmethod
    def detect_environment() -> dict:
        """
        Build a comprehensive snapshot of the host environment.

        Sections returned
        -----------------
        * **os** — operating system, release, architecture
        * **python** — version, implementation, venv status, site-packages
        * **virtualisation** — Docker / K8s / WSL / VM / CI detection
        * **resources** — CPU cores, RAM, disk space
        * **network** — hostname, local IP, interfaces
        * **package_managers** — every system & language PM on ``$PATH``
        * **system_tools** — dev tools with version strings

        Returns:
            dict
        """
        virt = SystemAnalyzer.detect_virtualisation()
        py_details = SystemAnalyzer.get_python_details()
        resources = SystemAnalyzer.get_resource_usage()
        network = SystemAnalyzer.get_network_info()

        return {
            # --- OS ---
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "architecture": platform.machine(),
            "platform_string": platform.platform(),
            "hostname": network.get("hostname", "unknown"),

            # --- Python ---
            "python_version": platform.python_version(),
            "python_implementation": py_details.get("implementation"),
            "python_compiler": py_details.get("compiler"),
            "python_executable": py_details.get("executable"),
            "is_virtualenv": py_details.get("is_virtualenv", False),
            "site_packages": py_details.get("site_packages"),

            # --- Virtualisation / Containers ---
            "is_docker": virt.get("is_docker", False),
            "is_kubernetes": virt.get("is_kubernetes", False),
            "is_wsl": virt.get("is_wsl", False),
            "is_vm": virt.get("is_vm", False),
            "is_ci": virt.get("is_ci", False),
            "ci_platform": virt.get("ci_platform"),
            "container_runtime": virt.get("container_runtime"),

            # --- Resources ---
            "cpu_cores": resources.get("cpu", {}).get("logical_cores", 0),
            "cpu_model": resources.get("cpu", {}).get("model", "Unknown"),
            "ram_total_gb": resources.get("memory", {}).get("total_gb", 0),
            "ram_used_percent": resources.get("memory", {}).get("used_percent", 0),
            "disk_total_gb": resources.get("disk", {}).get("total_gb", 0),
            "disk_free_gb": resources.get("disk", {}).get("free_gb", 0),
            "disk_used_percent": resources.get("disk", {}).get("used_percent", 0),

            # --- Network ---
            "local_ip": network.get("local_ip", "127.0.0.1"),
            "interfaces_count": len(network.get("interfaces", [])),

            # --- Tools ---
            "package_managers": SystemAnalyzer.detect_package_managers(),
            "system_tools": SystemAnalyzer.check_installed_tools(),
        }

    # ==================================================================
    #  Phase 1b — Misconfiguration Audit
    # ==================================================================

    # Env vars whose *presence* or *true-ish value* is a problem in prod
    _DEBUG_FLAGS = {
        "DEBUG", "FLASK_DEBUG", "DJANGO_DEBUG", "DJANGO_SETTINGS_MODULE",
        "NODE_ENV", "APP_ENV", "ENVIRONMENT", "RAILS_ENV",
    }

    # Values that indicate a development / debug mode
    _TRUTHY = {"true", "1", "yes", "on", "debug", "development", "dev"}

    # Env var name fragments that suggest a secret
    _SECRET_FRAGMENTS = {
        "SECRET", "TOKEN", "PASSWORD", "PASSWD", "AUTH",
        "CREDENTIAL", "PRIVATE_KEY", "ACCESS_KEY",
    }

    # Specific env vars that should never be set in production
    _DANGEROUS_ENV_VARS = {
        "PYTHONDONTWRITEBYTECODE",   # not dangerous per se, but useful to know
        "DISABLE_COLLECTSTATIC",
        "OAUTHLIB_INSECURE_TRANSPORT",
    }

    # Dangerous files in the project root
    _DANGEROUS_FILES = {
        ".env":          "An unencrypted .env file exists in the project root.  "
                         "Ensure it is listed in .gitignore.",
        ".env.local":    "A .env.local file exists — verify it is git-ignored.",
        ".env.production": "A .env.production file exists — it may contain real credentials.",
        "docker-compose.override.yml": "Override file can expose debug ports in production.",
        "id_rsa":        "An SSH private key file exists in the project root!",
        "id_ed25519":    "An SSH private key file exists in the project root!",
        ".npmrc":        "An .npmrc file may contain a registry auth token.",
        ".pypirc":       "A .pypirc file may contain PyPI credentials.",
    }

    @classmethod
    def check_misconfigurations(cls) -> dict:
        """
        Deep audit of environment variables, dangerous files, and common
        security anti-patterns.

        Categories
        ----------
        * **debug_flags** — debug / dev mode enabled in production
        * **exposed_secrets** — secret-looking env vars that are set
        * **insecure_env** — OAUTHLIB_INSECURE_TRANSPORT, etc.
        * **dangerous_files** — .env, private keys, .npmrc in project root
        * **missing_protections** — missing .gitignore, no requirements lock, etc.
        * **tls_verification** — curl/pip/node TLS verification disabled

        Returns:
            dict: ``{key: message}`` for every issue found.
        """
        issues: dict = {}

        # ---- 1. Debug flags ----
        for var in cls._DEBUG_FLAGS:
            val = os.environ.get(var, "").strip().lower()
            if val in cls._TRUTHY:
                # NODE_ENV=development is normal locally, but flag it
                if var in ("NODE_ENV", "RAILS_ENV", "APP_ENV", "ENVIRONMENT"):
                    issues[var] = (
                        f"WARNING: {var}={os.environ[var]!r} — "
                        "this indicates a non-production environment."
                    )
                else:
                    issues[var] = (
                        f"CRITICAL: {var} is enabled "
                        f"(value={os.environ[var]!r}).  "
                        "Disable debug mode before deploying to production."
                    )

        # ---- 2. Exposed secret-looking env vars ----
        for key in os.environ:
            upper = key.upper()
            if any(frag in upper for frag in cls._SECRET_FRAGMENTS):
                # Skip our own key, and common non-sensitive names
                if key == "PACKAGE_GUARDIAN_API_KEY":
                    continue
                issues[key] = (
                    f"WARNING: Environment variable '{key}' looks like a secret.  "
                    "Make sure it is not logged or leaked in CI output."
                )

        # ---- 3. Specific dangerous env vars ----
        for var in cls._DANGEROUS_ENV_VARS:
            if os.environ.get(var):
                issues[var] = (
                    f"WARNING: '{var}' is set — this may weaken security.  "
                    "Only use in tightly controlled dev environments."
                )

        # ---- 4. TLS verification disabled ----
        tls_off_vars = {
            "PYTHONHTTPSVERIFY": "Python HTTPS certificate verification disabled.",
            "NODE_TLS_REJECT_UNAUTHORIZED": "Node.js TLS certificate rejection disabled.",
            "CURL_CA_BUNDLE": "Custom CA bundle — verify it is intentional.",
            "REQUESTS_CA_BUNDLE": "Custom CA bundle for Python requests.",
            "GIT_SSL_NO_VERIFY": "Git SSL verification disabled!",
            "PIP_TRUSTED_HOST": "pip trusted-host set — packages fetched over HTTP.",
        }
        for var, msg in tls_off_vars.items():
            val = os.environ.get(var, "")
            if var == "NODE_TLS_REJECT_UNAUTHORIZED" and val == "0":
                issues[var] = f"CRITICAL: {msg}"
            elif var == "GIT_SSL_NO_VERIFY" and val.lower() in cls._TRUTHY:
                issues[var] = f"CRITICAL: {msg}"
            elif var == "PYTHONHTTPSVERIFY" and val == "0":
                issues[var] = f"CRITICAL: {msg}"
            elif val and var not in issues:
                # Just note presence for CA bundle vars
                if var in ("CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "PIP_TRUSTED_HOST"):
                    issues[var] = f"INFO: {msg}"

        # ---- 5. Dangerous files in project root ----
        for filename, msg in cls._DANGEROUS_FILES.items():
            if os.path.isfile(filename):
                issues[f"FILE:{filename}"] = f"WARNING: {msg}"

        # .env exists but .gitignore does not mention it
        if os.path.isfile(".env"):
            gitignore_ok = False
            if os.path.isfile(".gitignore"):
                try:
                    with open(".gitignore", "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            stripped = line.strip()
                            if stripped in (".env", ".env*", "*.env"):
                                gitignore_ok = True
                                break
                except Exception:
                    pass
            if not gitignore_ok:
                issues["GITIGNORE:.env"] = (
                    "CRITICAL: .env file exists but is NOT listed in .gitignore.  "
                    "Secrets may be committed to version control."
                )

        # ---- 6. Missing protections ----
        if not os.path.isfile(".gitignore"):
            issues["MISSING:.gitignore"] = (
                "WARNING: No .gitignore file found in the project root.  "
                "Sensitive files and build artefacts may be committed."
            )

        # Check for lock-file (requirements pinning)
        lock_files = [
            "requirements.txt", "Pipfile.lock", "poetry.lock", "pdm.lock",
            "uv.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        ]
        if not any(os.path.isfile(lf) for lf in lock_files):
            issues["MISSING:lockfile"] = (
                "WARNING: No dependency lock-file found.  "
                "Builds may be non-reproducible and vulnerable to supply-chain attacks."
            )

        # ---- 7. World-writable current directory (Linux/macOS) ----
        if platform.system() != "Windows":
            try:
                import stat
                mode = os.stat(".").st_mode
                if mode & stat.S_IWOTH:
                    issues["DIR:world_writable"] = (
                        "CRITICAL: Current working directory is world-writable.  "
                        "Other users on this machine can modify your code."
                    )
            except Exception:
                pass

        return issues

    # ==================================================================
    #  Phase 1c — Framework / Tech-Stack Detection
    # ==================================================================

    # Marker files → framework name  (checked in order, first match wins)
    _FILE_MARKERS: list = [
        # Python web
        ("manage.py",           "Django"),
        ("django_project",      "Django"),
        # Node / JS
        ("next.config.js",      "Next.js"),
        ("next.config.mjs",     "Next.js"),
        ("next.config.ts",      "Next.js"),
        ("nuxt.config.js",      "Nuxt.js"),
        ("nuxt.config.ts",      "Nuxt.js"),
        ("gatsby-config.js",    "Gatsby"),
        ("svelte.config.js",    "SvelteKit"),
        ("remix.config.js",     "Remix"),
        ("astro.config.mjs",    "Astro"),
        ("angular.json",        "Angular"),
        (".angular-cli.json",   "Angular"),
        ("vue.config.js",       "Vue CLI"),
        ("vite.config.ts",      "Vite"),
        ("vite.config.js",      "Vite"),
        # Python async / workers
        ("celeryconfig.py",     "Celery"),
        ("celery.py",           "Celery"),
        # Ruby
        ("Gemfile",             "Ruby (Bundler)"),
        ("config.ru",           "Rack (Ruby)"),
        ("Rakefile",            "Rake (Ruby)"),
        # PHP
        ("artisan",             "Laravel"),
        ("composer.json",       "PHP (Composer)"),
        # Go
        ("go.mod",              "Go Module"),
        # Rust
        ("Cargo.toml",         "Rust (Cargo)"),
        # Java / Kotlin
        ("pom.xml",            "Maven (Java)"),
        ("build.gradle",       "Gradle (Java/Kotlin)"),
        ("build.gradle.kts",   "Gradle (Kotlin DSL)"),
        # .NET
        ("*.csproj",           ".NET (C#)"),
        ("*.fsproj",           ".NET (F#)"),
        # Infrastructure
        ("Dockerfile",         "Docker"),
        ("docker-compose.yml", "Docker Compose"),
        ("docker-compose.yaml","Docker Compose"),
        ("terraform.tf",       "Terraform"),
        ("serverless.yml",     "Serverless Framework"),
        ("Vagrantfile",        "Vagrant"),
        ("Procfile",           "Heroku"),
    ]

    # package.json dependency → framework  (checked inside package.json)
    _NPM_DEP_MARKERS: dict = {
        "next":       "Next.js",
        "nuxt":       "Nuxt.js",
        "gatsby":     "Gatsby",
        "@angular/core": "Angular",
        "react":      "React",
        "vue":        "Vue.js",
        "svelte":     "Svelte",
        "express":    "Express.js",
        "fastify":    "Fastify",
        "hapi":       "Hapi",
        "koa":        "Koa",
        "electron":   "Electron",
        "react-native": "React Native",
        "@nestjs/core": "NestJS",
    }

    # Installed Python packages → framework  (order = priority)
    _PY_PKG_MARKERS: list = [
        ("django",     "Django"),
        ("fastapi",    "FastAPI"),
        ("flask",      "Flask"),
        ("starlette",  "Starlette"),
        ("tornado",    "Tornado"),
        ("sanic",      "Sanic"),
        ("bottle",     "Bottle"),
        ("falcon",     "Falcon"),
        ("aiohttp",    "aiohttp"),
        ("quart",      "Quart"),
        ("litestar",   "Litestar"),
        ("celery",     "Celery"),
        ("dramatiq",   "Dramatiq"),
        ("airflow",    "Apache Airflow"),
        ("prefect",    "Prefect"),
        ("dagster",    "Dagster"),
        ("streamlit",  "Streamlit"),
        ("gradio",     "Gradio"),
        ("panel",      "Panel"),
        ("dash",       "Plotly Dash"),
        ("scrapy",     "Scrapy"),
        ("pytest",     "pytest (Testing)"),
        ("sphinx",     "Sphinx (Docs)"),
        ("mkdocs",     "MkDocs (Docs)"),
        ("jupyter",    "Jupyter"),
        ("notebook",   "Jupyter Notebook"),
        ("tensorflow", "TensorFlow"),
        ("torch",      "PyTorch"),
        ("scikit-learn", "scikit-learn"),
    ]

    @classmethod
    def detect_framework(cls) -> dict:
        """
        Identify the project's primary framework and supporting tech stack.

        Strategy (in priority order):
        1. **Marker files** in the project root (strongest signal).
        2. **package.json** dependencies for JS/TS frameworks.
        3. **Installed Python packages** for Python frameworks.
        4. Falls back to ``"Generic Python"`` if nothing matches.

        Returns:
            dict: ``{primary, secondary, signals}``
        """
        detected: list = []      # ordered list of (framework, signal_source)
        signals: list = []       # human-readable explanation

        # ---- 1. Marker files ----
        for filename, framework in cls._FILE_MARKERS:
            if "*" in filename:
                # Glob-style (e.g. *.csproj)
                import glob
                if glob.glob(filename):
                    detected.append((framework, f"file:{filename}"))
                    signals.append(f"Found {filename}")
            elif os.path.exists(filename):
                detected.append((framework, f"file:{filename}"))
                signals.append(f"Found {filename}")

        # ---- 2. package.json deps ----
        if os.path.isfile("package.json"):
            try:
                import json
                with open("package.json", "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                all_deps = set()
                all_deps.update(pkg.get("dependencies", {}).keys())
                all_deps.update(pkg.get("devDependencies", {}).keys())
                for dep, framework in cls._NPM_DEP_MARKERS.items():
                    if dep in all_deps:
                        detected.append((framework, f"npm:{dep}"))
                        signals.append(f"npm dependency '{dep}'")
            except Exception:
                pass

        # ---- 3. Python packages ----
        try:
            installed = {
                pkg.metadata["Name"].lower()
                for pkg in importlib.metadata.distributions()
            }
        except Exception:
            installed = set()

        for pkg_name, framework in cls._PY_PKG_MARKERS:
            if pkg_name in installed:
                detected.append((framework, f"python:{pkg_name}"))
                signals.append(f"Python package '{pkg_name}'")

        # ---- 4. Extra heuristics ----
        # Flask: strengthen if app.py / FLASK_APP exists
        if ("Flask", "python:flask") in detected:
            if os.path.exists("app.py") or os.environ.get("FLASK_APP"):
                signals.append("Flask entry-point (app.py or FLASK_APP) found")

        # ---- Compose result ----
        primary = detected[0][0] if detected else "Generic Python"
        secondary = list(dict.fromkeys(fw for fw, _ in detected[1:5]))  # up to 4 unique

        return {
            "primary": primary,
            "secondary": secondary,
            "signals": signals[:10],  # cap at 10 to keep payload small
        }
