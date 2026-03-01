import json
import os
import time
import urllib.request
import urllib.error
from .config import Config

class Telemetry:
    """
    Handles reporting and visualization of security scan results.
    """

    @staticmethod
    def send_report(payload: dict, generate_html: bool = True):
        """
        Prints the JSON payload to console and sends it to the centralized server.
        Also optionally generates a local HTML dashboard.
        
        Args:
            payload (dict): The complete data collected by Sensor and Scanner.
            generate_html (bool): Whether to create the security_report.html file.
        """
        # 1. Console Output
        print("\n" + "="*60)
        print("[TELEMETRY]: Security Scan Completed.")
        print("="*60 + "\n")

        # 2. Network Transmission
        api_key = payload.get("api_key") or Config.get_api_key()
        if api_key:
             Telemetry._post_data(f"/guard/diagnostic/1", payload, api_key)
        else:
             print("[TELEMETRY]: No API Key found. Skipping server upload (Demo Mode).")

        # 3. Generate Client-Side HTML Dashboard
        if generate_html:
            Telemetry.generate_html_report(payload)

    @staticmethod
    def register_key():
        """
        Requests a new API Key from the server.
        Endpoint: POST /guard/create/key
        """
        print("[TELEMETRY]: Registering new device...")
        response = Telemetry._post_data("/guard/create/key", {})
        if response and "key" in response:
            return response["key"]
        return None

    @staticmethod
    def send_server_info(server_info: dict):
        """
        Sends server metadata.
        Endpoint: POST /guard/serverinfo
        """
        Telemetry._post_data("/guard/serverinfo", server_info)

    @staticmethod
    def _post_data(endpoint: str, data: dict, api_key=None):
        """
        Internal helper to send POST requests using urllib.
        """
        url = f"{Config.API_BASE_URL}{endpoint}"
        try:
            json_data = json.dumps(data).encode('utf-8')
            req = urllib.request.Request(url, data=json_data, method='POST')
            
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'PackageGuardian-Client/0.1.0')
            if api_key:
                req.add_header('X-API-Key', api_key)

            with urllib.request.urlopen(req, timeout=10) as response:
                if response.status in (200, 201):
                    response_body = response.read().decode('utf-8')
                    print(f"[TELEMETRY]: Data sent to {endpoint} successfully.")
                    try:
                        return json.loads(response_body)
                    except json.JSONDecodeError:
                        return {}
                else:
                    print(f"[TELEMETRY ERROR]: Server returned status {response.status}")

        except urllib.error.URLError as e:
            # For demo purposes, we degrade gracefully if the server is unreachable
            print(f"[TELEMETRY WARNING]: Failed to connect to {url}. Reason: {e.reason}")
        except Exception as e:
            print(f"[TELEMETRY ERROR]: Unexpected error sending data: {e}")
        
        return None

    @staticmethod
    def generate_html_report(data: dict, filename="security_report.html"):
        """
        Generates a standalone HTML file visualizing the security scan results.
        """
        
        # Calculate a simple risk score
        risk_score = 100
        issues_count = len(data.get('security_alerts', {}))
        ghosts_count = len(data.get('package_analysis', {}).get('ghost_packages', []))
        
        # Factor in secret findings by severity
        secrets_summary = data.get('secrets_summary', {})
        by_severity = secrets_summary.get('by_severity', {})
        risk_score -= by_severity.get('CRITICAL', 0) * 15
        risk_score -= by_severity.get('HIGH', 0) * 10
        risk_score -= by_severity.get('MEDIUM', 0) * 5
        risk_score -= by_severity.get('LOW', 0) * 2

        risk_score -= (issues_count * 10)
        risk_score -= (ghosts_count * 20)
        risk_score = max(0, risk_score)
        
        risk_level = "Low"
        risk_color = "#2ecc71" # Green
        if risk_score < 80:
            risk_level = "Medium"
            risk_color = "#f1c40f" # Yellow
        if risk_score < 50:
            risk_level = "High" 
            risk_color = "#e74c3c" # Red

        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Package Guardian Security Report</title>
    <style>
        :root {{
            --primary: #2c3e50;
            --secondary: #34495e;
            --accent: #3498db;
            --light: #ecf0f1;
            --dark: #2c3e50;
            --success: #2ecc71;
            --warning: #f1c40f;
            --danger: #e74c3c;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f4f7f6;
            margin: 0;
            padding: 20px;
            color: #333;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid var(--light);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1 {{ margin: 0; color: var(--primary); }}
        .badge {{
            padding: 5px 10px;
            border-radius: 4px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--light);
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }}
        .card h3 {{ margin: 0 0 10px 0; font-size: 0.9em; color: var(--secondary); text-transform: uppercase; }}
        .card .value {{ font-size: 1.5em; font-weight: bold; color: var(--primary); }}
        
        .section {{ margin-bottom: 40px; }}
        h2 {{ border-left: 5px solid var(--accent); padding-left: 10px; color: var(--secondary); }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{ background-color: var(--secondary); color: white; }}
        tr:hover {{ background-color: #f1f1f1; }}
        
        .alert-danger {{ color: var(--danger); font-weight: bold; }}
        .alert-warning {{ color: var(--warning); font-weight: bold; }}
        
        pre {{
            background: #2d2d2d;
            color: #ccc;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
        }}
        
        .score-circle {{
            width: 100px;
            height: 100px;
            border-radius: 50%;
            background: {risk_color};
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2em;
            font-weight: bold;
            margin: 0 auto 10px auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div>
                <h1>Package Guardian</h1>
                <p>Security Scan Report</p>
            </div>
            <div style="text-align: right;">
                <p>Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(data['timestamp']))}</p>
                <span class="badge" style="background-color: var(--accent)">v0.1.0</span>
            </div>
        </header>

        <!-- Executive Summary -->
        <div class="grid">
            <div class="card">
                <div class="score-circle">{risk_score}</div>
                <div>Security Score</div>
                <div style="color: {risk_color}; font-weight: bold;">{risk_level} Risk</div>
            </div>
            <div class="card">
                <h3>Project Framework</h3>
                <div class="value">{data.get('project_type', {}).get('primary', 'Unknown') if isinstance(data.get('project_type'), dict) else data.get('project_type', 'Unknown')}</div>
                <p>{data.get('environment', {}).get('python_version', 'N/A')}</p>
            </div>
            <div class="card">
                <h3>Environment</h3>
                <div class="value">{data.get('environment', {}).get('os', 'Unknown')}</div>
                <p>{'Docker Container' if data.get('environment', {}).get('is_docker') else 'CI Runner' if data.get('environment', {}).get('is_ci') else 'Host Machine'}</p>
            </div>
            <div class="card">
                <h3>Packages Scanned</h3>
                <div class="value">{data.get('package_analysis', {}).get('total_packages', 0)}</div>
                <p>{len(data.get('package_analysis', {}).get('ghost_packages', []))} Suspicious</p>
            </div>
        </div>

        <!-- Environment Details -->
        <div class="section">
            <h2>🖥️ Environment Details</h2>
            {Telemetry._render_environment_table(data.get('environment', {}))}
        </div>

        <!-- Framework / Tech Stack -->
        <div class="section">
            <h2>🔧 Tech Stack Detection</h2>
            {Telemetry._render_framework_table(data.get('project_type', {}))}
        </div>

        <!-- Security Alerts -->
        <div class="section">
            <h2>🚨 Security Misconfigurations</h2>
            {Telemetry._render_alerts_table(data.get('security_alerts', {}))}
        </div>

        <!-- Ghost Packages -->
        <div class="section">
            <h2>👻 Ghost Package Detection</h2>
            {Telemetry._render_ghosts_table(data.get('package_analysis', {}).get('ghost_packages', []))}
        </div>

        <!-- Vulnerabilities -->
        <div class="section">
            <h2>🛡️ Known Vulnerabilities (CVEs)</h2>
            {Telemetry._render_vulns_table(data.get('vulnerabilities', []))}
        </div>

        <!-- Outdated Packages -->
        <div class="section">
            <h2>📦 Outdated Packages</h2>
            {Telemetry._render_outdated_table(data.get('outdated_packages', []))}
        </div>

        <!-- Secrets & DB Issues -->
        <div class="section">
            <h2>🔑 Secrets & Database Security</h2>
            {Telemetry._render_secrets_table(data.get('secrets_detected', []), data.get('database_issues', []))}
        </div>

        <!-- File Structure Summary -->
        <div class="section">
            <h2>📂 Project Structure (Top Level)</h2>
            {Telemetry._render_file_tree(data.get('file_structure', {}))}
        </div>
        
        <footer>
            <p style="text-align: center; color: #777; font-size: 0.8em;">
                Generated by Package Guardian Client. This report is stored locally.
            </p>
        </footer>
    </div>
</body>
</html>
        """
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"[DASHBOARD]: Security Report generated successfully: {os.path.abspath(filename)}")
        except Exception as e:
            print(f"[DASHBOARD ERROR]: Failed to write HTML report: {e}")

    @staticmethod
    def _render_alerts_table(alerts):
        if not alerts:
            return "<p style='color: var(--success);'>✅ No misconfigurations detected.</p>"
        
        rows = ""
        for key, msg in alerts.items():
            level = "CRITICAL" if "CRITICAL" in msg else "WARNING"
            css_class = "alert-danger" if level == "CRITICAL" else "alert-warning"
            rows += f"<tr><td><code>{key}</code></td><td class='{css_class}'>{msg}</td></tr>"
            
        return f"<table><thead><tr><th>Variable</th><th>Issue</th></tr></thead><tbody>{rows}</tbody></table>"

    @staticmethod
    def _render_ghosts_table(ghosts):
        if not ghosts:
            return "<p style='color: var(--success);'>✅ No suspicious packages found.</p>"
            
        rows = ""
        for g in ghosts:
            confidence = g.get('confidence', 'medium')
            technique = g.get('technique', 'name-similarity')
            css = 'alert-danger' if confidence == 'high' else 'alert-warning'
            rows += f"""
            <tr>
                <td class="{css}">{g['name']}</td>
                <td>{g['similar_to']}</td>
                <td>{g['score']:.4f}</td>
                <td>{confidence}</td>
                <td>{technique}</td>
                <td>{g['warning']}</td>
            </tr>
            """
        return f"<table><thead><tr><th>Suspicious Package</th><th>Impersonating</th><th>Score</th><th>Confidence</th><th>Technique</th><th>Warning</th></tr></thead><tbody>{rows}</tbody></table>"

    @staticmethod
    def _render_vulns_table(vulns):
        if not vulns:
            return "<p style='color: var(--success);'>✅ No known vulnerabilities found.</p>"
            
        rows = ""
        for v in vulns:
            severity = v.get('severity')
            sev_str = str(severity) if severity else "Unknown"
            rows += f"<tr><td>{v['package']}</td><td>{v['id']}</td><td>{v['summary']}</td><td>{sev_str}</td></tr>"
        return f"<table><thead><tr><th>Package</th><th>ID</th><th>Summary</th><th>Severity</th></tr></thead><tbody>{rows}</tbody></table>"

    @staticmethod
    def _render_outdated_table(outdated):
        if not outdated:
            return "<p style='color: var(--success);'>✅ All packages up to date.</p>"
            
        rows = ""
        for o in outdated:
            update_type = o.get('update_type', '')
            # Style: yanked = red, major = orange, minor = yellow, patch = default
            css = ''
            if update_type == 'yanked':
                css = "class='alert-danger'"
            elif update_type == 'major':
                css = "class='alert-warning'"
            
            badges = []
            if o.get('is_yanked'):
                badges.append("<span style='background:#e74c3c;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em;'>YANKED</span>")
            if o.get('is_deprecated'):
                badges.append("<span style='background:#f39c12;color:white;padding:2px 6px;border-radius:3px;font-size:0.8em;'>DEPRECATED</span>")
            badges_html = ' '.join(badges)
            
            dep_msg = o.get('deprecated_msg', '')
            yanked_reason = o.get('yanked_reason', '')
            notes = dep_msg or yanked_reason or ''
            if len(notes) > 80:
                notes = notes[:80] + '…'
            
            rows += (f"<tr>"
                     f"<td {css}>{o['package']}</td>"
                     f"<td>{o['current']}</td>"
                     f"<td>{o['latest']}</td>"
                     f"<td>{update_type}</td>"
                     f"<td>{o['ecosystem']}</td>"
                     f"<td>{badges_html}</td>"
                     f"<td>{notes}</td>"
                     f"</tr>")
        return f"<table><thead><tr><th>Package</th><th>Current</th><th>Latest</th><th>Update</th><th>Ecosystem</th><th>Status</th><th>Notes</th></tr></thead><tbody>{rows}</tbody></table>"

    @staticmethod
    def _render_secrets_table(secrets, db_issues):
        if not secrets and not db_issues:
            return "<p style='color: var(--success);'>✅ No secrets or database misconfigurations found.</p>"
        
        rows = ""
        severity_css = {
            "CRITICAL": "alert-danger",
            "HIGH": "alert-danger",
            "MEDIUM": "alert-warning",
            "LOW": "alert-warning",
        }
        for s in secrets:
             sev = s.get('severity', 'HIGH')
             css = severity_css.get(sev, 'alert-warning')
             line = s.get('line', '?')
             entropy = s.get('entropy', '')
             rows += (f"<tr>"
                      f"<td class='{css}'>{sev}</td>"
                      f"<td>{s['type']}</td>"
                      f"<td>{s['file']}:{line}</td>"
                      f"<td>{s['redacted_snippet']}</td>"
                      f"<td>{entropy}</td>"
                      f"</tr>")
             
        for db in db_issues:
             warnings = "<br>".join(db['warnings'])
             rows += (f"<tr>"
                      f"<td class='alert-warning'>MEDIUM</td>"
                      f"<td>DB Misconfiguration</td>"
                      f"<td>{db['source']}</td>"
                      f"<td>{warnings}</td>"
                      f"<td>-</td>"
                      f"</tr>")
             
        return f"<table><thead><tr><th>Severity</th><th>Type</th><th>Location</th><th>Redacted Value</th><th>Entropy</th></tr></thead><tbody>{rows}</tbody></table>"

    @staticmethod
    def _render_environment_table(env: dict):
        """Render the full environment snapshot as an HTML table."""
        if not env:
            return "<p>No environment data collected.</p>"

        # Pick the most interesting fields to display
        display_fields = [
            ("OS",               f"{env.get('os', '?')} {env.get('os_release', '')}"),
            ("Platform",         env.get("platform_string", "N/A")),
            ("Architecture",     env.get("architecture", "N/A")),
            ("Hostname",         env.get("hostname", "N/A")),
            ("Python Version",   env.get("python_version", "N/A")),
            ("Python Impl.",     env.get("python_implementation", "N/A")),
            ("Virtual Env",      "Yes" if env.get("is_virtualenv") else "No"),
            ("Docker",           "Yes" if env.get("is_docker") else "No"),
            ("Kubernetes",       "Yes" if env.get("is_kubernetes") else "No"),
            ("WSL",              "Yes" if env.get("is_wsl") else "No"),
            ("VM Detected",      "Yes" if env.get("is_vm") else "No"),
            ("CI/CD",            env.get("ci_platform", "None detected")),
            ("CPU Model",        env.get("cpu_model", "N/A")),
            ("CPU Cores",        str(env.get("cpu_cores", "N/A"))),
            ("RAM Total",        f"{env.get('ram_total_gb', 0)} GB"),
            ("RAM Used",         f"{env.get('ram_used_percent', 0)}%"),
            ("Disk Total",       f"{env.get('disk_total_gb', 0)} GB"),
            ("Disk Free",        f"{env.get('disk_free_gb', 0)} GB"),
            ("Disk Used",        f"{env.get('disk_used_percent', 0)}%"),
            ("Local IP",         env.get("local_ip", "N/A")),
        ]

        rows = ""
        for label, value in display_fields:
            rows += f"<tr><td><strong>{label}</strong></td><td>{value}</td></tr>"

        # Package managers
        pm = env.get("package_managers", {})
        if pm:
            pm_list = ", ".join(f"<code>{k}</code>" for k in sorted(pm))
            rows += f"<tr><td><strong>Package Managers</strong></td><td>{pm_list}</td></tr>"

        # System tools (abbreviated)
        tools = env.get("system_tools", {})
        if tools:
            tool_list = ", ".join(f"<code>{k}</code>" for k in sorted(tools))
            rows += f"<tr><td><strong>Dev Tools</strong></td><td>{tool_list}</td></tr>"

        return f"<table><thead><tr><th>Property</th><th>Value</th></tr></thead><tbody>{rows}</tbody></table>"

    @staticmethod
    def _render_framework_table(framework):
        """Render the tech-stack detection result."""
        if not framework:
            return "<p>No framework detected.</p>"

        # Handle both old string format and new dict format
        if isinstance(framework, str):
            return f"<p><strong>Detected:</strong> {framework}</p>"

        primary = framework.get("primary", "Unknown")
        secondary = framework.get("secondary", [])
        signals = framework.get("signals", [])

        html = f"<p style='font-size:1.2em;'><strong>Primary Framework:</strong> {primary}</p>"

        if secondary:
            html += "<p><strong>Also detected:</strong> " + ", ".join(secondary) + "</p>"

        if signals:
            html += "<p><strong>Detection signals:</strong></p><ul>"
            for sig in signals:
                html += f"<li>{sig}</li>"
            html += "</ul>"

        return html

    @staticmethod
    def _render_file_tree(structure):
        if not structure:
            return "<p>No files scanned.</p>"
            
        # Limit to top-level for summary to avoid massive HTML
        rows = ""
        for name, info in structure.items():
            icon = "📁" if info.get('type') != 'file' else "📄"
            details = f"{info.get('lines', 0)} lines" if info.get('type') == 'file' else "Directory"
            rows += f"<tr><td>{icon} {name}</td><td>{details}</td></tr>"
            
        return f"<table><thead><tr><th>Name</th><th>Details</th></tr></thead><tbody>{rows}</tbody></table>"
