import json
import urllib.request
import urllib.error

class VulnScanner:
    """
    Scans installed packages for known vulnerabilities using the OSV API.
    """
    
    OSV_API_URL = "https://api.osv.dev/v1/query"

    @staticmethod
    def check_vulnerabilities(packages: list, ecosystem: str):
        """
        Checks a list of packages against the OSV database.
        
        Args:
            packages (list): List of package names (and optionally versions).
            ecosystem (str): 'PyPI' or 'npm'.
            
        Returns:
            list: List of vulnerabilities found.
        """
        vulnerabilities = []
        
        # Batching requests to avoid hammering the API too hard (or hitting limits)
        # OSV supports batch queries.
        
        queries = []
        for pkg in packages:
            # If pkg is a dict with name/version
            if isinstance(pkg, dict):
                name = pkg.get('name')
                version = pkg.get('version')
            else:
                name = pkg
                version = None # Check all versions if specific one unknown (may be too noisy)
            
            query = {"package": {"name": name, "ecosystem": ecosystem}}
            if version:
                query["version"] = version
                
            queries.append(query)
            
        if not queries:
            return []

        # OSV batch endpoint
        batch_url = "https://api.osv.dev/v1/querybatch"
        payload = {"queries": queries}
        
        try:
            json_data = json.dumps(payload).encode('utf-8')
            req = urllib.request.Request(batch_url, data=json_data, method='POST')
            req.add_header('Content-Type', 'application/json')
            
            with urllib.request.urlopen(req, timeout=15) as response:
                if response.status == 200:
                    results = json.loads(response.read().decode('utf-8')).get("results", [])
                    
                    for i, result in enumerate(results):
                        vulns = result.get("vulns", [])
                        if vulns:
                            pkg_name = queries[i]["package"]["name"]
                            for vuln in vulns:
                                vulnerabilities.append({
                                    "package": pkg_name,
                                    "id": vuln.get("id"),
                                    "summary": vuln.get("summary", "No summary provided"),
                                    "details": vuln.get("details", ""),
                                    "severity": vuln.get("severity", [])
                                })
                                
        except Exception as e:
            print(f"[VULN SCAN ERROR]: Failed to query OSV API: {e}")
            
        return vulnerabilities
