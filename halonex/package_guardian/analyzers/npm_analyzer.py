import json
import os
from typing import Dict, Any

class NPMAnalyzer:
    """
    Analyzes Node.js projects by parsing package.json and package-lock.json.
    """

    @staticmethod
    def analyze_package_json(project_root: str = ".") -> Dict[str, Any]:
        """
        Parses package.json to extract dependencies and scripts.
        
        Args:
            project_root (str): The root directory of the project.
            
        Returns:
            dict: Analysis results including dependencies and scripts.
        """
        package_json_path = os.path.join(project_root, "package.json")
        result = {
            "exists": False,
            "name": None,
            "version": None,
            "dependencies": {},
            "devDependencies": {},
            "scripts": {}
        }

        if not os.path.exists(package_json_path):
            return result

        try:
            with open(package_json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
            result["exists"] = True
            result["name"] = data.get("name")
            result["version"] = data.get("version")
            result["dependencies"] = data.get("dependencies", {})
            result["devDependencies"] = data.get("devDependencies", {})
            result["scripts"] = data.get("scripts", {})
            
        except json.JSONDecodeError:
            result["error"] = "Invalid JSON format in package.json"
        except Exception as e:
            result["error"] = str(e)

        return result

    @staticmethod
    def analyze_lock_file(project_root: str = ".") -> Dict[str, Any]:
        """
        Parses package-lock.json for exact versions and integrity checks.
        """
        lock_path = os.path.join(project_root, "package-lock.json")
        if not os.path.exists(lock_path):
            return {"exists": False}

        try:
            with open(lock_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return {
                "exists": True,
                "lockfileVersion": data.get("lockfileVersion"),
                "packages_count": len(data.get("packages", {})) if "packages" in data else len(data.get("dependencies", {}))
            }
        except Exception:
            return {"exists": True, "error": "Failed to parse package-lock.json"}
