import json
import os
import ssl
import time
import urllib.request
import urllib.error
from .config import Config, Plan


# Logging control — all internal output goes through _log() which is
# suppressed by default.  Only the final scan-complete line is printed.
def _log(msg: str):
    """Internal logger; silenced so the package produces no console noise."""
    pass

class Telemetry:
    """
    Handles reporting and visualization of security scan results.
    """

    # ------------------------------------------------------------------
    #  Key Validation  (Step 3 in the flow)
    # ------------------------------------------------------------------

    @staticmethod
    def validate_key(api_key: str) -> Plan:
        """
        Call the server to validate *api_key* and discover which plan /
        features are enabled.

        Endpoint: POST /guard/validate/key
        Request body:  {"api_key": "<key>"}
        Expected 200 response body (example):
            {
                "valid": true,
                "tier": "pro",
                "features": ["env_detection", "ghost_package_detection", ...]
            }

        Returns:
            A ``Plan`` instance.  On any failure the plan defaults to
            ``free`` so basic scanning still works.
        """
        result = Telemetry._post_data(
            "/guard/validate/key",
            {"api_key": api_key},
            api_key=api_key,
        )

        if not result or not isinstance(result, dict):
            _log("[AUTH]: Server unreachable — defaulting to free tier.")
            Config.key_validated = False
            return Plan()

        if result.get("_status") == 401 or not result.get("valid"):
            _log("[AUTH]: API key is invalid or expired. "
                  "Create a new key on the dashboard.")
            Config.key_validated = False
            return Plan()

        tier = result.get("tier", "free")
        features = result.get("features")  # may be None → use tier defaults
        plan = Plan(tier, features=set(features) if features else None)
        Config.key_validated = True
        _log(f"[AUTH]: Key validated — tier={plan.tier}, "
              f"features={len(plan.features)}")
        return plan

    # ------------------------------------------------------------------
    #  Report transmission
    # ------------------------------------------------------------------

    @staticmethod
    def send_report(payload: dict, generate_html: bool = True):
        """
        Sends the scan payload to the centralized server.

        Telemetry is sent whenever the API key has been validated by
        the server — it is not gated by plan tier.

        Args:
            payload (dict): The complete data collected by Sensor and Scanner.
            generate_html (bool): Ignored (HTML report generation removed).
        """
        # Network Transmission (requires a validated key)
        api_key = payload.get("api_key") or Config.get_api_key()

        if not api_key:
            _log("[TELEMETRY]: No API Key provided. Skipping server upload.")
        elif not Config.key_validated:
            _log("[TELEMETRY]: API key was not validated. Skipping server upload.")
        else:
            Telemetry._post_data("/guard/diagnostic/1", payload, api_key)

    @staticmethod
    def send_server_info(server_info: dict):
        """
        Sends server metadata.
        Endpoint: POST /guard/serverinfo
        """
        api_key = Config.get_api_key()
        Telemetry._post_data("/guard/serverinfo", server_info, api_key=api_key)

    @staticmethod
    def _post_data(endpoint: str, data: dict, api_key=None):
        """
        Internal helper to send POST requests using urllib.
        """
        url = f"{Config.API_BASE_URL}{endpoint}"

        # Only create an SSL context when using HTTPS
        ctx = None
        if url.lower().startswith("https://"):
            ctx = ssl.create_default_context()
            if os.environ.get("PG_ALLOW_SELF_SIGNED", "false").lower() == "true":
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

        try:
            json_data = json.dumps(data).encode('utf-8')
            req = urllib.request.Request(url, data=json_data, method='POST')
            
            req.add_header('Content-Type', 'application/json')
            req.add_header('User-Agent', 'PackageGuardian-Client/0.1.0')
            if api_key:
                req.add_header('X-API-Key', api_key)
            if Config.INTERNAL_SECRET:
                req.add_header('X-Internal-Token', Config.INTERNAL_SECRET)

            kwargs = {"timeout": 10}
            if ctx is not None:
                kwargs["context"] = ctx

            with urllib.request.urlopen(req, **kwargs) as response:
                if response.status in (200, 201):
                    response_body = response.read().decode('utf-8')
                    _log(f"[TELEMETRY]: Data sent to {endpoint} successfully.")
                    try:
                        return json.loads(response_body)
                    except json.JSONDecodeError:
                        return {}
                else:
                    _log(f"[TELEMETRY ERROR]: Server returned status {response.status}")

        except urllib.error.HTTPError as e:
            if e.code == 401:
                _log(f"[TELEMETRY WARNING]: Unauthorized (401) for {endpoint}. API key may be invalid.")
                return {"_status": 401}
            _log(f"[TELEMETRY WARNING]: Server returned HTTP {e.code} for {endpoint}.")
        except urllib.error.URLError as e:
            _log(f"[TELEMETRY WARNING]: Failed to connect to {url}. Reason: {e.reason}")
        except Exception as e:
            _log(f"[TELEMETRY ERROR]: Unexpected error sending data: {e}")
        
        return None
