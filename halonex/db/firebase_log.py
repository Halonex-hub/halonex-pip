from __future__ import annotations
import threading
from typing import Optional

try:
    import firebase_admin
    from firebase_admin import credentials, firestore, initialize_app
except Exception:
    firebase_admin = None
    credentials = None
    firestore = None
    initialize_app = None

_db = None

def _ensure_app() -> Optional["firestore.Client"]:
    global _db
    if firebase_admin is None:
        return None
    if not getattr(firebase_admin, "_apps", []):
        from os import environ as env
        cert = {
            "type": "service_account",
            "project_id": env.get("PROJECT_ID"),
            "private_key_id": env.get("PRIVATE_KEY_ID"),
            "private_key": env.get("PRIVATE_KEY","").replace("\\n","\\n"),
            "client_email": env.get("CLIENT_EMAIL"),
            "client_id": env.get("CLIENT_ID"),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": env.get("CERT_URL"),
            "universe_domain": "googleapis.com",
        }
        cred = credentials.Certificate(cert)
        initialize_app(cred)
    if _db is None:
        _db = firestore.client()
    return _db

def _spawn(fn, *args, **kwargs):
    t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
    t.start()

def log_async(collection: str, doc: dict) -> None:
    db = _ensure_app()
    if db is None:
        return
    def task():
        try:
            db.collection(collection).document().set(doc)
        except Exception:
            pass
    _spawn(task)

def log_error_async(message: str, collection: str = "amihacked_errors") -> None:
    db = _ensure_app()
    if db is None:
        return
    def task():
        try:
            db.collection(collection).document().set({"error": message, "timestamp": firestore.SERVER_TIMESTAMP})
        except Exception:
            pass
    _spawn(task)
