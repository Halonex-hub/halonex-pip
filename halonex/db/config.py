from __future__ import annotations
import os
from dataclasses import dataclass

@dataclass(frozen=True)
class PgConfig:
    dsn: str
    minconn: int = 1
    maxconn: int = 5

def build_dsn(
    *,
    host: str,
    port: str = "5432",
    dbname: str,
    user: str,
    password: str,
    sslmode: str = "require",
) -> str:
    return (
        f"host={host} port={port} dbname={dbname} user={user} "
        f"password={password} sslmode={sslmode}"
    )

def from_env(env: dict) -> PgConfig:
    url = env.get("DATABASE_URL")
    minconn = int(env.get("PG_MIN_CONN", "1"))
    maxconn = int(env.get("PG_MAX_CONN", "5"))

    if url:
        if "sslmode=" not in url:
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}sslmode=require"
        return PgConfig(dsn=url, minconn=minconn, maxconn=maxconn)
    

    host = env.get("DB_HOST", "localhost")
    port = env.get("DB_PORT", "5432")
    name = env.get("DB_NAME", None)
    user = env.get("DB_USER", None)
    pwd  = env.get("DB_PASSWORD", None)
    ssl  = env.get("DB_SSLMODE", "require")


    return PgConfig(
        dsn=build_dsn(host=host, port=port, dbname=name, user=user, password=pwd, sslmode=ssl),
        minconn=minconn,
        maxconn=maxconn,
    )