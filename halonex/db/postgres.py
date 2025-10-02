from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple
from contextlib import contextmanager

from psycopg2 import sql as _sql
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import RealDictCursor

from .config import from_env, build_dsn
from .json_safe import make_json_safe

import os

SQL = _sql.SQL
sql = _sql

class Database:

    def __init__(
        self,
        dsn: Optional[str] = None,
        *,
        host: Optional[str] = None,
        port: str = "5432",
        dbname: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        sslmode: str = "require",
        minconn: Optional[int] = None,
        maxconn: Optional[int] = None,
    ):
        PG_CONFIG = from_env(os.environ)
        if dsn:
            resolved_dsn = dsn if "sslmode=" in dsn else (dsn + ("&" if "?" in dsn else "?") + "sslmode=require")
            self._dsn = resolved_dsn
        elif host and dbname and user and password:
            self._dsn = build_dsn(host=host, port=port, dbname=dbname, user=user, password=password, sslmode=sslmode)
        else:
            self._dsn = PG_CONFIG.dsn

        self._min = minconn if minconn is not None else PG_CONFIG.minconn
        self._max = maxconn if maxconn is not None else PG_CONFIG.maxconn

        self._pool: SimpleConnectionPool = SimpleConnectionPool(self._min, self._max, dsn=self._dsn)

    def close(self) -> None:
        try:
            self._pool.closeall()
        except Exception:
            pass

    @contextmanager
    def connection(self):
        conn = self._pool.getconn()
        try:
            yield conn
        finally:
            try:
                self._pool.putconn(conn)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    @contextmanager
    def cursor(self):
        with self.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                yield cur

    def fetch_all(self, query: SQL, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
        with self.cursor() as cur:
            cur.execute(query, params)
            return list(cur.fetchall())

    def fetch_one(self, query: SQL, params: Tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
        with self.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()

    def execute(self, query: SQL, params: Tuple[Any, ...] = ()) -> int:
        with self.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(query, params)
                affected = cur.rowcount
                conn.commit()
                return affected

    def executemany(self, query: SQL, seq_of_params):
        with self.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.executemany(query, seq_of_params)
                affected = cur.rowcount
                conn.commit()
                return affected

class Transaction:
    def __init__(self, conn):
        self._conn = conn

    def execute(self, query: SQL, params: Tuple[Any, ...] = ()) -> int:
        with self._conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            return cur.rowcount

    def fetch_all(self, query: SQL, params: Tuple[Any, ...] = ()):
        with self._conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            return list(cur.fetchall())

    def fetch_one(self, query: SQL, params: Tuple[Any, ...] = ()):
        with self._conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, params)
            return cur.fetchone()

def to_json_safe(payload: Dict[str, Any]) -> Dict[str, Any]:
    return make_json_safe(payload)
