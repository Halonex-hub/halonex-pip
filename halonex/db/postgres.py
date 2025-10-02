from __future__ import annotations
from typing import Any, Dict, List, Optional, Tuple, Iterable
from contextlib import contextmanager

from psycopg2 import sql as _sql
from psycopg2.pool import SimpleConnectionPool
from psycopg2.extras import RealDictCursor
from psycopg2.extensions import STATUS_IN_TRANSACTION

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
        """
        Yields a raw connection from the pool.
        Ensures any open transaction is rolled back before the connection is returned to the pool.
        """
        conn = self._pool.getconn()
        try:
            # psycopg2 default is autocommit=False; we keep that to allow transactions.
            yield conn
        finally:
            try:
                # If the connection is still in a transaction, roll it back to avoid leaking state.
                if not getattr(conn, "autocommit", False) and conn.status == STATUS_IN_TRANSACTION:
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                self._pool.putconn(conn)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    @contextmanager
    def cursor(self):
        """
        Convenience cursor for read-only operations (no commit).
        Any uncommitted state will be rolled back by connection() when returning to the pool.
        """
        with self.connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                yield cur

    # ---------- READ HELPERS (no commit) ----------

    def fetch_all(self, query: SQL, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
        with self.cursor() as cur:
            cur.execute(query, params)
            return list(cur.fetchall())

    def fetch_one(self, query: SQL, params: Tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
        with self.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()

    # ---------- WRITE HELPERS (commit/rollback) ----------

    def execute(self, query: SQL, params: Tuple[Any, ...] = ()) -> int:
        """
        Execute a write statement and commit on success, rollback on failure.
        Returns affected row count.
        """
        with self.connection() as conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(query, params)
                    affected = cur.rowcount
                conn.commit()
                return affected
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise

    def executemany(self, query: SQL, seq_of_params: Iterable[Tuple[Any, ...]]):
        """
        Execute many write statements and commit on success, rollback on failure.
        Returns affected row count (as reported by psycopg2).
        """
        with self.connection() as conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.executemany(query, seq_of_params)
                    affected = cur.rowcount
                conn.commit()
                return affected
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise

    def fetch_one_write(self, query: SQL, params: Tuple[Any, ...] = ()) -> Optional[Dict[str, Any]]:
        """
        For functions/queries that RETURN a row AND mutate state.
        Commits on success, rollbacks on failure.
        """
        with self.connection() as conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(query, params)
                    row = cur.fetchone()
                conn.commit()
                return row
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise

    def fetch_all_write(self, query: SQL, params: Tuple[Any, ...] = ()) -> List[Dict[str, Any]]:
        """
        For queries that RETURN rows AND mutate state.
        Commits on success, rollbacks on failure.
        """
        with self.connection() as conn:
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(query, params)
                    rows = list(cur.fetchall())
                conn.commit()
                return rows
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise

    # ---------- EXPLICIT TRANSACTION CONTROL ----------

    @contextmanager
    def transaction(self):
        """
        Usage:
            with db.transaction() as tx:
                tx.execute(...); tx.fetch_one(...); ...
            # auto-commit on success; rollback on exception
        """
        with self.connection() as conn:
            try:
                yield Transaction(conn)
                conn.commit()
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                raise


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
