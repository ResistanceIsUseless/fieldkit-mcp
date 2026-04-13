#!/usr/bin/env python3
"""Simple sqlite cache helpers for web surface tools."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


DEFAULT_CACHE_DB = os.environ.get("CACHE_DB", "cache/cache.db")


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS web_cache (
    url TEXT NOT NULL,
    method TEXT NOT NULL,
    status INTEGER,
    headers_json TEXT,
    body BLOB,
    fetched_at TEXT NOT NULL,
    content_hash TEXT,
    PRIMARY KEY (url, method)
);
CREATE INDEX IF NOT EXISTS idx_web_cache_fetched_at ON web_cache(fetched_at DESC);
"""


@dataclass
class CachedResponse:
    url: str
    method: str
    status: Optional[int]
    headers: Dict[str, Any]
    body: bytes
    fetched_at: str
    content_hash: Optional[str]


def _connect(db_path: str = DEFAULT_CACHE_DB) -> sqlite3.Connection:
    parent = os.path.dirname(db_path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_cache(db_path: str = DEFAULT_CACHE_DB) -> None:
    conn = _connect(db_path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.commit()
    finally:
        conn.close()


def upsert_response(
    *,
    url: str,
    method: str,
    status: Optional[int],
    headers: Optional[Dict[str, Any]],
    body: bytes,
    db_path: str = DEFAULT_CACHE_DB,
) -> None:
    init_cache(db_path)
    fetched_at = datetime.now(timezone.utc).isoformat()
    content_hash = hashlib.sha256(body).hexdigest() if body else None
    headers_json = json.dumps(headers or {}, separators=(",", ":"))

    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO web_cache (url, method, status, headers_json, body, fetched_at, content_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(url, method)
            DO UPDATE SET
                status=excluded.status,
                headers_json=excluded.headers_json,
                body=excluded.body,
                fetched_at=excluded.fetched_at,
                content_hash=excluded.content_hash
            """,
            (url, method.upper(), status, headers_json, body, fetched_at, content_hash),
        )
        conn.commit()
    finally:
        conn.close()


def get_cached(url: str, method: str = "GET", db_path: str = DEFAULT_CACHE_DB) -> Optional[CachedResponse]:
    init_cache(db_path)
    conn = _connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT url, method, status, headers_json, body, fetched_at, content_hash
            FROM web_cache
            WHERE url = ? AND method = ?
            """,
            (url, method.upper()),
        ).fetchone()
        if not row:
            return None
        return CachedResponse(
            url=row["url"],
            method=row["method"],
            status=row["status"],
            headers=json.loads(row["headers_json"] or "{}"),
            body=row["body"] or b"",
            fetched_at=row["fetched_at"],
            content_hash=row["content_hash"],
        )
    finally:
        conn.close()


def list_cached(limit: int = 50, db_path: str = DEFAULT_CACHE_DB) -> List[Dict[str, Any]]:
    init_cache(db_path)
    conn = _connect(db_path)
    try:
        rows = conn.execute(
            """
            SELECT url, method, status, fetched_at, content_hash
            FROM web_cache
            ORDER BY fetched_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
