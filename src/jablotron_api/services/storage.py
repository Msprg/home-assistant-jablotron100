"""SQLite-backed service state."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

from jablotron_api.domain.models import DEFAULT_ADMIN_SCOPES, AuthenticatedToken, TokenInfoModel


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def token_hash(value: str) -> str:
    return hashlib.blake2b(value.encode("utf-8"), digest_size=32).hexdigest()


class TokenStore:
    """Stores API tokens, audit entries, and snapshot metadata."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tokens (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    token_hash TEXT NOT NULL UNIQUE,
                    scopes_json TEXT NOT NULL,
                    certificate_fingerprint TEXT,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    revoked_at TEXT
                );

                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    token_id TEXT,
                    action TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    details_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS snapshot_cache (
                    cache_key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def create_token(
        self,
        *,
        label: str,
        scopes: list[str] | None = None,
        certificate_fingerprint: str | None = None,
    ) -> tuple[str, TokenInfoModel]:
        token_value = secrets.token_urlsafe(32)
        token_id = secrets.token_hex(8)
        created_at = utc_now_iso()
        effective_scopes = scopes or list(DEFAULT_ADMIN_SCOPES)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tokens (
                    id, label, token_hash, scopes_json, certificate_fingerprint, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    token_id,
                    label,
                    token_hash(token_value),
                    json.dumps(effective_scopes),
                    certificate_fingerprint,
                    created_at,
                ),
            )
            conn.commit()
        return token_value, TokenInfoModel(
            id=token_id,
            label=label,
            scopes=effective_scopes,
            certificate_fingerprint=certificate_fingerprint,
            created_at=datetime.fromisoformat(created_at),
        )

    def list_tokens(self) -> list[TokenInfoModel]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM tokens ORDER BY created_at ASC").fetchall()
        return [self._row_to_token_info(row) for row in rows]

    def revoke_token(self, token_id: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE tokens SET revoked_at = ? WHERE id = ?",
                (utc_now_iso(), token_id),
            )
            conn.commit()

    def authenticate(
        self,
        token_value: str,
        *,
        certificate_fingerprint: str | None = None,
    ) -> AuthenticatedToken | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM tokens WHERE token_hash = ?",
                (token_hash(token_value),),
            ).fetchone()
            if row is None:
                return None
            if row["revoked_at"] is not None:
                return None
            expected_fingerprint = row["certificate_fingerprint"]
            if expected_fingerprint and expected_fingerprint != certificate_fingerprint:
                return None
            conn.execute(
                "UPDATE tokens SET last_used_at = ? WHERE id = ?",
                (utc_now_iso(), row["id"]),
            )
            conn.commit()
        return AuthenticatedToken(
            id=row["id"],
            label=row["label"],
            scopes=json.loads(row["scopes_json"]),
            certificate_fingerprint=row["certificate_fingerprint"],
        )

    def write_audit(
        self,
        *,
        token_id: str | None,
        action: str,
        resource: str,
        details: dict[str, object],
    ) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO audit_log (created_at, token_id, action, resource, details_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (utc_now_iso(), token_id, action, resource, json.dumps(details, sort_keys=True)),
            )
            conn.commit()

    def store_snapshot_metadata(self, key: str, payload: dict[str, object]) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO snapshot_cache(cache_key, value_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at
                """,
                (key, json.dumps(payload, sort_keys=True), utc_now_iso()),
            )
            conn.commit()

    def load_snapshot_metadata(self, key: str) -> dict[str, object] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value_json FROM snapshot_cache WHERE cache_key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        return json.loads(row["value_json"])

    @staticmethod
    def _row_to_token_info(row: sqlite3.Row) -> TokenInfoModel:
        created_at = datetime.fromisoformat(row["created_at"])
        revoked_at = datetime.fromisoformat(row["revoked_at"]) if row["revoked_at"] else None
        last_used_at = datetime.fromisoformat(row["last_used_at"]) if row["last_used_at"] else None
        return TokenInfoModel(
            id=row["id"],
            label=row["label"],
            scopes=json.loads(row["scopes_json"]),
            certificate_fingerprint=row["certificate_fingerprint"],
            created_at=created_at,
            revoked_at=revoked_at,
            last_used_at=last_used_at,
        )

