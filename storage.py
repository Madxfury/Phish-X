"""Complete visitor-scoped scans: Postgres/MongoDB and actual SQLite fallback."""
from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
import sqlite3
import time
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager

from pymongo import MongoClient
from pymongo.errors import PyMongoError
import psycopg
from postgres_store import PostgresStore

log = logging.getLogger(__name__)
SCHEMA_VERSION = 5


def config_fingerprint() -> str:
    names = ("AI_PROVIDER", "GROQ_MODEL", "GROQ_API_KEY", "OPENAI_MODEL", "OPENAI_API_KEY", "OLLAMA_MODEL", "OLLAMA_BASE_URL", "VIRUSTOTAL_API_KEY", "SAFE_BROWSING_API_KEY")
    material = "phish-x-policy-2026-10-06-v3|" + "|".join(os.getenv(name, "") for name in names)
    return hashlib.sha256(material.encode()).hexdigest()


class ScanStore:
    def __init__(self):
        self.client = None
        self.collection = None
        self.mongo_retry_at = 0
        self.database_name = os.getenv("MONGODB_DATABASE", "phishing_detection")
        dsn = os.getenv('DATABASE_URL') or os.getenv('POSTGRES_URL')
        self.postgres = PostgresStore(dsn) if dsn else None
        uri = os.getenv("MONGODB_URI") or os.getenv("MONGO_URI")
        if uri and not self.postgres:
            try:
                self.client = MongoClient(uri, serverSelectionTimeoutMS=1200, connectTimeoutMS=1200, socketTimeoutMS=2000)
                self.client.admin.command("ping")
                self._connect_collection()
            except (PyMongoError, ValueError):
                log.warning("MongoDB unavailable; actual scan results use SQLite fallback.")
                self.collection = None
                self.mongo_retry_at = time.monotonic() + 30
        default_dir = Path("/tmp/phish-x-ai") if os.getenv("VERCEL") else Path(__file__).resolve().parent / "data"
        self.path = Path(os.getenv("LOCAL_DB_PATH") or str(default_dir / "scans.sqlite3"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("CREATE TABLE IF NOT EXISTS scans (scan_id TEXT PRIMARY KEY, url TEXT NOT NULL, created_epoch REAL NOT NULL, fingerprint TEXT NOT NULL, result TEXT NOT NULL)")
            db.execute("CREATE INDEX IF NOT EXISTS scan_url_age ON scans(url, created_epoch DESC)")
            if "owner" not in {column[1] for column in db.execute("PRAGMA table_info(scans)")}:
                db.execute("ALTER TABLE scans ADD COLUMN owner TEXT NOT NULL DEFAULT ''")
            db.execute("CREATE INDEX IF NOT EXISTS scan_owner_age ON scans(owner, created_epoch DESC)")

    def _connect_collection(self):
        database = self.client[self.database_name]
        collection = database["verified_scans"]
        collection.create_index("scan_id", unique=True)
        collection.create_index([("owner", 1), ("url", 1), ("created_epoch", -1)])
        collection.create_index("expires_at", expireAfterSeconds=0)
        database["request_limits"].create_index("expires_at", expireAfterSeconds=0)
        self.collection = collection

    def rate_allowed(self, identity: str, limit: int) -> bool:
        """Atomic minute bucket shared across Vercel instances; no raw IPs stored."""
        if self.postgres:
            if not self.postgres.available():
                return not bool(os.getenv('VERCEL'))
            try:
                return self.postgres.rate_allowed(identity, limit)
            except psycopg.Error:
                self.postgres.failed()
                return not bool(os.getenv('VERCEL'))
        if self._mongo() is None:
            return not bool(os.getenv('VERCEL'))  # Fail closed without a production shared counter.
        now = time.time()
        bucket = f"{identity}:{int(now // 60)}"
        try:
            from pymongo import ReturnDocument
            row = self.client[self.database_name]["request_limits"].find_one_and_update(
                {"_id": bucket}, {"$inc": {"count": 1}, "$setOnInsert": {"expires_at": datetime.now(timezone.utc) + timedelta(minutes=2)}},
                upsert=True, return_document=ReturnDocument.AFTER)
            return row["count"] <= limit
        except PyMongoError:
            self._failed_mongo()
            return not bool(os.getenv("VERCEL"))

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=3)
        db.execute("PRAGMA busy_timeout=3000")
        try:
            with db:
                yield db
        finally:
            db.close()

    def _mongo(self):
        # Reuse the process MongoClient; avoid repeated failing requests during an outage.
        if self.collection is None and self.client is not None and time.monotonic() >= self.mongo_retry_at:
            try:
                self.client.admin.command("ping")
                self._connect_collection()
            except PyMongoError:
                self.mongo_retry_at = time.monotonic() + 30
        return self.collection

    def _failed_mongo(self):
        self.collection = None
        self.mongo_retry_at = time.monotonic() + 30
        log.warning("MongoDB operation failed; using local verified-result fallback.")

    @property
    def mode(self):
        if self.postgres and self.postgres.ready:
            return 'postgres'
        return "mongodb" if self.collection is not None else "ephemeral_sqlite" if os.getenv("VERCEL") else "local_sqlite"

    @property
    def durable_available(self):
        return self.postgres.available() if self.postgres else self._mongo() is not None

    def check_durable_connection(self):
        """Readiness probes verify a real connection, rather than cached startup status."""
        if self.postgres:
            if not self.postgres.available():
                return False
            try:
                with self.postgres.connection() as db:
                    db.execute('SELECT 1')
                return True
            except psycopg.Error:
                self.postgres.failed()
                return False
        if self._mongo() is None:
            return False
        try:
            self.client.admin.command('ping')
            return True
        except PyMongoError:
            self._failed_mongo()
            return False

    def _postgres_records(self, owner=None, **kwargs):
        if self.postgres and self.postgres.available():
            try:
                return self.postgres.records(owner, SCHEMA_VERSION, **kwargs)
            except psycopg.Error:
                self.postgres.failed()
        return []

    @staticmethod
    def _scope(owner):
        query = {"schema_version": SCHEMA_VERSION, "created_epoch": {"$gte": time.time() - 30 * 86400}}
        if owner is not None:
            query["owner"] = owner
        return query

    @staticmethod
    def _local_scope(owner):
        return (" AND owner = ?", [owner]) if owner is not None else ("", [])

    def save(self, result: dict, owner=""):
        now = time.time()
        if self.postgres:
            self.postgres.available()
        collection = self._mongo()
        mode = self.mode
        result["storage"] = {"mode": mode, "durable": mode in {"mongodb", "postgres"} or not bool(os.getenv("VERCEL"))}
        doc = {"scan_id": result["scan_id"], "url": result["url"], "owner": owner or "", "schema_version": SCHEMA_VERSION, "created_epoch": now,
               "expires_at": datetime.now(timezone.utc) + timedelta(days=30), "fingerprint": config_fingerprint(), "result": result,
               "summary": {key: result.get(key) for key in ("scan_id", "url", "timestamp", "title", "risk_score", "assessment", "state")}}
        doc["summary"]["content_status"] = result.get("features", {}).get("content", {}).get("status")
        if self.postgres and self.postgres.available():
            try:
                self.postgres.save(doc)
            except psycopg.Error:
                self.postgres.failed()
        elif collection is not None:
            try:
                collection.replace_one({"scan_id": result["scan_id"]}, doc, upsert=True)
            except PyMongoError:
                self._failed_mongo()
        result["storage"] = {"mode": self.mode, "durable": self.mode in {"mongodb", "postgres"} or not bool(os.getenv("VERCEL"))}
        if os.getenv("VERCEL") and not result["storage"]["durable"]:
            result.setdefault("unavailable", []).append({"source": "Storage", "status": "unavailable", "reason": "Database connection was lost. This result remains in this browser tab; durable report/history retrieval is unavailable."})
            if result.get("state") == "completed":
                result["state"] = "partial"
        # Local mirror preserves this instance's completed reports if Mongo goes down mid-session.
        try:
            with self.connection() as db:
                db.execute("INSERT OR REPLACE INTO scans (scan_id,url,created_epoch,fingerprint,result,owner) VALUES (?, ?, ?, ?, ?, ?)", (result["scan_id"], result["url"], now, doc["fingerprint"], json.dumps(result, ensure_ascii=False), owner or ""))
                db.execute("DELETE FROM scans WHERE created_epoch < ?", (now - 30 * 86400,))
        except sqlite3.Error:
            log.warning("Local result storage is unavailable; completed analysis was retained in the response.")
            if self.mode not in {"postgres", "mongodb"}:
                result["storage"] = {"mode": "unavailable", "durable": False}
                missing = {"source": "Storage", "status": "unavailable", "reason": "Completed analysis could not be saved. Keep this result open; history/report retrieval is unavailable for this scan."}
                result["unavailable"] = [item for item in result.get("unavailable", []) if item.get("source") != "Storage"] + [missing]
                if result.get("state") == "completed":
                    result["state"] = "partial"
        return self.mode

    def get(self, scan_id: str, owner=None) -> dict | None:
        records = self._postgres_records(owner, scan_id=scan_id, limit=1)
        if records:
            return records[0]
        collection = self._mongo()
        if collection is not None:
            try:
                doc = collection.find_one({**self._scope(owner), "scan_id": scan_id}, {"result": 1})
                if doc:
                    return doc["result"]
            except PyMongoError:
                self._failed_mongo()
        scope, args = self._local_scope(owner)
        with self.connection() as db:
            row = db.execute("SELECT result FROM scans WHERE scan_id = ? AND created_epoch >= ?" + scope, [scan_id, time.time() - 30 * 86400, *args]).fetchone()
        result = json.loads(row[0]) if row else None
        return result if result and result.get("schema_version") == SCHEMA_VERSION else None

    def recent(self, limit=50, owner=None) -> list[dict]:
        combined = {record['scan_id']: record for record in self._postgres_records(owner, limit=limit)}
        collection = self._mongo()
        if collection is not None:
            try:
                for doc in collection.find(self._scope(owner), {"result": 1}).sort("created_epoch", -1).limit(limit):
                    combined[doc["result"]["scan_id"]] = doc["result"]
            except PyMongoError:
                self._failed_mongo()
        scope, args = self._local_scope(owner)
        with self.connection() as db:
            rows = db.execute("SELECT result FROM scans WHERE created_epoch >= ?" + scope + " ORDER BY created_epoch DESC LIMIT ?", [time.time() - 30 * 86400, *args, limit]).fetchall()
        for row in rows:
            result = json.loads(row[0])
            if result.get("schema_version") == SCHEMA_VERSION:
                combined[result["scan_id"]] = result
        return sorted(combined.values(), key=lambda r: r["timestamp"], reverse=True)[:limit]

    def latest_url(self, url: str, owner=None) -> dict | None:
        records = self._postgres_records(owner, url=url, limit=1)
        if records:
            return records[0]
        collection = self._mongo()
        if collection is not None:
            try:
                doc = collection.find_one({**self._scope(owner), "url": url}, {"result": 1}, sort=[("created_epoch", -1)])
                if doc:
                    return doc["result"]
            except PyMongoError:
                self._failed_mongo()
        scope, args = self._local_scope(owner)
        with self.connection() as db:
            row = db.execute("SELECT result FROM scans WHERE url = ? AND created_epoch >= ?" + scope + " ORDER BY created_epoch DESC LIMIT 1", [url, time.time() - 30 * 86400, *args]).fetchone()
        result = json.loads(row[0]) if row else None
        return result if result and result.get("schema_version") == SCHEMA_VERSION else None

    def cached(self, url: str, owner=None) -> dict | None:
        ttl = max(0, int(os.getenv("SCAN_CACHE_TTL", "300")))
        now = time.time()
        collection = self._mongo()
        records = self._postgres_records(owner, url=url, fingerprint=config_fingerprint(), since=now-ttl, limit=1)
        result = records[0] if records else None
        if collection is not None:
            try:
                doc = collection.find_one({**self._scope(owner), "url": url, "fingerprint": config_fingerprint(), "created_epoch": {"$gte": now - ttl}}, {"result": 1}, sort=[("created_epoch", -1)])
                result = doc["result"] if doc else None
            except PyMongoError:
                self._failed_mongo()
        if result is None:
            scope, args = self._local_scope(owner)
            with self.connection() as db:
                row = db.execute("SELECT result FROM scans WHERE url = ? AND created_epoch >= ? AND fingerprint = ?" + scope + " ORDER BY created_epoch DESC LIMIT 1", [url, now - ttl, config_fingerprint(), *args]).fetchone()
            result = json.loads(row[0]) if row else None
        # Cache never manufactures missing features or preserves failed fetches as completed scans.
        if result and result.get("schema_version") == SCHEMA_VERSION and result.get("features", {}).get("http", {}).get("status") == "completed" and "evidence" in result:
            return {**result, "cached": True, "cached_at": result["timestamp"]}
        return None

    def summaries(self, owner, limit=10000):
        """Read small dashboard records without loading megabytes of crawl evidence."""
        combined = {record['scan_id']: record for record in self._postgres_records(owner, limit=limit, summaries=True)}
        collection = self._mongo()
        if collection is not None:
            try:
                for doc in collection.find(self._scope(owner), {"summary": 1}).sort("created_epoch", -1).limit(limit):
                    if doc.get("summary"):
                        combined[doc["summary"]["scan_id"]] = doc["summary"]
            except PyMongoError:
                self._failed_mongo()
        scope, args = self._local_scope(owner)
        fields = ("scan_id", "url", "timestamp", "title", "risk_score", "assessment", "state", "features.content.status")
        columns = ",".join("json_extract(result, '$." + key + "')" for key in fields)
        with self.connection() as db:
            rows = db.execute("SELECT " + columns + " FROM scans WHERE created_epoch >= ?" + scope + " ORDER BY created_epoch DESC LIMIT ?", [time.time() - 30 * 86400, *args, limit]).fetchall()
        for row in rows:
            record = dict(zip((*fields[:-1], "content_status"), row))
            combined[record["scan_id"]] = record
        return sorted(combined.values(), key=lambda r: r["timestamp"], reverse=True)[:limit]
