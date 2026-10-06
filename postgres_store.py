"""Bounded Postgres storage for Neon/Vercel. No workers or persistent local pool."""
from __future__ import annotations
from contextlib import contextmanager
import logging
import time
from urllib.parse import urlsplit

import certifi
import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

log = logging.getLogger(__name__)


class PostgresStore:
    def __init__(self, dsn):
        self.dsn = dsn
        self.ready = False
        self.retry_at = 0
        parsed = urlsplit(dsn)
        if parsed.scheme not in {'postgres', 'postgresql'} or not parsed.hostname or not parsed.path.strip('/'):
            log.warning('Invalid DATABASE_URL configuration; connection details are not logged.')
            self.retry_at = float('inf')
        self.available()

    @contextmanager
    def connection(self):
        # Verify the pooled endpoint's certificate and hostname; close before returning.
        with psycopg.connect(self.dsn, sslmode='verify-full', sslrootcert=certifi.where(), connect_timeout=3,
                            row_factory=dict_row, autocommit=True) as db:
            # Neon uses transaction pooling: startup options and session settings
            # are not portable. Pin each operation to one bounded transaction.
            with db.transaction():
                db.execute("SET LOCAL statement_timeout = '2s'")
                db.execute("SET LOCAL lock_timeout = '1s'")
                yield db

    def failed(self):
        self.ready = False
        self.retry_at = time.monotonic() + 30
        log.warning('Postgres operation unavailable; connection details are not logged.')

    def available(self):
        if self.ready:
            return True
        if time.monotonic() < self.retry_at:
            return False
        try:
            with self.connection() as db:
                # Serialize first-run DDL when several serverless instances start together.
                db.execute('SELECT pg_advisory_xact_lock(743928160)')
                db.execute('''CREATE TABLE IF NOT EXISTS phishx_scans (
                    scan_id TEXT PRIMARY KEY, owner TEXT NOT NULL, url TEXT NOT NULL,
                    schema_version INTEGER NOT NULL, created_epoch DOUBLE PRECISION NOT NULL,
                    fingerprint TEXT NOT NULL, result JSONB NOT NULL, summary JSONB NOT NULL)''')
                db.execute('CREATE INDEX IF NOT EXISTS phishx_owner_url_age ON phishx_scans(owner,url,created_epoch DESC)')
                db.execute('CREATE INDEX IF NOT EXISTS phishx_scan_age ON phishx_scans(created_epoch)')
                db.execute('CREATE TABLE IF NOT EXISTS phishx_request_limits (bucket TEXT PRIMARY KEY, count INTEGER NOT NULL, expires_epoch DOUBLE PRECISION NOT NULL)')
                db.execute('CREATE INDEX IF NOT EXISTS phishx_limit_expiry ON phishx_request_limits(expires_epoch)')
            self.ready = True
        except (psycopg.Error, ValueError):
            self.failed()
        return self.ready

    def save(self, doc):
        with self.connection() as db:
            db.execute('''INSERT INTO phishx_scans VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(scan_id) DO UPDATE SET result=EXCLUDED.result, summary=EXCLUDED.summary''',
                (doc['scan_id'],doc['owner'],doc['url'],doc['schema_version'],doc['created_epoch'],doc['fingerprint'],Jsonb(doc['result']),Jsonb(doc['summary'])))
            db.execute('DELETE FROM phishx_scans WHERE scan_id IN (SELECT scan_id FROM phishx_scans WHERE created_epoch < %s ORDER BY created_epoch LIMIT 1000)', (time.time() - 30*86400,))

    def records(self, owner, version, limit=50, scan_id=None, url=None, fingerprint=None, since=None, summaries=False):
        filters = ['schema_version=%s', 'created_epoch >= %s']
        args = [version, max(time.time() - 30*86400, since or 0)]
        for column,value in [('owner',owner),('scan_id',scan_id),('url',url),('fingerprint',fingerprint)]:
            if value is not None:
                filters.append(column+'=%s')
                args.append(value)
        # Only fixed internal identifiers enter the SQL; all values are parameters.
        column = 'summary' if summaries else 'result'
        with self.connection() as db:
            rows = db.execute('SELECT '+column+' FROM phishx_scans WHERE '+' AND '.join(filters)+' ORDER BY created_epoch DESC LIMIT %s', [*args,limit]).fetchall()
        return [row[column] for row in rows]

    def rate_allowed(self, identity, limit):
        now = time.time()
        bucket = f'{identity}:{int(now // 60)}'
        with self.connection() as db:
            row = db.execute('''INSERT INTO phishx_request_limits VALUES (%s,1,%s)
                ON CONFLICT(bucket) DO UPDATE SET count=phishx_request_limits.count+1 RETURNING count''', (bucket,now+120)).fetchone()
            db.execute('DELETE FROM phishx_request_limits WHERE bucket IN (SELECT bucket FROM phishx_request_limits WHERE expires_epoch < %s ORDER BY expires_epoch LIMIT 1000)', (now,))
        return row['count'] <= limit
