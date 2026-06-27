"""SQLite persistence for ThreatScope (dedupe + first/last-seen tracking)."""
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    published TEXT,
    modified TEXT,
    cvss REAL,
    severity TEXT,
    epss REAL,
    in_kev INTEGER DEFAULT 0,
    kev_date_added TEXT,
    score REAL,
    tier TEXT,
    rationale TEXT,
    description TEXT,
    refs TEXT,
    has_poc INTEGER DEFAULT 0,
    poc_count INTEGER DEFAULT 0,
    poc_url TEXT,
    source TEXT,
    first_seen TEXT,
    last_seen TEXT
);
CREATE TABLE IF NOT EXISTS news (
    id TEXT PRIMARY KEY,
    title TEXT,
    link TEXT,
    published TEXT,
    source TEXT,
    summary TEXT,
    first_seen TEXT
);
CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    ioc TEXT,
    ioc_type TEXT,
    threat TEXT,
    malware TEXT,
    confidence INTEGER,
    first_seen TEXT,
    source TEXT
);
CREATE TABLE IF NOT EXISTS runs (
    ts TEXT,
    source TEXT,
    count INTEGER,
    status TEXT
);
"""


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Store:
    def __init__(self, path):
        parent = os.path.dirname(os.path.abspath(path))
        os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._ensure_columns()

    def _ensure_columns(self):
        existing = {r["name"] for r in self.conn.execute("PRAGMA table_info(cves)")}
        for col, ddl in (("has_poc", "INTEGER DEFAULT 0"),
                         ("poc_count", "INTEGER DEFAULT 0"),
                         ("poc_url", "TEXT")):
            if col not in existing:
                self.conn.execute("ALTER TABLE cves ADD COLUMN %s %s" % (col, ddl))
        self.conn.commit()

    def close(self):
        self.conn.close()

    def commit(self):
        self.conn.commit()

    # ---- CVEs ----
    def upsert_cve(self, rec):
        ts = now_iso()
        row = self.conn.execute(
            "SELECT first_seen FROM cves WHERE cve_id = ?", (rec["cve_id"],)
        ).fetchone()
        first_seen = row["first_seen"] if row else ts
        self.conn.execute(
            """INSERT INTO cves
               (cve_id, published, modified, cvss, severity, epss, in_kev, kev_date_added,
                score, tier, rationale, description, refs, has_poc, poc_count, poc_url,
                source, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(cve_id) DO UPDATE SET
                 published=excluded.published, modified=excluded.modified, cvss=excluded.cvss,
                 severity=excluded.severity, epss=excluded.epss, in_kev=excluded.in_kev,
                 kev_date_added=excluded.kev_date_added, score=excluded.score, tier=excluded.tier,
                 rationale=excluded.rationale, description=excluded.description, refs=excluded.refs,
                 has_poc=excluded.has_poc, poc_count=excluded.poc_count, poc_url=excluded.poc_url,
                 source=excluded.source, last_seen=excluded.last_seen""",
            (rec["cve_id"], rec.get("published"), rec.get("modified"), rec.get("cvss"),
             rec.get("severity"), rec.get("epss"), 1 if rec.get("in_kev") else 0,
             rec.get("kev_date_added"), rec.get("score"), rec.get("tier"), rec.get("rationale"),
             rec.get("description"), rec.get("refs"), 1 if rec.get("has_poc") else 0,
             rec.get("poc_count") or 0, rec.get("poc_url"), rec.get("source"), first_seen, ts),
        )

    def top_cves(self, limit=50):
        cur = self.conn.execute(
            "SELECT * FROM cves ORDER BY score DESC, modified DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    # ---- News ----
    def upsert_news(self, item):
        self.conn.execute(
            """INSERT INTO news (id, title, link, published, source, summary, first_seen)
               VALUES (?,?,?,?,?,?,?)
               ON CONFLICT(id) DO NOTHING""",
            (item["id"], item.get("title"), item.get("link"), item.get("published"),
             item.get("source"), item.get("summary"), now_iso()),
        )

    def latest_news(self, limit=25):
        cur = self.conn.execute(
            "SELECT * FROM news ORDER BY published DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    # ---- IOCs ----
    def upsert_ioc(self, item):
        self.conn.execute(
            """INSERT INTO iocs (id, ioc, ioc_type, threat, malware, confidence, first_seen, source)
               VALUES (?,?,?,?,?,?,?,?)
               ON CONFLICT(id) DO NOTHING""",
            (item["id"], item.get("ioc"), item.get("ioc_type"), item.get("threat"),
             item.get("malware"), item.get("confidence"), now_iso(), item.get("source")),
        )

    # ---- Runs / stats ----
    def log_run(self, source, count, status):
        self.conn.execute(
            "INSERT INTO runs (ts, source, count, status) VALUES (?,?,?,?)",
            (now_iso(), source, count, status),
        )

    def stats(self):
        q = self.conn.execute
        return {
            "total_cves": q("SELECT COUNT(*) AS x FROM cves").fetchone()["x"],
            "kev": q("SELECT COUNT(*) AS x FROM cves WHERE in_kev=1").fetchone()["x"],
            "critical": q("SELECT COUNT(*) AS x FROM cves WHERE tier='Critical'").fetchone()["x"],
            "with_poc": q("SELECT COUNT(*) AS x FROM cves WHERE has_poc=1").fetchone()["x"],
            "news": q("SELECT COUNT(*) AS x FROM news").fetchone()["x"],
            "iocs": q("SELECT COUNT(*) AS x FROM iocs").fetchone()["x"],
        }
