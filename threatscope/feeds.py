"""Public threat-intelligence source fetchers.

Each function returns normalized Python dicts. All sources are public; optional
API keys (via environment variables) only raise rate limits or unlock extras.
"""
import datetime
import email.utils
import hashlib
import os
import re
import time
import xml.etree.ElementTree as ET

from . import http

SOURCE_NAMES = {
    "bleepingcomputer.com": "BleepingComputer",
    "feedburner.com": "The Hacker News",
    "feeds.feedburner.com": "The Hacker News",
    "krebsonsecurity.com": "Krebs on Security",
    "cisa.gov": "CISA",
}


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _parse_iso(s):
    if not s:
        return None
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt


# ----------------------- CISA KEV -----------------------
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_cisa_kev():
    """Return {cve_id: {date_added, vendor, product, name}}."""
    data = http.get_json(KEV_URL, timeout=60)
    out = {}
    for v in data.get("vulnerabilities", []):
        cid = v.get("cveID")
        if cid:
            out[cid] = {
                "date_added": v.get("dateAdded"),
                "vendor": v.get("vendorProject"),
                "product": v.get("product"),
                "name": v.get("vulnerabilityName"),
            }
    return out


# ----------------------- NVD -----------------------
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            cvss_data = arr[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            sev = cvss_data.get("baseSeverity") or arr[0].get("baseSeverity")
            if score is not None:
                return float(score), sev
    return None, None


def fetch_nvd(lookback_days=7, results_per_page=200, max_pages=5):
    end = _now()
    start = end - datetime.timedelta(days=lookback_days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    out, start_index = [], 0
    for _ in range(max_pages):
        params = {
            "lastModStartDate": start.strftime(fmt),
            "lastModEndDate": end.strftime(fmt),
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        data = http.get_json(NVD_URL, params=params, headers=headers, timeout=60)
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            cvss, sev = _nvd_cvss(cve)
            descs = cve.get("descriptions", [])
            desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "")
            refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
            out.append({
                "cve_id": cid,
                "published": cve.get("published"),
                "modified": cve.get("lastModified"),
                "cvss": cvss,
                "severity": sev,
                "description": desc,
                "refs": " ".join(refs[:10]),
                "source": "NVD",
            })
        total = data.get("totalResults", 0)
        start_index += results_per_page
        if start_index >= total:
            break
        # Respect NVD rate limits (5 req / 30s without a key, 50 with).
        time.sleep(0.8 if api_key else 6.5)
    return out


# ----------------------- EPSS -----------------------
EPSS_URL = "https://api.first.org/data/v1/epss"


def fetch_epss(cve_ids, batch_size=100):
    """Return {cve_id: epss_probability_float}."""
    out = {}
    ids = [c for c in cve_ids if c]
    for i in range(0, len(ids), batch_size):
        batch = ids[i:i + batch_size]
        try:
            data = http.get_json(EPSS_URL, params={"cve": ",".join(batch)}, timeout=60)
        except Exception:
            continue
        for row in data.get("data", []):
            try:
                out[row.get("cve")] = float(row.get("epss"))
            except (TypeError, ValueError):
                pass
    return out


# ----------------------- GitHub Security Advisories -----------------------
GHSA_URL = "https://api.github.com/advisories"


def fetch_github_advisories(lookback_days=7, per_page=100, max_pages=3):
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    cutoff = _now() - datetime.timedelta(days=lookback_days)
    out = []
    for page in range(1, max_pages + 1):
        params = {"per_page": per_page, "page": page, "sort": "published",
                  "direction": "desc", "type": "reviewed"}
        try:
            data = http.get_json(GHSA_URL, params=params, headers=headers, timeout=60)
        except Exception:
            break
        if not isinstance(data, list) or not data:
            break
        stop = False
        for adv in data:
            pub_dt = _parse_iso(adv.get("published_at"))
            if pub_dt and pub_dt < cutoff:
                stop = True
                break
            cvss_obj = adv.get("cvss") or {}
            score = cvss_obj.get("score")
            out.append({
                "ghsa_id": adv.get("ghsa_id"),
                "cve_id": adv.get("cve_id"),
                "summary": adv.get("summary") or "",
                "severity": (adv.get("severity") or "").title(),
                "cvss": float(score) if score else None,
                "url": adv.get("html_url"),
                "published": adv.get("published_at"),
            })
        if stop:
            break
    return out


# ----------------------- Security news RSS/Atom -----------------------
def _domain(url):
    m = re.match(r"https?://([^/]+)", url or "")
    host = (m.group(1) if m else url or "").lower()
    for key, name in SOURCE_NAMES.items():
        if key in host:
            return name
    return host.replace("www.", "")


def _strip_html(s):
    s = re.sub(r"<[^>]+>", "", s or "")
    return re.sub(r"\s+", " ", s).strip()[:300]


def _rfc_to_iso(s):
    if not s:
        return None
    try:
        dt = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError):
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _text(el):
    return (el.text or "").strip() if el is not None else ""


def _news_item(title, link, pub, desc, source):
    pub_iso = _rfc_to_iso(pub) or _parse_iso(pub)
    if isinstance(pub_iso, datetime.datetime):
        pub_iso = pub_iso.strftime("%Y-%m-%dT%H:%M:%SZ")
    uid = hashlib.sha1((link or title or "").encode("utf-8", "replace")).hexdigest()
    return {"id": uid, "title": title, "link": link,
            "published": pub_iso or "", "summary": _strip_html(desc), "source": source}


def _parse_feed(raw, source_url):
    root = ET.fromstring(raw.decode("utf-8", "replace"))
    source = _domain(source_url)
    items = []
    channel = root.find("channel")
    if channel is not None:  # RSS 2.0
        for it in channel.findall("item"):
            items.append(_news_item(_text(it.find("title")), _text(it.find("link")),
                                    _text(it.find("pubDate")), _text(it.find("description")), source))
        return items
    ns = "{http://www.w3.org/2005/Atom}"  # Atom
    for it in root.findall(ns + "entry"):
        link_el = it.find(ns + "link")
        link = link_el.get("href") if link_el is not None else ""
        pub = _text(it.find(ns + "updated")) or _text(it.find(ns + "published"))
        items.append(_news_item(_text(it.find(ns + "title")), link, pub,
                                _text(it.find(ns + "summary")), source))
    return items


def fetch_news(feeds):
    out = []
    for url in feeds:
        try:
            raw = http.get_bytes(url, timeout=45)
            out.extend(_parse_feed(raw, url))
        except Exception:
            continue
    return out


# ----------------------- abuse.ch ThreatFox (optional) -----------------------
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"


def fetch_threatfox(days=1, auth_key=None):
    if not auth_key:
        return []
    try:
        data = http.post_json(THREATFOX_URL, {"query": "get_iocs", "days": days},
                             headers={"Auth-Key": auth_key}, timeout=60)
    except Exception:
        return []
    out = []
    for row in (data.get("data") or []):
        out.append({
            "id": str(row.get("id")),
            "ioc": row.get("ioc"),
            "ioc_type": row.get("ioc_type"),
            "threat": row.get("threat_type"),
            "malware": row.get("malware_printable"),
            "confidence": row.get("confidence_level"),
            "source": "ThreatFox",
        })
    return out


# ----------------------- Public PoC / exploit availability (poc-in-github) -----------------------
POC_API = "https://poc-in-github.motikan2010.net/api/v1/"


def fetch_pocs(cve_ids, delay=0.4):
    """Return {cve_id: {count, url, stars}} for CVEs with public GitHub PoCs.

    Uses the public poc-in-github index (no API key required). Query only the
    CVEs you care about (e.g. the top prioritized set) to stay polite.
    """
    out = {}
    for cid in cve_ids:
        if not cid:
            continue
        try:
            data = http.get_json(POC_API, params={"cve_id": cid}, timeout=30)
        except Exception:
            continue
        pocs = data.get("pocs") or []
        if pocs:
            best = max(pocs, key=lambda p: int(p.get("stargazers_count") or 0))
            out[cid] = {"count": len(pocs), "url": best.get("html_url"),
                        "stars": int(best.get("stargazers_count") or 0)}
        if delay:
            time.sleep(delay)
    return out
