"""Minimal standard-library HTTP helpers (GET/POST JSON, gzip, retries).

No third-party dependencies — uses urllib only.
"""
import gzip
import json
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_HEADERS = {
    "User-Agent": "ThreatScope/1.0 (+https://github.com/)",
    "Accept": "application/json, text/xml, application/xml, */*",
    "Accept-Encoding": "gzip",
}


def _open(url, data=None, headers=None, method="GET", timeout=30):
    merged = dict(DEFAULT_HEADERS)
    if headers:
        merged.update(headers)
    req = urllib.request.Request(url, data=data, headers=merged, method=method)
    resp = urllib.request.urlopen(req, timeout=timeout)
    try:
        raw = resp.read()
        if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
            raw = gzip.decompress(raw)
        return raw
    finally:
        resp.close()


def get_bytes(url, params=None, headers=None, timeout=30, retries=2, backoff=1.5):
    if params:
        sep = "&" if "?" in url else "?"
        url = url + sep + urllib.parse.urlencode(params)
    last_err = None
    for attempt in range(retries + 1):
        try:
            return _open(url, headers=headers, timeout=timeout)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
            last_err = exc
            if attempt < retries:
                time.sleep(backoff * (attempt + 1))
    raise last_err


def get_text(url, params=None, headers=None, timeout=30):
    return get_bytes(url, params=params, headers=headers, timeout=timeout).decode("utf-8", "replace")


def get_json(url, params=None, headers=None, timeout=30):
    return json.loads(get_text(url, params=params, headers=headers, timeout=timeout))


def post_json(url, payload, headers=None, timeout=30):
    body = json.dumps(payload).encode("utf-8")
    merged = {"Content-Type": "application/json"}
    if headers:
        merged.update(headers)
    raw = _open(url, data=body, headers=merged, method="POST", timeout=timeout)
    return json.loads(raw.decode("utf-8", "replace"))
