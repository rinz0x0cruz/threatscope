"""ThreatScope command-line interface.

Usage:
    python -m threatscope update            Fetch sources, score, and store
    python -m threatscope report --top 20   Print a prioritized CVE digest
    python -m threatscope dashboard --open  Generate and open the HTML dashboard
    python -m threatscope selftest          Run offline self-tests (no network)
"""
import argparse
import json
import os
import sys
import webbrowser

from . import __version__, feeds, prioritize, render
from .store import Store, now_iso

DEFAULT_CONFIG = {
    "lookback_days": 7,
    "sources": {
        "cisa_kev": {"enabled": True},
        "nvd": {"enabled": True, "results_per_page": 200, "max_pages": 5},
        "epss": {"enabled": True, "batch_size": 100},
        "github_advisories": {"enabled": True, "per_page": 100, "max_pages": 3},
        "news_rss": {
            "enabled": True,
            "feeds": [
                "https://www.bleepingcomputer.com/feed/",
                "https://feeds.feedburner.com/TheHackersNews",
                "https://krebsonsecurity.com/feed/",
                "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            ],
        },
        "threatfox": {"enabled": False, "days": 1},
        "poc_github": {"enabled": True, "top_n_enrich": 50, "delay": 0.4},
    },
    "scoring": {"weights": {"cvss": 0.35, "epss": 0.35, "kev": 0.2, "poc": 0.1}, "kev_floor": 80},
    "output": {"dashboard_path": "dashboard.html", "top_n": 50},
}


def _deep_merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path):
    if path and os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            return _deep_merge(DEFAULT_CONFIG, json.load(fh))
    return json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy


def cmd_update(cfg, store):
    src = cfg["sources"]

    kev = {}
    if src["cisa_kev"]["enabled"]:
        try:
            kev = feeds.fetch_cisa_kev()
            store.log_run("cisa_kev", len(kev), "ok")
            print("  [KEV]  %d known-exploited CVEs" % len(kev))
        except Exception as e:
            store.log_run("cisa_kev", 0, "error")
            print("  [KEV]  error: %s" % e)

    cves = []
    if src["nvd"]["enabled"]:
        try:
            n = src["nvd"]
            cves = feeds.fetch_nvd(cfg["lookback_days"], n["results_per_page"], n["max_pages"])
            store.log_run("nvd", len(cves), "ok")
            print("  [NVD]  %d recent CVEs" % len(cves))
        except Exception as e:
            store.log_run("nvd", 0, "error")
            print("  [NVD]  error: %s" % e)

    gh = []
    if src["github_advisories"]["enabled"]:
        try:
            g = src["github_advisories"]
            gh = feeds.fetch_github_advisories(cfg["lookback_days"], g["per_page"], g["max_pages"])
            store.log_run("github_advisories", len(gh), "ok")
            print("  [GHSA] %d advisories" % len(gh))
        except Exception as e:
            store.log_run("github_advisories", 0, "error")
            print("  [GHSA] error: %s" % e)

    seen = {r["cve_id"] for r in cves}
    for adv in gh:
        cid = adv.get("cve_id")
        if cid and cid not in seen:
            cves.append({
                "cve_id": cid, "published": adv.get("published"), "modified": adv.get("published"),
                "cvss": adv.get("cvss"), "severity": adv.get("severity"),
                "description": adv.get("summary"), "refs": adv.get("url") or "", "source": "GitHub",
            })
            seen.add(cid)

    if src["epss"]["enabled"] and cves:
        try:
            epss = feeds.fetch_epss([r["cve_id"] for r in cves], src["epss"]["batch_size"])
            store.log_run("epss", len(epss), "ok")
            print("  [EPSS] scored %d CVEs" % len(epss))
        except Exception as e:
            epss = {}
            store.log_run("epss", 0, "error")
            print("  [EPSS] error: %s" % e)
    else:
        epss = {}

    for r in cves:
        cid = r["cve_id"]
        r["in_kev"] = cid in kev
        if cid in kev:
            r["kev_date_added"] = kev[cid].get("date_added")
        r["epss"] = epss.get(cid)
    prioritize.enrich_and_sort(cves, cfg["scoring"]["weights"], cfg["scoring"]["kev_floor"])

    pg = src.get("poc_github", {})
    if pg.get("enabled") and cves:
        top = cves[:pg.get("top_n_enrich", 50)]
        try:
            pocs = feeds.fetch_pocs([r["cve_id"] for r in top], pg.get("delay", 0.4))
            for r in cves:
                info = pocs.get(r["cve_id"])
                if info:
                    r["has_poc"], r["poc_count"], r["poc_url"] = True, info["count"], info["url"]
            store.log_run("poc_github", len(pocs), "ok")
            print("  [POC]  %d of top %d CVEs have public exploits" % (len(pocs), len(top)))
        except Exception as e:
            store.log_run("poc_github", 0, "error")
            print("  [POC]  error: %s" % e)
        prioritize.enrich_and_sort(cves, cfg["scoring"]["weights"], cfg["scoring"]["kev_floor"])

    for r in cves:
        store.upsert_cve(r)

    if src["news_rss"]["enabled"]:
        try:
            news = feeds.fetch_news(src["news_rss"]["feeds"])
            for item in news:
                store.upsert_news(item)
            store.log_run("news_rss", len(news), "ok")
            print("  [NEWS] %d articles" % len(news))
        except Exception as e:
            store.log_run("news_rss", 0, "error")
            print("  [NEWS] error: %s" % e)

    tf = src.get("threatfox", {})
    if tf.get("enabled"):
        try:
            iocs = feeds.fetch_threatfox(tf.get("days", 1), os.environ.get("THREATFOX_AUTH_KEY"))
            for item in iocs:
                store.upsert_ioc(item)
            store.log_run("threatfox", len(iocs), "ok")
            print("  [IOC]  %d indicators" % len(iocs))
        except Exception as e:
            store.log_run("threatfox", 0, "error")
            print("  [IOC]  error: %s" % e)

    store.commit()
    s = store.stats()
    print("\n  Stored: %d CVEs (%d KEV, %d PoC, %d Critical) | %d news | %d IOCs"
          % (s["total_cves"], s["kev"], s["with_poc"], s["critical"], s["news"], s["iocs"]))


def cmd_report(store, top):
    rows = store.top_cves(top)
    print("\n== ThreatScope: top %d prioritized CVEs ==\n" % top)
    if not rows:
        print("  (no data yet - run 'python -m threatscope update' first)\n")
        return
    for r in rows:
        marks = []
        if r["in_kev"]:
            marks.append("KEV")
        if r["has_poc"]:
            marks.append("PoC")
        flag = ",".join(marks)
        desc = (r["description"] or "").replace("\n", " ")[:70]
        print("  %5.1f  %-8s  %-18s %-8s %s" % (r["score"] or 0, r["tier"] or "-", r["cve_id"], flag, desc))
    news = store.latest_news(8)
    if news:
        print("\n== Latest security news ==\n")
        for n in news:
            print("  - [%s] %s" % (n["source"] or "", (n["title"] or "")[:88]))
    print("")


def cmd_dashboard(cfg, store, open_after):
    html = render.build_dashboard(store.top_cves(cfg["output"]["top_n"]),
                                  store.latest_news(25), store.stats())
    out_path = cfg["output"]["dashboard_path"]
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)
    full = os.path.abspath(out_path)
    print("Dashboard written to %s" % full)
    if open_after:
        webbrowser.open("file:///" + full.replace("\\", "/"))


def cmd_selftest():
    from .prioritize import score_cve, tier_for, enrich_and_sort
    ok = [True]

    def check(cond, msg):
        print(("  PASS  " if cond else "  FAIL  ") + msg)
        ok[0] = ok[0] and cond

    s1, t1, _ = score_cve(9.8, 0.97, True)
    check(t1 == "Critical" and s1 >= 80, "KEV + high CVSS/EPSS -> Critical")
    s2, _, _ = score_cve(2.0, 0.0, True)
    check(s2 >= 80, "KEV floor enforced for low-CVSS exploited bug")
    _, t3, _ = score_cve(4.0, 0.02, False)
    check(t3 in ("Low", "Medium"), "low CVSS + low EPSS -> Low/Medium")
    s4, _, _ = score_cve(None, None, False)
    check(s4 == 0.0, "no data -> score 0")
    check(tier_for(80) == "Critical" and tier_for(59.9) == "Medium", "tier boundaries")
    data = [{"cve_id": "A", "cvss": 5, "epss": 0.1, "in_kev": False},
            {"cve_id": "B", "cvss": 9, "epss": 0.9, "in_kev": True}]
    enrich_and_sort(data)
    check(data[0]["cve_id"] == "B", "enrich_and_sort orders highest risk first")
    print("\nSELF-TEST: " + ("ALL PASSED" if ok[0] else "FAILURES PRESENT") + "\n")
    return 0 if ok[0] else 1


def main(argv=None):
    p = argparse.ArgumentParser(prog="threatscope",
                                description="Self-hosted threat-intelligence & CVE prioritization.")
    p.add_argument("--version", action="version", version="ThreatScope " + __version__)
    p.add_argument("--config", default="config.json")
    p.add_argument("--data-dir", default="data")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("update", help="Fetch sources, score, and store")
    rp = sub.add_parser("report", help="Print a prioritized CVE digest")
    rp.add_argument("--top", type=int, default=20)
    dp = sub.add_parser("dashboard", help="Generate the HTML dashboard")
    dp.add_argument("--open", action="store_true", help="Open the dashboard in a browser")
    sub.add_parser("selftest", help="Run offline self-tests")
    args = p.parse_args(argv)

    if args.cmd == "selftest":
        return cmd_selftest()
    if not args.cmd:
        p.print_help()
        return 0

    cfg = load_config(args.config)
    if not os.path.isabs(cfg["output"]["dashboard_path"]):
        cfg["output"]["dashboard_path"] = os.path.join(args.data_dir, cfg["output"]["dashboard_path"])
    store = Store(os.path.join(args.data_dir, "threatscope.db"))
    try:
        if args.cmd == "update":
            print("ThreatScope update @ %s" % now_iso())
            cmd_update(cfg, store)
        elif args.cmd == "report":
            cmd_report(store, args.top)
        elif args.cmd == "dashboard":
            cmd_dashboard(cfg, store, args.open)
    finally:
        store.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
