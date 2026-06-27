"""Exploitability-aware CVE prioritization.

Combines CVSS (impact), EPSS (exploitation probability), and CISA KEV
(confirmed in-the-wild exploitation) into a single transparent 0-100 score.
"""

DEFAULT_WEIGHTS = {"cvss": 0.35, "epss": 0.35, "kev": 0.2, "poc": 0.1}


def tier_for(score):
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    return "Low"


def score_cve(cvss=None, epss=None, in_kev=False, has_poc=False, weights=None, kev_floor=80):
    """Return (score_0_100, tier, rationale).

    cvss    : NVD CVSS base score 0-10 (or None)
    epss    : EPSS probability 0-1 (or None)
    in_kev  : True if listed in CISA KEV
    has_poc : True if a public proof-of-concept / exploit exists
    """
    w = dict(DEFAULT_WEIGHTS)
    if weights:
        w.update(weights)

    cvss_v = max(0.0, min(float(cvss), 10.0)) if cvss is not None else 0.0
    epss_v = max(0.0, min(float(epss), 1.0)) if epss is not None else 0.0

    raw = (w["cvss"] * (cvss_v / 10.0)
           + w["epss"] * epss_v
           + w["kev"] * (1.0 if in_kev else 0.0)
           + w.get("poc", 0.0) * (1.0 if has_poc else 0.0))
    score = round(raw * 100.0, 1)
    if in_kev and score < kev_floor:
        score = float(kev_floor)
    score = min(score, 100.0)

    parts = [("CVSS %.1f" % cvss_v) if cvss is not None else "CVSS n/a",
             ("EPSS %.1f%%" % (epss_v * 100.0)) if epss is not None else "EPSS n/a"]
    if has_poc:
        parts.append("public PoC available")
    if in_kev:
        parts.append("in CISA KEV (actively exploited)")
    return score, tier_for(score), ", ".join(parts)


def enrich_and_sort(cves, weights=None, kev_floor=80):
    """Annotate each record with score/tier/rationale, then sort highest-risk first."""
    for rec in cves:
        s, t, why = score_cve(rec.get("cvss"), rec.get("epss"), rec.get("in_kev", False),
                              rec.get("has_poc", False), weights, kev_floor)
        rec["score"], rec["tier"], rec["rationale"] = s, t, why
    cves.sort(key=lambda r: r.get("score", 0), reverse=True)
    return cves
