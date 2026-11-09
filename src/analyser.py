from __future__ import annotations
import csv
import re
from pathlib import Path
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {".xyz", ".top", ".icu", ".zip", ".mov"}
LOOKALIKES = {
    "microsoft": ["micr0soft", "rnicrosoft", "mircosoft"],
    "paypal": ["paypa1", "paypai"],
    "google": ["g00gle", "googel"],
}
KEYWORDS = ["login", "verify", "reset", "password", "account", "update", "wallet"]


def score_url(url: str) -> dict:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    score = 0
    reasons = []
    if re.fullmatch(r"\d+\.\d+\.\d+\.\d+", host or ""):
        score += 40
        reasons.append("ip_literal_host")
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 25
            reasons.append(f"suspicious_tld:{tld}")
    for brand, variants in LOOKALIKES.items():
        if any(v in host for v in variants):
            score += 35
            reasons.append(f"brand_lookalike:{brand}")
    if any(k in path or k in host for k in KEYWORDS) and score > 0:
        score += 10
        reasons.append("credential_keyword")
    if parsed.scheme == "http":
        score += 10
        reasons.append("no_https")
    band = "high" if score >= 50 else "medium" if score >= 25 else "low"
    return {"url": url, "host": host, "score": score, "risk": band, "reasons": reasons}


def analyse_csv(path: Path) -> dict:
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    results = [score_url(r["url"]) for r in rows if r.get("url")]
    return {
        "url_count": len(results),
        "high": sum(1 for r in results if r["risk"] == "high"),
        "results": sorted(results, key=lambda x: x["score"], reverse=True),
    }
