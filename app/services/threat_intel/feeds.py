"""Threat-intelligence feeds: fetch, trim to what ORION uses, cache.

Only the addresses listed in FEEDS are ever requested (no user-supplied URL, so no way to aim this at an internal service),
every response has a size cap, and anything that looks like an indicator is validated before use. A feed that cannot be
reached falls back to the last cached copy and says so ("stale"); with no copy it is "unavailable". The run never pretends
a feed was read when it was not.

  kev      CISA Known Exploited Vulnerabilities: CVEs attackers are using now
  attack   MITRE ATT&CK: campaigns and the techniques they use (compacted)
  feodo    abuse.ch Feodo Tracker: command-and-control server addresses
  urlhaus  abuse.ch URLhaus: recently reported malware URLs (reduced to hosts)
EPSS (first.org) gives the likelihood a CVE is exploited and is used only to enrich the new KEV entries.
"""
import ipaddress
import json
import re
import tempfile
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import IntelCache

FEEDS: Dict[str, str] = {
    "kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_recent/",
}
EPSS_URL = "https://api.first.org/data/v1/epss"
MAX_BYTES = {"kev": 10_000_000, "attack": 90_000_000, "feodo": 5_000_000, "urlhaus": 15_000_000}
MAX_AGE = {"kev": timedelta(hours=12), "attack": timedelta(days=7), "feodo": timedelta(hours=12), "urlhaus": timedelta(hours=6)}
MAX_IOCS_PER_KIND = 5000
USER_AGENT = "ORION-threat-intel/0.1"

_DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")


# ── indicator validation ─────────────────────────────────────────────────────────

def valid_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved)


def valid_domain(value: str) -> bool:
    return bool(_DOMAIN.match(value.strip().lower()))


def valid_sha256(value: str) -> bool:
    return bool(_SHA256.match(value.strip().lower()))


# ── parsers (pure) ───────────────────────────────────────────────────────────────

def parse_kev(data: dict) -> List[dict]:
    out = []
    for item in data.get("vulnerabilities", []):
        cve = str(item.get("cveID", "")).strip()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", cve):
            continue
        out.append({
            "cve": cve, "vendor": item.get("vendorProject", ""), "product": item.get("product", ""),
            "name": item.get("vulnerabilityName", ""), "added": item.get("dateAdded", ""),
            "ransomware": str(item.get("knownRansomwareCampaignUse", "")).lower() == "known",
        })
    return out


def parse_attack(bundle: dict) -> dict:
    """ATT&CK STIX bundle -> {"techniques": {id: {...}}, "campaigns": [{...}]} (a few hundred KB instead of tens of MB)."""
    techniques: Dict[str, dict] = {}
    by_stix: Dict[str, str] = {}
    campaigns: Dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        kind = obj.get("type")
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external = next((r.get("external_id") for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if kind == "attack-pattern" and external:
            techniques[external] = {
                "name": obj.get("name", ""),
                "tactics": [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
                "platforms": obj.get("x_mitre_platforms", []),
            }
            by_stix[obj["id"]] = external
        elif kind == "campaign":
            campaigns[obj["id"]] = {"id": external, "name": obj.get("name", ""), "first_seen": obj.get("first_seen", ""),
                                    "last_seen": obj.get("last_seen", ""), "techniques": []}
    for obj in bundle.get("objects", []):
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "uses" and not obj.get("revoked"):
            campaign, technique = campaigns.get(obj.get("source_ref")), by_stix.get(obj.get("target_ref"))
            if campaign and technique and technique not in campaign["techniques"]:
                campaign["techniques"].append(technique)
    return {"techniques": techniques, "campaigns": [c for c in campaigns.values() if c["techniques"]]}


def parse_feodo(data) -> List[dict]:
    rows = data if isinstance(data, list) else data.get("blocklist", [])
    out = []
    for item in rows:
        ip = str(item.get("ip_address", "")).strip()
        if valid_ip(ip):
            out.append({"ip": ip, "malware": item.get("malware", ""), "last_online": item.get("last_online", "")})
    return out[:MAX_IOCS_PER_KIND]


def parse_urlhaus(text: str) -> dict:
    ips, domains = set(), set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        host = (urlparse(line).hostname or "").lower()
        if valid_ip(host):
            ips.add(host)
        elif valid_domain(host):
            domains.add(host)
    return {"ips": sorted(ips)[:MAX_IOCS_PER_KIND], "domains": sorted(domains)[:MAX_IOCS_PER_KIND]}


PARSERS: Dict[str, Callable] = {
    "kev": lambda raw: {"entries": parse_kev(json.loads(raw)), "release": json.loads(raw).get("dateReleased", "")},
    "attack": lambda raw: parse_attack(json.loads(raw)),
    "feodo": lambda raw: {"entries": parse_feodo(json.loads(raw))},
    "urlhaus": lambda raw: parse_urlhaus(raw.decode("utf-8", "replace")),
}


# ── selection helpers (pure) ─────────────────────────────────────────────────────

def recent_campaign_techniques(attack: dict, platform: str = "Linux", campaigns: int = 8) -> List[dict]:
    """Techniques used by the most recently active campaigns that apply to the platform, with the campaigns that use them."""
    chosen = sorted(attack.get("campaigns", []), key=lambda c: c.get("last_seen") or "", reverse=True)[:campaigns]
    techniques = attack.get("techniques", {})
    found: Dict[str, dict] = {}
    for campaign in chosen:
        for tid in campaign["techniques"]:
            info = techniques.get(tid)
            if not info or platform not in info.get("platforms", []):
                continue
            slot = found.setdefault(tid, {"technique": tid, "name": info["name"], "tactics": info["tactics"], "campaigns": []})
            slot["campaigns"].append(campaign["name"])
    return sorted(found.values(), key=lambda t: (-len(t["campaigns"]), t["technique"]))


def new_kev(entries: List[dict], since: datetime) -> List[dict]:
    cutoff = since.date().isoformat()
    return sorted([e for e in entries if e["added"] >= cutoff], key=lambda e: e["added"], reverse=True)


# ── network + cache ──────────────────────────────────────────────────────────────

async def download(source: str, client: Optional[httpx.AsyncClient] = None) -> bytes:
    """GET one allow-listed feed, refusing anything bigger than its cap."""
    url, cap = FEEDS[source], MAX_BYTES[source]
    own = client is None
    client = client or httpx.AsyncClient(timeout=90.0, follow_redirects=True, headers={"User-Agent": USER_AGENT})
    try:
        async with client.stream("GET", url) as response:
            response.raise_for_status()
            if source == "attack":                       # too large to hold twice in memory: spool to disk
                with tempfile.TemporaryFile() as spool:
                    size = 0
                    async for chunk in response.aiter_bytes():
                        size += len(chunk)
                        if size > cap:
                            raise ValueError(f"{source} feed larger than {cap} bytes")
                        spool.write(chunk)
                    spool.seek(0)
                    return spool.read()
            data = bytearray()
            async for chunk in response.aiter_bytes():
                data.extend(chunk)
                if len(data) > cap:
                    raise ValueError(f"{source} feed larger than {cap} bytes")
            return bytes(data)
    finally:
        if own:
            await client.aclose()


async def get_feed(db: AsyncSession, source: str, now: Optional[datetime] = None,
                   client: Optional[httpx.AsyncClient] = None) -> Tuple[Optional[dict], dict]:
    """The feed's parsed payload and a status record: ok (fresh), cached (still fresh enough), stale (fetch failed, old copy), unavailable."""
    now = now or datetime.now(timezone.utc)
    row = await db.get(IntelCache, source)
    age = (now - row.fetched_at) if row else None
    meta = {"source": source, "fetched_at": row.fetched_at.isoformat() if row else None, "status": "unavailable", "error": None}
    if row and age < MAX_AGE[source]:
        meta["status"] = "cached"
        return row.payload, meta
    try:
        raw = await download(source, client)
        payload = PARSERS[source](raw)
    except Exception as e:
        meta["error"] = f"{type(e).__name__}: {str(e)[:150]}"
        if row:
            meta["status"] = "stale"
            return row.payload, meta
        return None, meta
    if row:
        row.payload, row.fetched_at = payload, now
    else:
        db.add(IntelCache(source=source, payload=payload, fetched_at=now))
    await db.flush()
    meta.update(status="ok", fetched_at=now.isoformat())
    return payload, meta


async def epss_scores(cves: List[str], client: Optional[httpx.AsyncClient] = None) -> Dict[str, float]:
    """Exploit-probability score per CVE (0-1). Any failure just means no enrichment."""
    scores: Dict[str, float] = {}
    own = client is None
    client = client or httpx.AsyncClient(timeout=30.0, headers={"User-Agent": USER_AGENT})
    try:
        for i in range(0, len(cves), 50):
            batch = [c for c in cves[i:i + 50] if re.fullmatch(r"CVE-\d{4}-\d{4,}", c)]
            if not batch:
                continue
            response = await client.get(EPSS_URL, params={"cve": ",".join(batch)})
            response.raise_for_status()
            for row in response.json().get("data", []):
                scores[row["cve"]] = float(row["epss"])
    except Exception:
        pass
    finally:
        if own:
            await client.aclose()
    return scores
