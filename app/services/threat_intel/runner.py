"""The threat-intelligence check: what the news says attackers are doing, tested against what ORION can see.

One run, in order:
  1. refresh each connected SIEM's data profile, so "what can this SIEM see" is current
  2. read the feeds (exploited CVEs, current campaigns, malicious addresses and domains)
  3. threat-informed hunt: for the techniques of recent campaigns that apply to Linux, run ORION's rule for each one on every
     SIEM where it can really run, and list the techniques it has no rule or no data for
  4. indicator sweep: look for the feed's addresses and domains (and the analyst's own indicators) in the events of the window,
     but only on SIEMs whose events carry those fields
  5. exposure: do any CVEs on the exploited list show up in the vulnerability data a SIEM holds
  6. a verdict: findings, clear (within scope) or incomplete, always with the list of what could not be checked

"Clear" is only ever reported together with its limits. A SIEM without network fields cannot clear an address sweep, a technique
without a rule cannot be cleared by a hunt, and an unreachable feed makes the run incomplete rather than clean.
"""
import ipaddress
from functools import partial
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Awaitable, Callable, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import JobRun, Notification, ScheduledJob, SIEMConnection, SIEMProfile, User
from app.services.connectors.factory import ConnectorError, get_connector
from app.services.threat_intel import feeds, iocs
from app.services.threat_intel.coverage import rule_status
from app.services.threat_intel.rules import rules_for, title_of

DEFAULT_CONFIG = {"campaigns": 8, "max_techniques": 30, "platform": "Linux", "kev_days": 7, "custom_iocs": {}}
MAX_MATCHES_SHOWN = 25


@dataclass
class Deps:
    """Everything a run reaches outside itself for. Tests replace these; None means the real implementation."""
    load_feed: Callable[[AsyncSession, str], Awaitable[tuple]] = feeds.get_feed
    epss: Callable[[List[str]], Awaitable[Dict[str, float]]] = feeds.epss_scores
    connector: Callable[[SIEMConnection], object] = get_connector
    hunt: Optional[Callable[..., Awaitable[object]]] = None             # (db, created_by, siem_ids, rule_yaml, time_range) -> hunt
    connections: Optional[Callable[[AsyncSession], Awaitable[list]]] = None   # (db) -> [Live]
    admin_id: Optional[Callable[[AsyncSession], Awaitable[object]]] = None    # (db) -> user id to own the hunts
    top_findings: Optional[Callable[[AsyncSession, object], Awaitable[list]]] = None
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


@dataclass
class Live:
    id: object
    name: str
    type: str
    connector: object
    profile: Optional[dict]
    error: Optional[str] = None


async def _default_hunt(db: AsyncSession, created_by, siem_ids, rule_yaml: str, time_range: dict, client_id=None):
    from app.services.hunt_runner import HuntRunner
    return await HuntRunner(db).create_and_run(created_by=created_by, siem_targets=siem_ids, rule_yaml=rule_yaml, time_range=time_range, client_id=client_id)


def clean_custom_iocs(raw: dict) -> Dict[str, List[str]]:
    """The analyst's own indicators, validated. Private addresses are allowed here (an internal host can be the indicator)."""
    out: Dict[str, List[str]] = {"ip": [], "domain": [], "sha256": []}
    for value in (raw or {}).get("ip", []):
        try:
            if not ipaddress.ip_address(str(value).strip()).is_unspecified:
                out["ip"].append(str(value).strip())
        except ValueError:
            continue
    out["domain"] = [str(v).strip().lower() for v in (raw or {}).get("domain", []) if feeds.valid_domain(str(v))]
    out["sha256"] = [str(v).strip().lower() for v in (raw or {}).get("sha256", []) if feeds.valid_sha256(str(v))]
    return {k: sorted(set(v))[:feeds.MAX_IOCS_PER_KIND] for k, v in out.items()}


# ── the verdict (pure) ───────────────────────────────────────────────────────────

def decide(summary: dict) -> tuple:
    """(status, headline, limits) from a finished summary. Pure, so it can be tested without any network or SIEM."""
    hunts = summary["technique_hunts"]
    matches = summary["ioc"]["matches"]
    exposure = summary["kev"]["exposure"]["matches"]
    hits = [h for h in hunts["executed"] if h["findings"] > 0]

    limits: List[str] = []
    for name, meta in summary["feeds"].items():
        if meta["status"] == "unavailable":
            limits.append(f"the {name} feed could not be read ({meta.get('error') or 'unreachable'})")
        elif meta["status"] == "stale":
            limits.append(f"the {name} feed could not be refreshed; the copy from {meta['fetched_at'][:10]} was used")
    for c in summary["connections"]:
        if c.get("error"):
            limits.append(f"{c['name']}: {c['error']}")
    if hunts["no_rule"]:
        limits.append(f"{len(hunts['no_rule'])} of {hunts['campaign_techniques']} campaign techniques have no ORION rule")
    for kind in iocs.KINDS:
        if summary["ioc"]["counts"].get(kind) and not any(c["kind"] == kind and c["status"] == "checkable" for c in summary["ioc"]["checks"]):
            limits.append(f"{summary['ioc']['counts'][kind]} {kind} indicator(s) could not be checked on any SIEM (no data carries them)")
    if summary["kev"]["exposure"]["status"] != "checked":
        limits.append(f"CVE exposure not checked: {summary['kev']['exposure']['reason']}")
    for item in hunts["blind"][:6]:
        limits.append(f"{item['technique']} cannot run on {item['connection']}: {item['reasons'][0]}")

    required_feeds_down = any(summary["feeds"].get(n, {}).get("status") == "unavailable" for n in ("kev", "attack"))
    no_siem = not any(c["live"] for c in summary["connections"])

    if hits or matches or exposure:
        parts = []
        if hits:
            parts.append(f"{sum(h['findings'] for h in hits)} hit(s) on {len(hits)} technique rule(s) used by recent campaigns")
        if matches:
            parts.append(f"{len(matches)} indicator match(es)")
        if exposure:
            parts.append(f"{len(exposure)} host(s) exposed to actively exploited CVEs")
        return "findings", "; ".join(parts), limits
    if required_feeds_down or no_siem:
        why = "no SIEM could be reached" if no_siem else "a required feed was unavailable"
        return "incomplete", f"Incomplete: {why}. Nothing can be concluded.", limits
    checked = len([h for h in hunts["executed"]])
    swept = sum(summary["ioc"]["counts"].get(k, 0) for k in iocs.KINDS
                if any(c["kind"] == k and c["status"] == "checkable" for c in summary["ioc"]["checks"]))
    return "clear", f"Nothing found within scope: {checked} technique rule(s) run, {swept} indicator(s) swept.", limits


# ── phases ───────────────────────────────────────────────────────────────────────

async def _prepare_connections(db: AsyncSession, deps: Deps, client_id=None) -> List[Live]:
    live: List[Live] = []
    query = select(SIEMConnection).where(SIEMConnection.is_active.is_(True))
    if client_id is not None:
        query = query.where(SIEMConnection.client_id == client_id)      # a client's job only reads that client's SIEMs
    rows = (await db.execute(query.order_by(SIEMConnection.created_at))).scalars().all()
    for conn in rows:
        item = Live(conn.id, conn.name, conn.type, None, None)
        try:
            item.connector = deps.connector(conn)
            profile = await item.connector.profile(7)
            row = (await db.execute(select(SIEMProfile).where(SIEMProfile.siem_connection_id == conn.id))).scalar_one_or_none()
            if row is None:
                row = SIEMProfile(siem_connection_id=conn.id)
                db.add(row)
            row.profile, row.collected_at = profile, func.now()
            item.profile = profile
        except (ConnectorError, NotImplementedError) as e:
            item.error = f"not usable: {e}"
        except Exception as e:
            item.error = f"unreachable ({type(e).__name__})"
        live.append(item)
    await db.flush()
    return live


async def _technique_hunts(db, deps: Deps, job: ScheduledJob, cfg: dict, attack: Optional[dict], live: List[Live], since: datetime, admin_id) -> dict:
    out = {"campaign_techniques": 0, "with_rule": 0, "executed": [], "no_rule": [], "blind": []}
    if not attack:
        return out
    techniques = feeds.recent_campaign_techniques(attack, cfg["platform"], cfg["campaigns"])[:cfg["max_techniques"]]
    out["campaign_techniques"] = len(techniques)
    hunted: Dict[str, dict] = {}                               # one hunt per rule, however many techniques share it
    for tech in techniques:
        rules = rules_for(tech["technique"])
        if not rules:
            out["no_rule"].append({"technique": tech["technique"], "name": tech["name"], "campaigns": tech["campaigns"][:3]})
            continue
        out["with_rule"] += 1
        for rule in rules:
            runnable = []
            for conn in live:
                if conn.error:
                    continue
                status, reasons = rule_status(rule["yaml"], conn.type, conn.profile)
                if status == "runnable":
                    runnable.append(conn)
                elif status in ("blind", "not_runnable", "unknown"):
                    out["blind"].append({"technique": tech["technique"], "rule": rule["title"], "connection": conn.name, "status": status, "reasons": reasons})
            record = hunted.get(rule["title"])
            if record is None:
                record = {"technique": tech["technique"], "name": tech["name"], "campaigns": tech["campaigns"][:3], "rule": rule["title"],
                          "siems": [c.name for c in runnable], "hunt_id": None, "findings": 0, "top": [], "error": None}
                hunted[rule["title"]] = record
                out["executed"].append(record)
                if runnable:
                    try:
                        hunt = await (deps.hunt or partial(_default_hunt, client_id=getattr(job, "client_id", None)))(db, admin_id, [c.id for c in runnable], rule["yaml"], {"from": since.isoformat().replace("+00:00", "Z")})
                        record["hunt_id"] = str(hunt.id)
                        record["findings"] = hunt.total_hits
                        record["top"] = await (deps.top_findings or _top_findings)(db, hunt)
                        if hunt.error:
                            record["error"] = hunt.error[:200]
                    except Exception as e:
                        record["error"] = f"{type(e).__name__}: {str(e)[:150]}"
    out["executed"] = [r for r in out["executed"] if r["siems"]]      # rules nobody could run are in "blind", not "executed"
    return out


async def _first_admin(db: AsyncSession):
    return (await db.execute(select(User.id).where(User.role == "admin", User.is_active.is_(True)).limit(1))).scalar_one_or_none()


async def _top_findings(db: AsyncSession, hunt) -> List[dict]:
    from app.models import HuntResult
    rows = (await db.execute(
        select(HuntResult).where(HuntResult.hunt_id == hunt.id)
        .order_by(HuntResult.priority_score.desc().nulls_last()).limit(3)
    )).scalars().all()
    return [{"id": str(r.id), "siem": r.siem_type, "host": r.host_name, "process": r.process_name, "priority": r.priority_score} for r in rows]


async def _ioc_sweep(deps: Deps, cfg: dict, feed_data: Dict[str, Optional[dict]], live: List[Live], since: datetime, now: datetime) -> dict:
    lists: Dict[str, set] = {"ip": set(), "domain": set(), "sha256": set()}
    if feed_data.get("feodo"):
        lists["ip"].update(e["ip"] for e in feed_data["feodo"]["entries"])
    if feed_data.get("urlhaus"):
        lists["ip"].update(feed_data["urlhaus"]["ips"])
        lists["domain"].update(feed_data["urlhaus"]["domains"])
    custom = clean_custom_iocs(cfg.get("custom_iocs", {}))
    for kind, values in custom.items():
        lists[kind].update(values)
    out = {"counts": {k: len(v) for k, v in lists.items()}, "custom": {k: len(v) for k, v in custom.items()}, "checks": [], "matches": []}
    for kind in iocs.KINDS:
        if not lists[kind]:
            continue
        wanted = {v.lower() for v in lists[kind]}
        values = sorted(lists[kind])
        for conn in live:
            if conn.error:
                continue
            status, fields, reasons = iocs.check_status(kind, conn.type, conn.profile)
            check = {"kind": kind, "connection": conn.name, "status": status, "fields": fields, "reasons": reasons, "matches": 0}
            if status == "checkable":
                try:
                    for i in range(0, len(values), 1000):
                        events = await conn.connector.match_iocs(kind, values[i:i + 1000], since, now)
                        for event in events:
                            for hit in iocs.matched_indicators(event, kind, wanted):
                                check["matches"] += 1
                                if len(out["matches"]) < MAX_MATCHES_SHOWN:
                                    host = (event.get("host") or {}).get("name")
                                    out["matches"].append({"kind": kind, "indicator": hit, "connection": conn.name, "host": host,
                                                           "time": event.get("@timestamp")})
                except Exception as e:
                    check["status"], check["reasons"] = "error", [f"{type(e).__name__}: {str(e)[:120]}"]
            out["checks"].append(check)
    return out


async def _kev_watch(deps: Deps, kev: Optional[dict], live: List[Live], since: datetime) -> dict:
    out = {"total": 0, "new": [], "exposure": {"status": "not_checked", "reason": "the exploited-vulnerability list was unavailable", "matches": []}}
    if not kev:
        return out
    entries = kev["entries"]
    out["total"] = len(entries)
    new = feeds.new_kev(entries, since)[:30]
    scores = await deps.epss([e["cve"] for e in new]) if new else {}
    out["new"] = [{**e, "epss": scores.get(e["cve"])} for e in new]

    out["exposure"]["reason"] = "no connected SIEM holds vulnerability data"
    cves = [e["cve"] for e in entries]
    for conn in live:
        if conn.error or conn.type != "wazuh" or not hasattr(conn.connector, "find_vulnerabilities"):
            continue
        try:
            if await conn.connector.vulnerability_records() == 0:
                out["exposure"]["reason"] = f"{conn.name} holds no vulnerability records yet (its vulnerability detector has produced nothing)"
                continue
            found = await conn.connector.find_vulnerabilities(cves)
            out["exposure"].update(status="checked", reason="")
            out["exposure"]["matches"] += [{**f, "connection": conn.name} for f in found]
        except Exception as e:
            out["exposure"]["reason"] = f"{conn.name}: {type(e).__name__}"
    return out


# ── the run ──────────────────────────────────────────────────────────────────────

async def run_job(db: AsyncSession, job: ScheduledJob, trigger: str = "schedule", deps: Optional[Deps] = None) -> JobRun:
    """Execute one threat-intelligence check, record it, notify, and schedule the next one."""
    deps = deps or Deps()
    cfg = {**DEFAULT_CONFIG, **(job.config or {})}
    now = deps.now()
    run = JobRun(job_id=job.id, trigger=trigger, status="running", started_at=now)
    db.add(run)
    await db.flush()
    try:
        since = job.last_run_at or (now - timedelta(days=cfg["kev_days"]))
        since = max(since, now - timedelta(days=14))
        admin_id = job.created_by or await (deps.admin_id or _first_admin)(db)

        live = await (deps.connections or (lambda session: _prepare_connections(session, deps, getattr(job, "client_id", None))))(db)
        feed_data, feed_meta = {}, {}
        for source in feeds.FEEDS:
            payload, meta = await deps.load_feed(db, source)
            feed_data[source], feed_meta[source] = payload, meta

        usable = [c for c in live if not c.error and c.profile and c.profile.get("recent_docs")]      # archives say nothing about now
        hunts = await _technique_hunts(db, deps, job, cfg, feed_data.get("attack"), usable, since, admin_id) if admin_id else \
            {"campaign_techniques": 0, "with_rule": 0, "executed": [], "no_rule": [], "blind": []}
        sweep = await _ioc_sweep(deps, cfg, feed_data, usable, since, now)
        kev = await _kev_watch(deps, feed_data.get("kev"), usable, since)

        summary = {
            "window": {"from": since.isoformat(), "to": now.isoformat()},
            "feeds": {n: {**m, "items": _feed_size(n, feed_data.get(n))} for n, m in feed_meta.items()},
            "connections": [{"name": c.name, "type": c.type, "live": c in usable, "error": c.error,
                             "recent_events": (c.profile or {}).get("recent_docs")} for c in live],
            "technique_hunts": hunts, "ioc": sweep, "kev": kev,
        }
        status, headline, limits = decide(summary)
        summary.update(verdict=status, headline=headline, limits=limits)
        run.status, run.summary = status, summary
    except Exception as e:                                  # a broken run must be visible, never silent
        run.status, run.error = "error", f"{type(e).__name__}: {str(e)[:300]}"
        run.summary = {"verdict": "error", "headline": f"The check failed: {run.error}", "limits": []}
    run.finished_at = deps.now()
    job.last_run_at = now
    job.next_run_at = now + timedelta(hours=job.interval_hours)
    db.add(_notification(run, job))
    await db.commit()
    return run


def _feed_size(name: str, payload: Optional[dict]) -> Optional[int]:
    if not payload:
        return None
    return {"kev": lambda p: len(p["entries"]), "attack": lambda p: len(p["campaigns"]), "feodo": lambda p: len(p["entries"]),
            "urlhaus": lambda p: len(p["ips"]) + len(p["domains"])}[name](payload)


def _notification(run: JobRun, job: ScheduledJob) -> Notification:
    summary = run.summary or {}
    severity = {"findings": "critical", "clear": "info", "incomplete": "warning", "error": "warning"}[run.status]
    title = {"findings": "Threat-intel check: possible match", "clear": "Threat-intel check: nothing found (within scope)",
             "incomplete": "Threat-intel check: incomplete", "error": "Threat-intel check failed"}[run.status]
    limits = summary.get("limits") or []
    body = summary.get("headline", "")
    if limits:
        body += "\nNot checked: " + "; ".join(limits[:4]) + ("; ..." if len(limits) > 4 else "")
    return Notification(client_id=getattr(job, "client_id", None), kind="threat_intel", title=title, body=body[:2000], severity=severity, run_id=run.id)
