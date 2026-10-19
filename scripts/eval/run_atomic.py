"""Replay tests of the Atomic Red Team project on the lab VM and check which ORION rules find them.

The atomics are written by a third party (Red Canary), so this checks the rules against attack commands that I did
not choose. Each test runs on the monitored host through SSH, one after the other, inside its own time window. A test
counts as detected on a SIEM when a rule of the ORION library for that technique returns an event of the monitored host
whose time falls inside the window of the test. The atomics are fetched from the public repository when the script
runs. Only Linux tests that need no installed dependency are replayed, and tests that would damage the lab (clearing
system logs, stopping the audit service) are left out.

    ORION_EVAL_SSH="soc@127.0.0.1|2222|C:\\Users\\me\\.ssh\\key" python scripts/eval/run_atomic.py --host orion-lab
"""
import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "eval"))

from run_evaluation import live_connectors  # noqa: E402
from app.services.data_profile import blind_spots  # noqa: E402
from app.services.ecs import extract_ecs_fields, get_nested  # noqa: E402
from app.services.sigma_engine import convert_sigma_rule, rule_fields, unmapped_fields  # noqa: E402
from app.services.threat_intel.rules import rules_for  # noqa: E402

RAW = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/{t}/{t}.yaml"

# technique -> names of the atomic tests to replay (matched on the start of the test name)
SELECTION = {
    "T1003.008": ["Access /etc/passwd (Local)", "Access /etc/shadow (Local)"],
    "T1046": ["Port Scan"],
    "T1049": ["System Network Connections Discovery via ss or lsof"],
    "T1053.003": ["Cron - Replace crontab with referenced file", "Cron - Add script to /etc/cron.d folder"],
    "T1059.004": ["Create and Execute Bash Shell Script", "Command-Line Interface", "Command line scripts",
                  "Obfuscated command line scripts", "Shell Creation using awk command"],
    "T1070.003": ["Clear Bash history (rm)", "Clear Bash history (echo)", "Clear Bash history (cat dev/null)",
                  "Clear Bash history (truncate)", "Clear and Disable Bash History Logging"],
    "T1082": ["List OS Information", "Hostname Discovery", "Linux List Kernel Modules"],
    "T1087.001": ["Enumerate all accounts (Local)", "View accounts with UID 0", "Enumerate users and groups"],
    "T1105": ["Linux Download File and Run"],
    "T1136.001": ["Create a user account on a Linux system"],
    "T1140": ["Base64 decoding with shell utilities"],
    "T1548.001": ["Set a SetUID flag on file", "Set a SetGID flag on file", "Do reconnaissance for files that have the setuid bit set"],
}
# an atomic test can show a technique that has its own rule (the base64 test of T1059.004 belongs to T1027.010 as well)
RELATED = {"Obfuscated command line scripts": ["T1027.010"]}
SSH = os.environ.get("ORION_EVAL_SSH", "")
# Seconds around a test during which its events count. Elastic stamps an event with the time it happened. Wazuh stamps an
# alert with the time its manager processed it, some seconds later, so its window is longer. The pause between two tests
# (GAP) is longer than every window, so that no event can be credited to the wrong test.
WINDOW_BEFORE = 2
WINDOW_AFTER = {"elastic": 3, "wazuh": 75}
GAP = 100


def log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def fetch_atomics(technique: str) -> list:
    with urllib.request.urlopen(RAW.format(t=technique), timeout=30) as r:
        doc = yaml.safe_load(r.read().decode())
    return doc.get("atomic_tests", []) if isinstance(doc, dict) else []


def render(command: str, arguments: dict) -> str:
    values = {k: str((v or {}).get("default", "")) for k, v in (arguments or {}).items()}
    return re.sub(r"#\{(\w+)\}", lambda m: values.get(m.group(1), ""), command)


def ssh_run(script: str, sudo: bool, timeout: int) -> str:
    target, port, key = SSH.split("|")
    remote = "sudo -n bash -s" if sudo else "bash -s"
    out = subprocess.run(
        ["/mnt/c/Windows/System32/OpenSSH/ssh.exe", "-T", "-i", key, "-p", port, "-o", "BatchMode=yes",
         "-o", "StrictHostKeyChecking=no", target, remote],
        input=script.replace("\r", ""), capture_output=True, text=True, timeout=timeout)
    return out.stdout


def run_test(test: dict) -> dict:
    sudo = bool(test["executor"].get("elevation_required"))
    body = render(test["executor"]["command"], test.get("input_arguments"))
    cleanup = render(test["executor"].get("cleanup_command") or "", test.get("input_arguments"))
    script = f"date +%s\ntimeout 60 bash -c {json.dumps(body)} >/dev/null 2>&1\ndate +%s\n{cleanup}\n"
    lines = ssh_run(script, sudo, 150).split()
    nums = [int(x) for x in lines if x.isdigit()]
    return {"start": nums[0], "end": nums[1]} if len(nums) >= 2 else {"start": int(time.time()), "end": int(time.time())}


def when(event: dict) -> float:
    return extract_ecs_fields(event)["event_time"].timestamp()


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="orion-lab")
    parser.add_argument("--connections", type=lambda v: v.split(","), default=["Auditbeat", "Wazuh"])
    parser.add_argument("--out", default="atomic")
    parser.add_argument("--rules-file", default="", help="a python file with an earlier version of the rule library (rules_for), to measure what the refinement changed")
    parser.add_argument("--reuse", default="", help="results.json of an earlier run: analyse its time windows again without running the tests")
    args = parser.parse_args()
    if not SSH and not args.reuse:
        sys.exit("set ORION_EVAL_SSH")
    lookup = rules_for
    if args.rules_file:
        import importlib.util
        spec = importlib.util.spec_from_file_location("rules_before", args.rules_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        lookup = module.rules_for

    runs = []
    if args.reuse:
        runs = [{k: v for k, v in r.items() if k != "siems"} for r in json.loads(Path(args.reuse).read_text())]
    for technique, names in ({} if args.reuse else SELECTION).items():
        tests = fetch_atomics(technique)
        for name in names:
            test = next((t for t in tests if t["name"].startswith(name) and "linux" in t["supported_platforms"]), None)
            if test is None:
                log(f"{technique} {name}: not found, skipped")
                continue
            log(f"running {technique} {test['name']}")
            window = run_test(test)
            runs.append({"technique": technique, "name": test["name"], "guid": test.get("auto_generated_guid"), **window})
            time.sleep(GAP)

    if not args.reuse:
        log("waiting for the SIEMs to index the events")
        await asyncio.sleep(150)

    sources = await live_connectors(args.connections)
    first = min(r["start"] for r in runs) - 60
    since = datetime.fromtimestamp(first, timezone.utc).isoformat().replace("+00:00", "Z")
    cache: dict = {}
    for r in runs:
        r["siems"] = {}
        rules = lookup(r["technique"]) + [x for t in RELATED.get(r["name"], []) for x in lookup(t)]
        for siem in sources:
            key = {"elastic": "eql", "wazuh": "lucene"}[siem["type"]]
            if not rules:
                r["siems"][siem["name"]] = {"status": "no rule"}
                continue
            best = {"status": "not detected", "events": 0}
            for rule in rules:
                yaml_text = rule["yaml"]
                reasons = []
                missing = unmapped_fields(yaml_text, siem["type"])
                if missing:
                    reasons.append("no field mapping for " + ", ".join(missing))
                reasons += blind_spots(rule_fields(yaml_text), siem["type"], siem["profile"])
                if reasons:
                    best = best if best["status"] == "detected" else {"status": "not runnable", "events": 0, "why": reasons[:1]}
                    continue
                query = convert_sigma_rule(yaml_text)[key]
                ck = (siem["name"], query)
                if ck not in cache:
                    events = await siem["connector"].run_query(query, max_results=1000, time_range={"from": since})
                    cache[ck] = [e for e in events if str(get_nested(e, "host.name") or "").lower() == args.host.lower()]
                hits = [e for e in cache[ck] if r["start"] - WINDOW_BEFORE <= when(e) <= r["end"] + WINDOW_AFTER[siem["type"]]]
                if hits:
                    best = {"status": "detected", "events": len(hits), "rule": rule["title"]}
                    break
            r["siems"][siem["name"]] = best

    out = ROOT / "docs" / "evaluation" / args.out
    out.mkdir(parents=True, exist_ok=True)
    (out / "results.json").write_text(json.dumps(runs, indent=1))
    names = [s["name"] for s in sources]
    lines = ["# Atomic Red Team replay", "",
             f"Run on {datetime.now().strftime('%Y-%m-%d %H:%M')} on the host {args.host}. "
             "Each atomic test ran alone; a detection counts when a library rule returns an event of the host inside the test window.", "",
             "| Technique | Atomic test | " + " | ".join(names) + " |", "|---|---|" + "---|" * len(names)]
    for r in runs:
        cells = []
        for n in names:
            s = r["siems"][n]
            cells.append(f"{s['status']} ({s['events']})" if s["status"] == "detected" else s["status"])
        lines.append(f"| {r['technique']} | {r['name']} | " + " | ".join(cells) + " |")
    for n in names:
        total = [r for r in runs if r["siems"][n]["status"] != "no rule"]
        det = sum(1 for r in total if r["siems"][n]["status"] == "detected")
        lines.append(f"\n**{n}**: {det} of {len(total)} tests detected.")
    (out / "RESULTS.md").write_text("\n".join(lines) + "\n")
    log(f"written to {out}")


if __name__ == "__main__":
    asyncio.run(main())
