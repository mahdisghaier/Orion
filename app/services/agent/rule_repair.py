"""Making a generated Sigma rule work before the analyst is asked to approve it.

A language model often writes a rule that is almost right: a date written 2024/05/22 instead of 2024-05-22, an `id`
that is not a UUID, an unknown status, a missing condition. A rule that cannot be compiled is useless to the analyst, so
the assistant checks every rule it proposes. It first fixes what it can fix with plain code, then (twice at most) asks the
model to correct the rule given the exact error, and as a last resort offers the closest rule of the library, saying so.
The platform stays in charge: the analyst still approves the rule that finally comes out.
"""
import re
import uuid
from datetime import datetime
from typing import Callable, List, Optional, Tuple

import yaml

from app.services.sigma_engine import convert_sigma_rule

STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
_DATE_SEPARATORS = re.compile(r"[/.]")


def _fixed_date(value) -> Optional[str]:
    text = str(value).strip()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%d/%m/%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


def normalise_rule(rule_yaml: str) -> Tuple[str, List[str]]:
    """Fix the usual slips with plain code. Returns the rule and a plain-words list of what was changed."""
    try:
        rule = yaml.safe_load(rule_yaml)
    except yaml.YAMLError as e:
        raise ValueError(f"the text is not valid YAML ({str(e).splitlines()[0]})")
    if not isinstance(rule, dict):
        raise ValueError("the text is not a Sigma rule (a YAML mapping was expected)")
    changes: List[str] = []

    for key in ("date", "modified"):
        if key in rule:
            fixed = _fixed_date(rule[key])
            if fixed is None:
                del rule[key]
                changes.append(f"removed the unreadable {key} '{rule.get(key, '')}'".replace("''", "'"))
            elif fixed != str(rule[key]):
                changes.append(f"wrote the {key} {rule[key]} as {fixed}")
                rule[key] = fixed
    if "id" in rule:
        try:
            uuid.UUID(str(rule["id"]))
        except ValueError:
            del rule["id"]
            changes.append("removed an identifier that was not a UUID")
    if "status" in rule and str(rule["status"]).lower() not in STATUSES:
        rule["status"] = "experimental"
        changes.append("set the status to experimental")
    if "level" in rule and str(rule["level"]).lower() not in LEVELS:
        del rule["level"]
        changes.append("removed an unknown level")
    if not isinstance(rule.get("logsource"), dict):
        rule["logsource"] = {"product": "linux", "category": "process_creation"}
        changes.append("added the Linux process_creation log source")
    detection = rule.get("detection")
    if isinstance(detection, dict) and "condition" not in detection:
        names = [k for k in detection if k != "timeframe"]
        if len(names) == 1:
            detection["condition"] = names[0]
            changes.append(f"added the condition '{names[0]}'")
    if isinstance(rule.get("tags"), list):
        rule["tags"] = [str(t).strip() for t in rule["tags"] if str(t).strip()]
    return yaml.safe_dump(rule, sort_keys=False, allow_unicode=True), changes


def compile_error(rule_yaml: str) -> Optional[str]:
    """None when the rule compiles for at least one SIEM, otherwise why it does not."""
    result = convert_sigma_rule(rule_yaml)
    if result.get("eql") or result.get("lucene"):
        return None
    errors = [result.get(k) for k in ("eql_error", "lucene_error", "kql_error") if result.get(k)]
    return (errors[0] if errors else "the rule could not be compiled")[:300]


def library_match(intent: str, rule_yaml: Optional[str] = None) -> Optional[dict]:
    """The rule of the ORION library closest to what the analyst asked: same technique tag, else most shared words."""
    from app.services.threat_intel.rules import library, technique_of
    rules = library()
    if rule_yaml:
        try:
            wanted = technique_of(rule_yaml)
        except Exception:
            wanted = None
        if wanted:
            for r in rules:
                if r["technique"] == wanted or (r["technique"] or "").startswith(wanted.split(".")[0]):
                    return r
    words = {w for w in re.findall(r"[a-z0-9]{4,}", intent.lower())}
    scored = sorted(rules, key=lambda r: -len(words & set(re.findall(r"[a-z0-9]{4,}", (r["title"] + " " + (r["technique"] or "")).lower()))))
    best = scored[0] if scored else None
    return best if best and words & set(re.findall(r"[a-z0-9]{4,}", best["title"].lower())) else None


REPAIR_SYSTEM = ("You repair Sigma rules. You receive a rule and the exact error the compiler gave. Return ONLY the corrected rule "
                 "in a yaml code block. Keep its meaning. Dates are written yyyy-mm-dd, an id is a UUID or absent, the "
                 "logsource is product: linux, category: process_creation, and the detection has a condition.")


def ensure_valid_rule(rule_yaml: str, intent: str, ask_model: Optional[Callable[[str, str], str]] = None,
                      attempts: int = 2) -> Tuple[str, List[str], bool]:
    """Return (rule, notes, from_library). The rule always compiles when a library rule had to be used; otherwise the
    notes say what was corrected. `ask_model(prompt, system)` returns the model's text and may raise."""
    from app.services.agent.llm import extract_yaml_from_response
    notes: List[str] = []
    current = rule_yaml
    error: Optional[str] = None
    for attempt in range(attempts + 1):
        try:
            current, changes = normalise_rule(current)
            notes += changes
            error = compile_error(current)
        except ValueError as e:
            error = str(e)
        if error is None:
            return current, notes, False
        if attempt == attempts or ask_model is None:
            break
        try:
            reply = ask_model(f"Rule:\n```yaml\n{current}\n```\nCompiler error: {error}\nReturn the corrected rule.", REPAIR_SYSTEM)
            current = extract_yaml_from_response(reply)
            notes.append(f"asked the model to correct it ({error[:90]})")
        except Exception:
            break
    match = library_match(intent, rule_yaml)
    if match:
        notes.append(f"the generated rule could not be compiled ({(error or '')[:120]}), so I use the closest rule of the library, "
                     f"'{match['title']}' ({match['technique']})")
        return match["yaml"], notes, True
    raise ValueError(error or "the rule could not be made to work")
