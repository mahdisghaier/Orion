"""LangGraph nodes — each is a step in the agent's state machine."""
import json
import yaml
from typing import Dict, Any, List

from .state import ChatState
from .llm import get_llm, llm_call_with_audit, extract_yaml_from_response


# [explain] Step 1: ask the AI to restate, in one short sentence, what the analyst wants to hunt for.
async def understand_intent(state: ChatState) -> ChatState:
    """Parse what the analyst wants from their natural language message."""
    user_message = state["user_message"]
    llm = get_llm()
    system_prompt = "You are ORION, a threat hunting assistant for SOC analysts. Your job is to understand what the analyst wants to hunt for. Respond in JSON format: {\"intent\": \"<brief description>\", \"hunting_type\": \"detection\" or \"investigation\", \"suggested_targets\": [\"what to look for\"]}"
    prompt = 'Analyst message: "' + user_message + '". What is the analyst trying to do? Extract the intent concisely.'
    response, audit = llm_call_with_audit(llm, prompt, system_prompt, "understand_intent")
    try:
        clean = response.strip()
        if clean.startswith("```"):
            clean = clean.split("```")[1]
            if clean.startswith("json"):
                clean = clean[4:]
        parsed = json.loads(clean)
    except json.JSONDecodeError:
        parsed = {"intent": user_message, "hunting_type": "detection", "suggested_targets": [user_message]}
    state["intent"] = parsed.get("intent", user_message)
    state["llm_audit_entries"] = state.get("llm_audit_entries", []) + [audit]
    state["chat_history"] = state.get("chat_history", []) + [{"role": "assistant", "content": "Understood. You want to hunt for: " + state['intent'] + ". Let me generate a Sigma rule for this."}]
    return state


# [explain] Step 2: ask the AI to write a Sigma rule for that. It is told to keep it broad (match on the program name only).
# [explain] If the answer is not valid YAML, a safe fallback rule is used. Then it stops and waits for the analyst.
async def generate_sigma(state: ChatState) -> ChatState:
    """Generate a Sigma rule YAML based on the analyst's intent."""
    intent = state["intent"]
    llm = get_llm()
    system_prompt = "You are a Sigma rule expert. Generate BROAD rules that match on process NAME or BINARY PATH only. Do NOT add CommandLine conditions. Use a single selection with condition: selection. For Linux logs use logsource product: linux, category: process_creation. Include MITRE tags. Output ONLY the YAML in a yaml code block. Example: match Image|endswith with values like /nc /ncat /netcat and use condition: selection."
    prompt = 'Generate a Sigma rule for this hunting intent: "' + intent + '". The rule should be BROAD. Output the YAML only in a yaml code block.'
    response, audit = llm_call_with_audit(llm, prompt, system_prompt, "generate_sigma")
    sigma_yaml = extract_yaml_from_response(response)
    try:
        parsed = yaml.safe_load(sigma_yaml)
        if not isinstance(parsed, dict) or "title" not in parsed:
            raise ValueError("Missing title")
    except Exception:
        sigma_yaml = "title: Generated Hunt Rule\nlogsource:\n  product: linux\n  category: process_creation\ndetection:\n  selection:\n    CommandLine|contains: " + intent[:50] + "\n  condition: selection\ntags:\n  - attack.t1059\n"
    state["sigma_rule"] = sigma_yaml
    state["needs_confirmation"] = True
    state["confirmed"] = None
    state["llm_audit_entries"] = state.get("llm_audit_entries", []) + [audit]
    state["chat_history"] = state.get("chat_history", []) + [{"role": "assistant", "content": "I generated this Sigma rule:\n\n```yaml\n" + sigma_yaml + "\n```\n\nShall I run this hunt? (Yes / No)"}]
    return state


# [explain] Step 3 (only after the analyst said yes): run the search through HuntRunner and keep the top findings, without the suppressed ones.
async def run_hunt(state: ChatState) -> ChatState:
    """Execute the hunt using the HuntRunner service."""
    from app.services.hunt_runner import HuntRunner
    from app.core.database import async_session
    sigma_rule = state.get("sigma_rule")
    siem_targets = state.get("siem_targets", [])
    user_id = state["user_id"]
    if not sigma_rule or not siem_targets:
        state["error"] = "Missing Sigma rule or SIEM targets"
        state["hunt_status"] = "failed"
        return state
    try:
        async with async_session() as db:
            runner = HuntRunner(db)
            from uuid import UUID
            target_uuids = [UUID(t) if isinstance(t, str) else t for t in siem_targets]
            hunt = await runner.create_and_run(created_by=UUID(user_id), siem_targets=target_uuids, rule_yaml=sigma_rule)
            state["hunt_id"] = str(hunt.id)
            state["hunt_status"] = hunt.status
            state["total_hits"] = hunt.total_hits
            from sqlalchemy import select
            from app.models import HuntResult
            result = await db.execute(select(HuntResult).where(HuntResult.hunt_id == hunt.id, HuntResult.suppression_id.is_(None)).order_by(HuntResult.priority_score.desc().nulls_last(), HuntResult.event_time.desc()).limit(50))
            findings = result.scalars().all()
            state["findings"] = [{"id": str(f.id), "process_name": f.process_name, "process_command_line": f.process_command_line, "host_name": f.host_name, "user_name": f.user_name, "event_time": f.event_time.isoformat() if f.event_time else None, "mitre_techniques": f.mitre_techniques, "siem_type": f.siem_type, "priority_score": f.priority_score, "priority_breakdown": f.priority_breakdown} for f in findings]
            state["chat_history"] = state.get("chat_history", []) + [{"role": "assistant", "content": "Hunt complete. Status: " + str(hunt.status) + ". Found " + str(hunt.total_hits) + " matching event(s)."}]
    except Exception as e:
        state["error"] = str(e)
        state["hunt_status"] = "failed"
        state["chat_history"] = state.get("chat_history", []) + [{"role": "assistant", "content": "Hunt failed: " + str(e)}]
    return state


# [explain] Step 4: ask the AI to explain the findings in plain words, using the priority score and its reasons.
# [explain] The AI may explain the ranking but must never change it.
async def explain_findings(state: ChatState) -> ChatState:
    """Analyze the findings + explain them to the analyst."""
    findings = state.get("findings", [])
    intent = state.get("intent", "")
    if not findings:
        state["explanation"] = "No findings to explain - the hunt returned 0 results. Consider broadening the search criteria."
        state["follow_up_suggestions"] = ["Try a broader Sigma rule that matches on process name only", "Check if the activity occurred on a different host", "Verify the SIEM connection is receiving the right data"]
        return state
    llm = get_llm()
    system_prompt = "You are a threat hunting expert explaining findings to a SOC analyst. Analyze the findings and explain what was found in plain English, state why it is suspicious, reference MITRE techniques, and suggest 2-3 follow-up queries. Keep it concise with bullet points. Each finding carries a priority score (0-100) computed by ORION from its evidence, with the reasons listed. Explain that ranking in plain words using ONLY those reasons. Never compute, change, dispute or invent a score or a ranking."
    findings_summary = "\n".join(["- " + str(i+1) + ". Process: " + str(f.get('process_name', 'unknown')) + ", Cmd: " + str(f.get('process_command_line', 'N/A')) + ", Host: " + str(f.get('host_name', 'unknown')) + ", User: " + str(f.get('user_name', 'unknown')) + ", MITRE: " + str(f.get('mitre_techniques', [])) + ", Priority: " + str(f.get('priority_score')) + " (" + "; ".join(str(b['points']) + " " + b['factor'] + ": " + b['detail'] for b in (f.get('priority_breakdown') or [])) + ")" for i, f in enumerate(findings[:10])])
    prompt = "Original analyst intent: " + intent + "\n\nHunt returned " + str(len(findings)) + " finding(s):\n\n" + findings_summary + "\n\nExplain what was found and suggest follow-up queries."
    response, audit = llm_call_with_audit(llm, prompt, system_prompt, "explain_findings")
    state["explanation"] = response
    state["llm_audit_entries"] = state.get("llm_audit_entries", []) + [audit]
    state["chat_history"] = state.get("chat_history", []) + [{"role": "assistant", "content": response}]
    suggestions = []
    if any("nc" in (f.get("process_name") or "").lower() for f in findings):
        suggestions.append("Check what process spawned nc (parent process)")
        suggestions.append("Check if nc made any outbound connections")
    if any(f.get("mitre_techniques") for f in findings):
        suggestions.append("Hunt for related MITRE techniques on the same host")
    if not suggestions:
        suggestions.append("Check if these processes appear on other hosts")
        suggestions.append("Look for unusual network connections from these hosts")
    state["follow_up_suggestions"] = suggestions
    return state
