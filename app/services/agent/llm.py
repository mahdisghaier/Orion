"""LLM client + audit logging helper for the agent."""
import json
from datetime import datetime
from typing import Optional, Dict, Any

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage

from app.core.config import settings


def get_llm() -> ChatGoogleGenerativeAI:
    """Get a configured Gemini LLM client."""
    return ChatGoogleGenerativeAI(
        model=settings.GEMINI_MODEL,
        google_api_key=settings.GEMINI_API_KEY,
        temperature=0.3,  # low for predictable Sigma rule generation
    )


def llm_call_with_audit(
    llm: ChatGoogleGenerativeAI,
    prompt: str,
    system_prompt: str = "",
    context_name: str = "unnamed_call",
) -> tuple[str, Dict[str, Any]]:
    """Call the LLM + return audit entry for hallucination mitigation.
    
    Returns:
        (response_text, audit_entry)
        audit_entry is appended to state.llm_audit_entries by the calling node.
    """
    started_at = datetime.utcnow()
    
    messages = []
    if system_prompt:
        messages.append(SystemMessage(content=system_prompt))
    messages.append(HumanMessage(content=prompt))
    
    response = llm.invoke(messages)
    response_text = response.content
    
    audit_entry = {
        "context": context_name,
        "prompt": prompt,
        "system_prompt": system_prompt,
        "response": response_text,
        "model": settings.GEMINI_MODEL,
        "provider": "google",
        "latency_ms": int((datetime.utcnow() - started_at).total_seconds() * 1000),
        "timestamp": started_at.isoformat(),
    }
    
    return response_text, audit_entry


def extract_yaml_from_response(text: str) -> str:
    """Extract YAML from an LLM response that may contain markdown code blocks."""
    # Common patterns:
    # ```yaml\n...\n```
    # ```yaml\n...\n```  
    # plain YAML
    
    if "```yaml" in text:
        # Extract content between ```yaml and ```
        start = text.find("```yaml") + 7
        end = text.find("```", start)
        if end > start:
            return text[start:end].strip()
    
    if "```" in text:
        # Extract content between first ``` and next ```
        start = text.find("```") + 3
        # Skip language identifier on first line if present
        if text[start:start+4].lower() in ["yaml", "yml"]:
            start = text.find("\n", start) + 1
        end = text.find("```", start)
        if end > start:
            return text[start:end].strip()
    
    # No code block — return as-is
    return text.strip()
