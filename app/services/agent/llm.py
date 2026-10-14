"""LLM client + audit logging helper for the agent."""
import json
import time
from datetime import datetime
from types import SimpleNamespace
from typing import Optional, Dict, Any, Tuple

import httpx

from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.messages import HumanMessage, SystemMessage

from app.core.config import settings


class LLMUnavailable(Exception):
    """The model service refused or could not answer (quota, auth, network, bad reply)."""


class OpenAICompatLLM:
    """Minimal client for any OpenAI-compatible /chat/completions endpoint.

    Exposes the same invoke(messages) -> object with .content as the langchain Gemini client, so the
    chat agent and the investigation planner work with either provider unchanged.
    Fails fast: no retries, a hard timeout. A 429 or any other error raises LLMUnavailable at once.
    """

    def __init__(self, base_url: str, model: str, api_key: Optional[str] = None,
                 temperature: float = 0.3, timeout: float = 45.0, transport=None):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout
        self._transport = transport

    @staticmethod
    def _role(message) -> str:
        return {"system": "system", "human": "user", "ai": "assistant"}.get(getattr(message, "type", "human"), "user")

    def invoke(self, messages):
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [{"role": self._role(m), "content": m.content} for m in messages],
        }
        try:
            with httpx.Client(timeout=self.timeout, transport=self._transport) as client:
                response = client.post(f"{self.base_url}/chat/completions", json=payload, headers=headers)
        except httpx.HTTPError as e:
            raise LLMUnavailable(f"{type(e).__name__}: {e}") from e
        if response.status_code != 200:
            raise LLMUnavailable(f"HTTP {response.status_code}: {response.text[:200]}")
        try:
            return SimpleNamespace(content=response.json()["choices"][0]["message"]["content"])
        except (KeyError, IndexError, ValueError) as e:
            raise LLMUnavailable(f"unexpected reply shape: {e}") from e


_TRY_NEXT_MODEL = {"ResourceExhausted", "NotFound", "ServiceUnavailable"}
_COOLDOWN_SECONDS = 30 * 60
_exhausted_until: Dict[str, float] = {}      # model -> time before which we do not even try it


class GeminiFallbackLLM:
    def __init__(self, models: list, api_key: Optional[str], temperature: float, timeout: float):
        self.models = models
        self.api_key = api_key
        self.temperature = temperature
        self.timeout = timeout
        self.last_model: Optional[str] = None

    def invoke(self, messages):
        last_error: Optional[Exception] = None
        now = time.monotonic()
        candidates = [m for m in self.models if _exhausted_until.get(m, 0) <= now] or list(self.models)
        for model in candidates:
            client = ChatGoogleGenerativeAI(model=model, google_api_key=self.api_key, temperature=self.temperature,
                                            max_retries=0, timeout=self.timeout)
            try:
                reply = client.invoke(messages)
            except Exception as e:
                if type(e).__name__ not in _TRY_NEXT_MODEL:
                    raise
                _exhausted_until[model] = time.monotonic() + _COOLDOWN_SECONDS
                last_error = e
                continue
            self.last_model = model
            return reply
        raise last_error if last_error else LLMUnavailable("no Gemini model configured")


def llm_identity() -> Tuple[str, str]:
    """(provider, model) actually in use, for the audit trail."""
    if settings.LLM_PROVIDER == "openai_compatible":
        return "openai_compatible", settings.LLM_MODEL or "unknown"
    return "google", settings.GEMINI_MODEL


def get_llm():
    """The configured model client. Fails fast: a quota error must not leave an analyst waiting for minutes."""
    if settings.LLM_PROVIDER == "openai_compatible":
        if not settings.LLM_BASE_URL or not settings.LLM_MODEL:
            raise LLMUnavailable("LLM_PROVIDER=openai_compatible needs LLM_BASE_URL and LLM_MODEL")
        return OpenAICompatLLM(settings.LLM_BASE_URL, settings.LLM_MODEL, settings.LLM_API_KEY,
                               temperature=0.3, timeout=settings.LLM_TIMEOUT_SECONDS)
    models = [settings.GEMINI_MODEL] + [m.strip() for m in settings.GEMINI_FALLBACK_MODELS.split(",") if m.strip()]
    return GeminiFallbackLLM(
        models=list(dict.fromkeys(models)),       # no duplicates, order kept
        api_key=settings.GEMINI_API_KEY,
        temperature=0.3,                          # low for predictable Sigma rule generation
        timeout=settings.LLM_TIMEOUT_SECONDS,     # no retries inside a model: the default (6, with backoff) meant minutes of "Thinking..."
    )


def llm_call_with_audit(
    llm,
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
    
    provider, model = llm_identity()
    model = getattr(llm, "last_model", None) or model       # the model that really answered (fallback chain)
    audit_entry = {
        "context": context_name,
        "prompt": prompt,
        "system_prompt": system_prompt,
        "response": response_text,
        "model": model,
        "provider": provider,
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
