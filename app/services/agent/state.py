"""LangGraph state — passed between nodes in the agent graph."""
from typing import Optional, List, Dict, Any, Annotated
from typing_extensions import TypedDict
from operator import add


class ChatState(TypedDict):
    """State that flows through the LangGraph agent.
    
    Each node reads from + writes to this dict.
    """
    # Input
    user_message: str                                    # what the analyst asked
    user_id: str                                         # who's asking
    chat_history: List[Dict[str, str]]                   # previous messages (each node returns the full list)
    
    # Generated during processing
    intent: Optional[str]                                # what the analyst wants
    sigma_rule: Optional[str]                            # generated Sigma YAML
    siem_targets: List[str]                              # which SIEMs to query
    client_id: Optional[str]                             # the client that owns them (checked by the API)
    needs_confirmation: bool                             # waiting for user approval?
    confirmed: Optional[bool]                            # did user approve?
    
    # Hunt results
    hunt_id: Optional[str]                               # created hunt ID
    hunt_status: Optional[str]                           # pending/running/completed/failed
    total_hits: Optional[int]                            # number of findings
    findings: List[Dict[str, Any]]                       # the actual findings
    
    # Generated explanation
    explanation: Optional[str]                           # plain-English summary
    follow_up_suggestions: List[str]                      # next-step ideas
    
    # LLM audit trail (hallucination mitigation)
    llm_audit_entries: List[Dict[str, Any]]              # every LLM call logged (each node returns the full list)
    
    # Error handling
    error: Optional[str]
