"""LangGraph state — passed between nodes in the agent graph."""
from typing import Optional, List, Dict, Any, Annotated
from typing_extensions import TypedDict
from operator import add


# [explain] The agent's notebook page. Every step of the flowchart reads from it and writes to it:
# [explain] what the analyst asked, the rule it wrote, the hunt that ran, the findings, the explanation.
class ChatState(TypedDict):
    """State that flows through the LangGraph agent.
    
    Each node reads from + writes to this dict.
    """
    # Input
    user_message: str                                    # what the analyst asked
    user_id: str                                         # who's asking
    chat_history: Annotated[List[Dict[str, str]], add]   # previous messages
    
    # Generated during processing
    intent: Optional[str]                                # what the analyst wants
    sigma_rule: Optional[str]                            # generated Sigma YAML
    siem_targets: List[str]                              # which SIEMs to query
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
    llm_audit_entries: Annotated[List[Dict[str, Any]], add]  # every LLM call logged
    
    # Error handling
    error: Optional[str]
