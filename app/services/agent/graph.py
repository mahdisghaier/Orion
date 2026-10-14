"""LangGraph state machine — defines the agent's flow.

Flow:
    START
      ↓
    understand_intent
      ↓
    generate_sigma
      ↓
    [WAIT FOR USER CONFIRMATION]  ← stops here, asks user
      ↓ (user says yes)
    run_hunt
      ↓
    explain_findings
      ↓
    END
"""
from langgraph.graph import StateGraph, END

from .state import ChatState
from .nodes import understand_intent, generate_sigma, run_hunt, explain_findings


# [explain] The fork in the road after the rule is written: yes = run it, no = stop, not answered yet = wait.
def should_wait_for_confirmation(state: ChatState) -> str:
    """Decide whether to wait for user confirmation or proceed to run the hunt."""
    if state.get("confirmed") is True:
        return "run_hunt"
    elif state.get("confirmed") is False:
        return "end"
    else:
        return "wait"


# [explain] Draws the flowchart: understand the request, write the rule, then WAIT for the analyst. The hunt itself is run from /confirm.
def build_graph():
    """Build the LangGraph agent workflow."""
    workflow = StateGraph(ChatState)
    
    # Add nodes
    workflow.add_node("understand_intent", understand_intent)
    workflow.add_node("generate_sigma", generate_sigma)
    workflow.add_node("run_hunt", run_hunt)
    workflow.add_node("explain_findings", explain_findings)
    
    # Set entry point
    workflow.set_entry_point("understand_intent")
    
    # Add edges
    workflow.add_edge("understand_intent", "generate_sigma")
    
    # Conditional edge after generate_sigma:
    # - If user confirmed → run_hunt
    # - If user rejected → END
    # - Otherwise → wait (graph pauses, returns to user)
    workflow.add_conditional_edges(
        "generate_sigma",
        should_wait_for_confirmation,
        {
            "run_hunt": "run_hunt",
            "end": END,
            "wait": END,  # graph ends here, will resume on next user message
        },
    )
    
    workflow.add_edge("run_hunt", "explain_findings")
    workflow.add_edge("explain_findings", END)
    
    return workflow.compile()


# Singleton — import this everywhere
# [explain] Built once when the server starts, and reused by every chat message.
agent_graph = build_graph()
