"""Chat API — conversational hunting with the AI agent."""
import json
from uuid import UUID
from typing import List, Dict, Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_action
from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import User, LLMAudit
from app.services.agent.graph import agent_graph
from app.services.agent.state import ChatState
from app.services.agent.nodes import run_hunt, explain_findings

router = APIRouter()


class ChatMessageRequest(BaseModel):
    message: str
    siem_targets: List[UUID]
    chat_history: List[Dict[str, str]] = []


class ChatMessageResponse(BaseModel):
    chat_history: List[Dict[str, str]]
    sigma_rule: Optional[str] = None
    needs_confirmation: bool = False
    hunt_id: Optional[str] = None
    hunt_status: Optional[str] = None
    total_hits: Optional[int] = None
    findings: List[Dict[str, Any]] = []
    explanation: Optional[str] = None
    follow_up_suggestions: List[str] = []
    error: Optional[str] = None


class ConfirmRequest(BaseModel):
    approved: bool
    sigma_rule: str
    siem_targets: List[UUID]
    chat_history: List[Dict[str, str]] = []


# [explain] The analyst talks to the AI. The AI understands the request and writes a Sigma rule,
# [explain] then it STOPS and waits: nothing is searched until the analyst says yes (see confirm_hunt).
@router.post("/message", response_model=ChatMessageResponse)
async def send_message(
    request: ChatMessageRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Send a message to the AI agent. Stops at generate_sigma, waiting for confirmation."""
    try:
        state: ChatState = {
            "user_message": request.message,
            "user_id": str(current_user.id),
            "chat_history": request.chat_history,
            "intent": None,
            "sigma_rule": None,
            "siem_targets": [str(t) for t in request.siem_targets],
            "needs_confirmation": False,
            "confirmed": None,
            "hunt_id": None,
            "hunt_status": None,
            "total_hits": None,
            "findings": [],
            "explanation": None,
            "follow_up_suggestions": [],
            "llm_audit_entries": [],
            "error": None,
        }
        
        # [explain] The agent is a small flowchart (understand, write rule). The graph runs it from start to the waiting point.
        result = await agent_graph.ainvoke(state)
        
        # Persist LLM audit entries
        # [explain] Every question we asked the AI and every answer is saved in llm_audit, so a lead can check later what it said.
        for audit in result.get("llm_audit_entries", []):
            llm_entry = LLMAudit(
                user_id=current_user.id,
                prompt=audit["prompt"][:5000],
                retrieved_context={"context": audit["context"], "system_prompt": audit["system_prompt"][:1000]},
                raw_response=audit["response"][:10000],
                parsed_response={"text": audit["response"]},
                model=audit["model"],
                provider=audit["provider"],
                latency_ms=audit["latency_ms"],
            )
            db.add(llm_entry)
        
        await log_action(
            db, user_id=current_user.id, action="chat.message",
            target_type="user", target_id=current_user.id,
            metadata={"message_length": len(request.message), "intent": result.get("intent", "")[:200]},
            request=req,
        )
        await db.commit()
        
        return ChatMessageResponse(
            chat_history=result.get("chat_history", []),
            sigma_rule=result.get("sigma_rule"),
            needs_confirmation=result.get("needs_confirmation", False),
            hunt_id=result.get("hunt_id"),
            hunt_status=result.get("hunt_status"),
            total_hits=result.get("total_hits"),
            findings=result.get("findings", []),
            explanation=result.get("explanation"),
            follow_up_suggestions=result.get("follow_up_suggestions", []),
            error=result.get("error"),
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Agent error: {str(e)}")


# [explain] The analyst's answer to "shall I run this?". Yes = run the hunt and let the AI explain the results.
# [explain] Known gap: the explanation's AI call is not saved to llm_audit here, only the /message route saves its calls.
@router.post("/confirm", response_model=ChatMessageResponse)
async def confirm_hunt(
    request: ConfirmRequest,
    req: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Approve or reject a generated Sigma rule.
    
    If approved → runs the hunt directly (bypasses understand_intent + generate_sigma).
    """
    try:
        if not request.approved:
            chat_history = request.chat_history + [{
                "role": "assistant",
                "content": "Okay, I won't run that hunt. What would you like to hunt for instead?",
            }]
            
            await log_action(
                db, user_id=current_user.id, action="chat.reject_hunt",
                target_type=None, target_id=None,
                metadata={"approved": False},
                request=req,
            )
            await db.commit()
            
            return ChatMessageResponse(
                chat_history=chat_history,
                needs_confirmation=False,
                follow_up_suggestions=[],
                findings=[],
            )
        
        # APPROVED → run the hunt directly using the run_hunt node
        state: ChatState = {
            "user_message": "Confirmed — run the hunt",
            "user_id": str(current_user.id),
            "chat_history": request.chat_history,
            "intent": "Confirmed by analyst",
            "sigma_rule": request.sigma_rule,
            "siem_targets": [str(t) for t in request.siem_targets],
            "needs_confirmation": False,
            "confirmed": True,
            "hunt_id": None,
            "hunt_status": None,
            "total_hits": None,
            "findings": [],
            "explanation": None,
            "follow_up_suggestions": [],
            "llm_audit_entries": [],
            "error": None,
        }
        
        # Run the hunt node directly (NOT the full graph)
        # [explain] Skips the first two steps of the flowchart: the rule was already written and approved.
        state = await run_hunt(state)
        
        # If hunt succeeded, explain the findings
        if state.get("hunt_status") == "completed" and state.get("findings"):
            state = await explain_findings(state)
        
        await log_action(
            db, user_id=current_user.id, action="chat.confirm_hunt",
            target_type="hunt",
            target_id=UUID(state["hunt_id"]) if state.get("hunt_id") else None,
            metadata={
                "approved": True,
                "hunt_status": state.get("hunt_status"),
                "total_hits": state.get("total_hits"),
            },
            request=req,
        )
        await db.commit()
        
        return ChatMessageResponse(
            chat_history=state.get("chat_history", []),
            sigma_rule=state.get("sigma_rule"),
            needs_confirmation=False,
            hunt_id=state.get("hunt_id"),
            hunt_status=state.get("hunt_status"),
            total_hits=state.get("total_hits"),
            findings=state.get("findings", []),
            explanation=state.get("explanation"),
            follow_up_suggestions=state.get("follow_up_suggestions", []),
            error=state.get("error"),
        )
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Confirm error: {str(e)}")
