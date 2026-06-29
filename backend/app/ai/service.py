"""AI orchestration: retrieve -> prompt -> provider -> validate -> persist + audit."""
from __future__ import annotations

import time
import uuid

from sqlmodel import Session

from app.ai.factory import get_provider
from app.ai.prompts import build_messages
from app.ai.retrieval import build_context
from app.ai.schema import validate_answer
from app.ai.triage import INTENT_ANALYSIS, SUGGESTIONS, TriageResult, triage_chat
from app.core.config import settings
from app.core.enums import AIUseCase, AuditAction, MessageRole
from app.models.ai import AIConversation, AIMessage
from app.schemas.ai import AIChatResponse
from app.services.audit_service import record_audit


def _get_or_create_conversation(
    session: Session,
    *,
    conversation_id: uuid.UUID | None,
    user_id: uuid.UUID | None,
    use_case: AIUseCase,
    title_seed: str,
) -> AIConversation:
    if conversation_id is not None:
        conv = session.get(AIConversation, conversation_id)
        if conv is not None:
            return conv
    conv = AIConversation(
        user_id=user_id,
        use_case=use_case,
        title=(title_seed[:60] or "New conversation"),
    )
    session.add(conv)
    session.commit()
    session.refresh(conv)
    return conv


def _short_circuit_chat(
    session: Session,
    *,
    user_id: uuid.UUID | None,
    actor_email: str | None,
    question: str,
    conversation_id: uuid.UUID | None,
    triaged: TriageResult,
) -> AIChatResponse:
    """Persist + return a canned capability reply for a non-task chat input.

    No model inference happens; the conversation/messages are still recorded and
    audited so the trail is complete.
    """
    conv = _get_or_create_conversation(
        session,
        conversation_id=conversation_id,
        user_id=user_id,
        use_case=AIUseCase.CHAT,
        title_seed=question or "New conversation",
    )

    record_audit(
        session,
        action=AuditAction.AI_PROMPT,
        actor_user_id=user_id,
        actor_email=actor_email,
        entity_type="ai_conversation",
        entity_id=conv.id,
        summary=f"AI CHAT query (triaged: {triaged.intent})",
        meta={"use_case": AIUseCase.CHAT.value, "triaged": True, "intent": triaged.intent},
    )

    user_msg = AIMessage(
        conversation_id=conv.id,
        role=MessageRole.USER,
        content=question or "",
        use_case=AIUseCase.CHAT,
    )
    session.add(user_msg)
    session.commit()

    assistant_msg = AIMessage(
        conversation_id=conv.id,
        role=MessageRole.ASSISTANT,
        content=triaged.message,
        confidence="n/a",
        intent=triaged.intent,
        provider_name="triage",
        model_name="rule-based",
        latency_ms=0,
        use_case=AIUseCase.CHAT,
    )
    session.add(assistant_msg)
    session.commit()
    session.refresh(assistant_msg)

    record_audit(
        session,
        action=AuditAction.AI_RESPONSE,
        actor_user_id=user_id,
        actor_email=actor_email,
        entity_type="ai_message",
        entity_id=assistant_msg.id,
        summary=f"AI triaged reply ({triaged.intent}, no model call)",
        meta={"intent": triaged.intent, "triaged": True},
    )

    assert conv.id is not None and assistant_msg.id is not None
    return AIChatResponse(
        conversation_id=conv.id,
        message_id=assistant_msg.id,
        use_case=AIUseCase.CHAT,
        summary=triaged.message,
        findings=[],
        citations=[],
        confidence="n/a",
        assumptions=[],
        safe_ot_actions=[],
        attack_path=[],
        reasoning=None,
        intent=triaged.intent,
        suggestions=triaged.suggestions,
        disclaimer="",
        provider_name="triage",
        model_name="rule-based",
        latency_ms=0,
    )


def run_ai_query(
    session: Session,
    *,
    user_id: uuid.UUID | None,
    actor_email: str | None,
    use_case: AIUseCase,
    entity_id: uuid.UUID | None,
    question: str,
    conversation_id: uuid.UUID | None,
) -> AIChatResponse:
    # Free-form chat: cheaply gate non-task inputs (greetings, small talk, help) so we
    # return an honest capability message — and skip the model call — instead of
    # fabricating a grounded analysis for a question that was never asked.
    if use_case == AIUseCase.CHAT:
        triaged = triage_chat(question)
        if triaged is not None:
            return _short_circuit_chat(
                session,
                user_id=user_id,
                actor_email=actor_email,
                question=question,
                conversation_id=conversation_id,
                triaged=triaged,
            )

    context = build_context(session, use_case=use_case, entity_id=entity_id, question=question)
    messages = build_messages(context, question)
    provider = get_provider()

    conv = _get_or_create_conversation(
        session,
        conversation_id=conversation_id,
        user_id=user_id,
        use_case=use_case,
        title_seed=question or context.headline,
    )

    # Audit the prompt (full traceability of what the AI was asked).
    record_audit(
        session,
        action=AuditAction.AI_PROMPT,
        actor_user_id=user_id,
        actor_email=actor_email,
        entity_type="ai_conversation",
        entity_id=conv.id,
        summary=f"AI {use_case.value} query",
        meta={"use_case": use_case.value, "allowed_citations": sorted(context.allowed_citations)},
    )

    # Persist the user message.
    user_msg = AIMessage(
        conversation_id=conv.id,
        role=MessageRole.USER,
        content=question or context.headline,
        use_case=use_case,
    )
    session.add(user_msg)
    session.commit()

    t0 = time.perf_counter()
    raw = provider.complete(
        messages,
        temperature=settings.ai_temperature,
        max_tokens=settings.ai_max_tokens,
    )
    latency_ms = int((time.perf_counter() - t0) * 1000)

    answer = validate_answer(raw, context.allowed_citations)
    reasoning = getattr(provider, "last_reasoning", None) if settings.ai_capture_reasoning else None
    suggestions = list(SUGGESTIONS) if answer.intent != INTENT_ANALYSIS else []
    if answer.intent != INTENT_ANALYSIS:
        # A non-task reply that slipped past triage: keep the message, drop the
        # analysis chrome so the UI never shows confidence/citations for it.
        answer.findings = []
        answer.citations = []
        answer.safe_ot_actions = []
        answer.attack_path = []

    assistant_msg = AIMessage(
        conversation_id=conv.id,
        role=MessageRole.ASSISTANT,
        content=answer.summary,
        citations=[c.model_dump() for c in answer.citations],
        confidence=answer.confidence,
        assumptions=answer.assumptions,
        safe_ot_actions=answer.safe_ot_actions,
        attack_path=[s.model_dump() for s in answer.attack_path],
        reasoning=reasoning,
        intent=answer.intent,
        provider_name=provider.name(),
        model_name=provider.model_name,
        latency_ms=latency_ms,
        use_case=use_case,
    )
    session.add(assistant_msg)
    session.commit()
    session.refresh(assistant_msg)

    record_audit(
        session,
        action=AuditAction.AI_RESPONSE,
        actor_user_id=user_id,
        actor_email=actor_email,
        entity_type="ai_message",
        entity_id=assistant_msg.id,
        summary=f"AI response ({answer.confidence} confidence, {len(answer.citations)} citations)",
        meta={
            "provider": provider.name(),
            "model": provider.model_name,
            "latency_ms": latency_ms,
            "has_reasoning": bool(reasoning),
            "attack_path_steps": len(answer.attack_path),
        },
    )

    assert conv.id is not None and assistant_msg.id is not None
    return AIChatResponse(
        conversation_id=conv.id,
        message_id=assistant_msg.id,
        use_case=use_case,
        summary=answer.summary,
        findings=answer.findings,
        citations=answer.citations,
        confidence=answer.confidence,
        assumptions=answer.assumptions,
        safe_ot_actions=answer.safe_ot_actions,
        attack_path=answer.attack_path,
        reasoning=reasoning,
        intent=answer.intent,
        suggestions=suggestions,
        disclaimer=answer.disclaimer,
        provider_name=provider.name(),
        model_name=provider.model_name,
        latency_ms=latency_ms,
    )
