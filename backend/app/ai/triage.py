"""Lightweight, deterministic pre-gate for the free-form AI chat.

Greetings, small talk and help/meta questions are NOT security questions.
Answering them with a grounded analysis — complete with a confidence badge and
citations — is misleading and wastes an (expensive) model call. This module
classifies such inputs cheaply, with no model call, so the orchestrator can
return a short, honest capability message instead.

Only the free-form ``CHAT`` use case is triaged; the structured endpoints
(asset risk, attack path, alert translate, …) are always explicit tasks and skip
this entirely. Semantic off-topic inputs that slip past these rules are caught by
the model itself via the ``intent`` field in the response contract.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Intent labels surfaced on the API/UI. "analysis" == a normal grounded answer.
INTENT_ANALYSIS = "analysis"
INTENT_GREETING = "greeting"
INTENT_HELP = "help"
INTENT_OUT_OF_SCOPE = "out_of_scope"

# What the analyst can actually do — shown in capability replies.
CAPABILITIES: list[str] = [
    "Assess an asset's risk and the single safest next action",
    "Explain a vulnerability's OT impact and a safe remediation plan",
    "Translate a detection or alert into plain language",
    "Map compliance evidence and summarize control gaps",
    "Model a DEFENSIVE ATT&CK-for-ICS attack path over your asset graph",
]

# Clickable starter questions offered alongside a capability reply.
SUGGESTIONS: list[str] = [
    "What are the top OT risks across the plant right now?",
    "Which critical assets are internet-reachable?",
    "Summarize today's most urgent detections.",
    "Which compliance controls have gaps?",
]

_CAPABILITY_LINES = "\n".join(f"• {c}" for c in CAPABILITIES)

_GREETING_MESSAGE = (
    "Hi — I'm the ForgeShield OT Security Analyst. I don't do small talk, but I "
    "can help you secure this OT environment. I can:\n"
    f"{_CAPABILITY_LINES}\n\n"
    "Ask about a specific asset, detection, vulnerability, control or incident — "
    "or pick one of the suggestions below."
)

_HELP_MESSAGE = (
    "I'm the ForgeShield OT Security Analyst — a grounded, advisory-only assistant. "
    "Everything I say is cited to your OT records and limited to safe OT actions. I can:\n"
    f"{_CAPABILITY_LINES}\n\n"
    "Try one of the suggestions below, or reference a specific record."
)

# Whole-message greetings / pleasantries (anchored: must be the entire message).
_GREETING_RE = re.compile(
    r"^(?:"
    r"hi+|hey+|hello+|hiya|yo|sup|howdy|heya|ha?llo|"
    r"good\s*(?:morning|afternoon|evening|day)|greetings|gm|gn|"
    r"thanks?|thank\s*you|thx|ty|cheers|ok(?:ay)?|kk|cool|nice|great|awesome|"
    r"bye+|goodbye|see\s*ya|later|"
    r"how\s*are\s*you|how'?s\s*it\s*going|what'?s\s*up|wass?up"
    r")[\s!.?]*$"
)

# Whole-message help requests.
_HELP_WHOLE_RE = re.compile(r"^(?:help|help\s*me|i\s*need\s*help|help\s*please|please\s*help)[\s!.?]*$")

# Meta/capability questions — only honored when the message is short (see below),
# so real questions like "what are you seeing on asset X" are NOT misclassified.
_META_RE = re.compile(
    r"\b(?:what\s+can\s+you\s+do|what\s+can\s+i\s+ask|who\s+are\s+you|what\s+are\s+you|"
    r"how\s+do\s+you\s+work|what\s+do\s+you\s+do|what\s+is\s+this\s+(?:app|tool|thing|page|assistant))\b"
)


@dataclass
class TriageResult:
    intent: str
    message: str
    suggestions: list[str]


def triage_chat(question: str) -> TriageResult | None:
    """Classify a free-form chat input.

    Returns a canned :class:`TriageResult` for non-task inputs (greeting / help /
    empty / trivially short), or ``None`` to let the grounded analysis pipeline
    handle a genuine question.
    """
    q = (question or "").strip()
    if len(q) < 2:  # "", "?", "hi" typo'd to one char — nudge toward a real question
        return TriageResult(INTENT_GREETING, _GREETING_MESSAGE, list(SUGGESTIONS))

    normalized = re.sub(r"\s+", " ", q.lower()).strip()
    word_count = len(normalized.split())

    if _GREETING_RE.match(normalized):
        return TriageResult(INTENT_GREETING, _GREETING_MESSAGE, list(SUGGESTIONS))

    # "help" only as a whole message; meta-questions only when short, so a long
    # genuine question that happens to contain these words still gets analyzed.
    if _HELP_WHOLE_RE.match(normalized) or (word_count <= 6 and _META_RE.search(normalized)):
        return TriageResult(INTENT_HELP, _HELP_MESSAGE, list(SUGGESTIONS))

    return None
