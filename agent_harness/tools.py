"""
Agent Tools — Minimal tool set for demonstrating accountability receipts.

Tool 1: classify_text  — Rule-based CUI/PII/ITAR classification
Tool 2: redact_text    — Mask flagged spans based on classification
Tool 3: send_slack     — Mocked Slack sender that blocks if CUI present

These tools are intentionally simple. The point is not sophisticated NLP —
it's producing a real execution trace that maps to receipt steps.

Copyright (c) 2026 Julio Berroa / NeoXFortress LLC
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional


# ---------------------------------------------------------------------------
# Classification rules (loaded from config in production)
# ---------------------------------------------------------------------------

CLASSIFICATION_RULES = [
    {
        "id": "cui-header-001",
        "tag": "CUI",
        "patterns": [
            r"\bCUI\b",
            r"CONTROLLED\s+UNCLASSIFIED",
            r"CUI//[A-Z\-]+",
            r"DISTRIBUTION\s+(STATEMENT\s+)?[A-F]",
        ],
        "confidence": 1.0,
    },
    {
        "id": "cui-sp-001",
        "tag": "CUI_SPECIFIED",
        "patterns": [
            r"CUI//SP-[A-Z]+",
            r"CUI\s+SPECIFIED",
        ],
        "confidence": 1.0,
    },
    {
        "id": "pii-ssn-001",
        "tag": "PII",
        "patterns": [
            r"\b\d{3}-\d{2}-\d{4}\b",
        ],
        "confidence": 0.95,
    },
    {
        "id": "pii-email-001",
        "tag": "PII",
        "patterns": [
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        ],
        "confidence": 0.85,
    },
    {
        "id": "itar-001",
        "tag": "ITAR",
        "patterns": [
            r"\bITAR\b",
            r"INTERNATIONAL\s+TRAFFIC\s+IN\s+ARMS",
            r"USML\s+CATEGORY",
        ],
        "confidence": 0.9,
    },
    {
        "id": "export-001",
        "tag": "EXPORT_CONTROL",
        "patterns": [
            r"\bEAR\b",
            r"EXPORT\s+CONTROL",
            r"ECCN\s+\d",
        ],
        "confidence": 0.85,
    },
]


@dataclass
class ClassificationResult:
    tag: str
    confidence: float
    method: str = "rule_based"
    rule_id: str = ""
    spans: List[tuple] = field(default_factory=list)  # (start, end) positions
    notes: str = ""


@dataclass
class RedactionResult:
    redacted_text: str
    original_text: str
    redaction_count: int
    method: str
    classifications: List[ClassificationResult] = field(default_factory=list)


@dataclass
class SlackResult:
    sent: bool
    blocked: bool
    reason: str
    channel: str
    classification_tags: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Tool 1: classify_text
# ---------------------------------------------------------------------------

def classify_text(text: str, rules: list = None) -> List[ClassificationResult]:
    """
    Rule-based text classification for CUI/PII/ITAR/EXPORT_CONTROL.

    Returns a list of classification results with matched spans.
    In production, this would load rules from policy YAML.
    """
    if rules is None:
        rules = CLASSIFICATION_RULES

    results = []
    for rule in rules:
        all_spans = []
        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                all_spans.append((match.start(), match.end()))

        if all_spans:
            results.append(ClassificationResult(
                tag=rule["tag"],
                confidence=rule["confidence"],
                method="rule_based",
                rule_id=rule["id"],
                spans=all_spans,
                notes=f"Matched {len(all_spans)} span(s) via pattern(s)",
            ))

    return results


# ---------------------------------------------------------------------------
# Tool 2: redact_text
# ---------------------------------------------------------------------------

def redact_text(
    text: str,
    classifications: List[ClassificationResult],
    tags_to_redact: List[str] = None,
) -> RedactionResult:
    """
    Redact text spans that match specified classification tags.

    Default: redacts CUI, CUI_SPECIFIED, PII, ITAR spans.
    Replaces matched spans with [REDACTED:<TAG>].
    """
    if tags_to_redact is None:
        tags_to_redact = ["CUI", "CUI_SPECIFIED", "PII", "ITAR", "EXPORT_CONTROL"]

    # Collect all spans to redact, with their tags
    spans_to_redact = []
    for cls in classifications:
        if cls.tag in tags_to_redact:
            for start, end in cls.spans:
                spans_to_redact.append((start, end, cls.tag))

    if not spans_to_redact:
        return RedactionResult(
            redacted_text=text,
            original_text=text,
            redaction_count=0,
            method="no_redaction_needed",
            classifications=classifications,
        )

    # Sort by position (descending) so replacements don't shift indices
    spans_to_redact.sort(key=lambda x: x[0], reverse=True)

    # Merge overlapping spans
    merged = []
    for start, end, tag in spans_to_redact:
        if merged and start <= merged[-1][1]:
            # Overlapping — extend
            prev_start, prev_end, prev_tag = merged[-1]
            merged[-1] = (min(start, prev_start), max(end, prev_end), prev_tag)
        else:
            merged.append((start, end, tag))

    redacted = text
    for start, end, tag in merged:
        redacted = redacted[:start] + f"[REDACTED:{tag}]" + redacted[end:]

    return RedactionResult(
        redacted_text=redacted,
        original_text=text,
        redaction_count=len(merged),
        method="regex_pattern_redact",
        classifications=classifications,
    )


# ---------------------------------------------------------------------------
# Tool 3: send_slack (mocked)
# ---------------------------------------------------------------------------

def send_slack(
    channel: str,
    message: str,
    classifications: List[ClassificationResult] = None,
    block_on_tags: List[str] = None,
) -> SlackResult:
    """
    Mocked Slack sender. Blocks transmission if CUI/sensitive tags detected.

    In production, this would be a real Slack webhook with guardrail enforcement.
    For demo purposes, it simulates the send/block decision.
    """
    if block_on_tags is None:
        block_on_tags = ["CUI", "CUI_SPECIFIED", "ITAR"]

    if classifications is None:
        classifications = classify_text(message)

    found_tags = [c.tag for c in classifications]
    blocked_tags = [t for t in found_tags if t in block_on_tags]

    if blocked_tags:
        return SlackResult(
            sent=False,
            blocked=True,
            reason=f"Blocked: {', '.join(blocked_tags)} detected in message. "
                   f"Policy prohibits transmission of {', '.join(blocked_tags)} "
                   f"to external SaaS channels.",
            channel=channel,
            classification_tags=found_tags,
        )

    # Simulated send (no actual HTTP call)
    return SlackResult(
        sent=True,
        blocked=False,
        reason="Message sent successfully (simulated)",
        channel=channel,
        classification_tags=found_tags,
    )


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    test_text = (
        "CUI//SP-EXPT — This contract covers satellite communications upgrade. "
        "Budget: $42M. Contact: john.doe@defense.mil. SSN: 123-45-6789. "
        "ITAR restricted components in USML Category XI."
    )

    print("=== classify_text ===")
    results = classify_text(test_text)
    for r in results:
        print(f"  {r.tag} (conf={r.confidence}, rule={r.rule_id}, spans={len(r.spans)})")

    print("\n=== redact_text ===")
    redacted = redact_text(test_text, results)
    print(f"  Redactions: {redacted.redaction_count}")
    print(f"  Result: {redacted.redacted_text[:100]}...")

    print("\n=== send_slack (with CUI) ===")
    slack = send_slack("#bids", test_text, results)
    print(f"  Sent: {slack.sent}, Blocked: {slack.blocked}")
    print(f"  Reason: {slack.reason}")

    print("\n=== send_slack (clean text) ===")
    clean = send_slack("#general", "Meeting at 3pm tomorrow in conf room B.")
    print(f"  Sent: {clean.sent}, Blocked: {clean.blocked}")
    print(f"  Reason: {clean.reason}")
