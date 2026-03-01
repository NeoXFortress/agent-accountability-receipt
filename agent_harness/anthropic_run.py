"""
Anthropic Agent Run — Real Claude API call with tool use.

Scenario: User asks Claude to summarize a document excerpt and share
findings to a Slack channel. The harness:
1. Calls Claude (real API)
2. Runs classify_text on the input
3. Runs classify_text on Claude's output
4. Attempts send_slack (gets blocked if CUI detected)
5. Prompts for human checkpoint approval
6. Produces a signed Agent Accountability Receipt

Usage:
    export ANTHROPIC_API_KEY=sk-ant-...
    python agent_harness/anthropic_run.py

Copyright (c) 2026 Julio Berroa / NeoXFortress LLC
"""

import os
import sys
import time
import json
from datetime import datetime, timezone

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tools import classify_text, redact_text, send_slack
from receipt_writer import (
    ExecutionRecorder, StepEvent, make_data_ref, save_and_verify
)

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "..", "schema.json")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "examples")


def run_agent():
    """Run a real Claude-powered agent with accountability receipt generation."""

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("ERROR: Set ANTHROPIC_API_KEY environment variable.")
        print("  export ANTHROPIC_API_KEY=sk-ant-...")
        sys.exit(1)

    try:
        import anthropic
    except ImportError:
        print("ERROR: pip install anthropic")
        sys.exit(1)

    # --- Setup ---
    print("=" * 60)
    print("  NeoXFortress AAE — Anthropic Agent Run (Live)")
    print("=" * 60)
    print()

    # The document excerpt to process (contains CUI markings)
    document = (
        "CUI//SP-EXPT — DISTRIBUTION STATEMENT D\n\n"
        "PROJECT AURORA: Next-generation satellite communications upgrade "
        "for COCOM tactical networks. Budget ceiling: $42M over 36 months. "
        "Requires TS/SCI clearance for lead systems engineers. "
        "Key milestones: CDR in Q3 2026, IOC in Q1 2027. "
        "Subcontractor flow-down: DFARS 252.204-7012 applies. "
        "Contact: james.wilson@aurora-program.mil, SSN on file: 456-78-9012.\n\n"
        "TECHNICAL REQUIREMENTS:\n"
        "- Ka-band SATCOM terminals (ITAR restricted, USML Category XI)\n"
        "- AES-256 encryption at rest and in transit\n"
        "- CMMC Level 2 compliance required for all subcontractors\n"
        "- FedRAMP High authorization for cloud components"
    )

    target_channel = "#bd-team"

    # --- Initialize recorder ---
    recorder = ExecutionRecorder(
        purpose="Summarize classified document excerpt and share to Slack",
        agent_id="agent-claude-summarizer",
        agent_name="Claude Document Summarizer",
        agent_version="1.0.0",
        organization="Apex Defense Solutions",
        network_boundary="CUI enclave",
        policy_id="pol-apex-ai-governance",
        policy_version="2.1.0",
        schema_path=SCHEMA_PATH,
    )

    # --- Step 1: Classify input document ---
    print("[Step 1] Classifying input document...")
    t0 = time.time()
    input_classifications = classify_text(document)
    classify_ms = int((time.time() - t0) * 1000)

    cls_tags = [{"tag": c.tag, "confidence": c.confidence, "method": "rule_based",
                 "rule_id": c.rule_id} for c in input_classifications]
    found_tags = [c.tag for c in input_classifications]
    print(f"  Found: {', '.join(found_tags)}")

    step1_id = recorder.record(StepEvent(
        step_type="tool_call",
        summary=f"Classified input document — found {', '.join(found_tags)}",
        actor="system",
        tool_name="classify_text",
        tool_version="1.0.0",
        tool_permission_scope="read_input",
        inputs=[make_data_ref("ref-doc-input", document, source_hint="User document")],
        outputs=[make_data_ref("ref-classify-result", json.dumps(found_tags))],
        classifications=cls_tags,
        latency_ms=classify_ms,
    ))

    recorder.add_cui_flow(
        direction="in",
        boundary="User input to agent memory",
        data=document,
        classification="CUI_SPECIFIED" if "CUI_SPECIFIED" in found_tags else "CUI",
        redacted=False,
        step_ids=[step1_id],
        policy_rule_id="cui-ingest-allow-001",
    )

    # --- Step 2: Call Claude (real API) ---
    print("[Step 2] Calling Claude API...")
    client = anthropic.Anthropic(api_key=api_key)

    prompt = (
        "Summarize the following document excerpt for an internal bid/no-bid review. "
        "Focus on: budget, timeline, key requirements, and compliance obligations. "
        "Keep it concise (3-5 sentences).\n\n"
        f"Document:\n{document}"
    )

    t0 = time.time()
    response = client.messages.create(
        model="claude-sonnet-4-5-20250514",
        max_tokens=500,
        messages=[{"role": "user", "content": prompt}],
    )
    llm_ms = int((time.time() - t0) * 1000)

    llm_output = response.content[0].text
    tokens_in = response.usage.input_tokens
    tokens_out = response.usage.output_tokens

    print(f"  Response ({tokens_out} tokens, {llm_ms}ms):")
    print(f"  {llm_output[:120]}...")

    step2_id = recorder.record(StepEvent(
        step_type="llm_call",
        summary="Called Claude to summarize classified document",
        parent_step_id=step1_id,
        model_provider="Anthropic",
        model_id="claude-sonnet-4-5-20250514",
        model_region="us-east-1",
        inputs=[make_data_ref("ref-prompt", prompt, source_hint="Agent prompt")],
        outputs=[make_data_ref("ref-llm-output", llm_output)],
        classifications=cls_tags,  # inherit input classifications
        latency_ms=llm_ms,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
    ))

    recorder.add_cui_flow(
        direction="out",
        boundary="Agent memory to Anthropic API (external)",
        data=prompt,
        classification="CUI_SPECIFIED" if "CUI_SPECIFIED" in found_tags else "CUI",
        redacted=False,
        step_ids=[step2_id],
        policy_rule_id="cui-llm-transit-002",
    )

    # --- Step 3: Classify Claude's output ---
    print("[Step 3] Classifying Claude's output...")
    output_classifications = classify_text(llm_output)
    output_tags = [c.tag for c in output_classifications]
    output_cls = [{"tag": c.tag, "confidence": c.confidence, "method": "rule_based",
                   "rule_id": c.rule_id} for c in output_classifications]

    step3_id = recorder.record(StepEvent(
        step_type="tool_call",
        summary=f"Classified LLM output — found {', '.join(output_tags) if output_tags else 'no sensitive tags'}",
        parent_step_id=step2_id,
        actor="system",
        tool_name="classify_text",
        tool_version="1.0.0",
        tool_permission_scope="read_output",
        inputs=[make_data_ref("ref-output-for-classify", llm_output)],
        outputs=[make_data_ref("ref-output-classify-result", json.dumps(output_tags))],
        classifications=output_cls,
    ))

    # --- Step 4: Attempt to send to Slack ---
    print(f"[Step 4] Attempting to send to Slack {target_channel}...")
    slack_result = send_slack(target_channel, llm_output, output_classifications)

    if slack_result.blocked:
        print(f"  BLOCKED: {slack_result.reason}")

        guardrail_events = [{
            "event_id": "gr-live-001",
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "event_type": "block",
            "action": "blocked",
            "reason": slack_result.reason,
            "policy_rule_id": "cui-exfil-block-001",
            "attempted_action": f"POST message to Slack channel {target_channel}",
            "target_resource_hint": f"Slack:{target_channel}/***",
        }]

        step4_id = recorder.record(StepEvent(
            step_type="guardrail_event",
            summary=f"BLOCKED: Attempted to send {', '.join(slack_result.classification_tags)} content to Slack",
            parent_step_id=step3_id,
            actor="system",
            inputs=[make_data_ref("ref-slack-payload", llm_output)],
            outputs=[],
            classifications=output_cls,
            guardrails=guardrail_events,
            error_code="CUI_BOUNDARY_VIOLATION",
            error_message=slack_result.reason,
            error_recoverable=True,
        ))

        recorder.add_cui_flow(
            direction="out",
            boundary=f"BLOCKED: Agent to Slack {target_channel} (external SaaS)",
            data=llm_output,
            classification=output_tags[0] if output_tags else "UNKNOWN",
            redacted=False,
            step_ids=[step4_id],
            policy_rule_id="cui-exfil-block-001",
        )

        # --- Step 5: Redact and retry ---
        print("[Step 5] Redacting sensitive content...")
        redaction = redact_text(llm_output, output_classifications)
        print(f"  Redacted {redaction.redaction_count} span(s)")

        step5_id = recorder.record(StepEvent(
            step_type="tool_call",
            summary=f"Redacted {redaction.redaction_count} sensitive span(s) from output",
            parent_step_id=step4_id,
            actor="system",
            tool_name="redact_text",
            tool_version="1.0.0",
            tool_permission_scope="read_write_output",
            inputs=[make_data_ref("ref-pre-redact", llm_output)],
            outputs=[make_data_ref("ref-post-redact", redaction.redacted_text,
                                   "redacted_text", redaction_method=redaction.method,
                                   redaction_count=redaction.redaction_count)],
            classifications=[{"tag": "PROPRIETARY", "confidence": 1.0,
                              "method": "rule_based", "rule_id": "post-redaction-001"}],
        ))

        final_output = redaction.redacted_text
    else:
        print(f"  Sent successfully (simulated)")
        step4_id = recorder.record(StepEvent(
            step_type="tool_call",
            summary=f"Sent summary to Slack {target_channel}",
            parent_step_id=step3_id,
            tool_name="send_slack",
            tool_version="1.0.0",
            tool_permission_scope="write_slack",
            inputs=[make_data_ref("ref-slack-msg", llm_output)],
            outputs=[make_data_ref("ref-slack-result", "sent")],
            classifications=output_cls,
        ))
        step5_id = step4_id
        final_output = llm_output

    # --- Step 6: Human checkpoint ---
    print()
    print("[Step 6] HUMAN CHECKPOINT")
    print("-" * 40)
    print("Agent output (for review):")
    print()
    print(final_output)
    print()
    print("-" * 40)

    t_review_start = time.time()
    try:
        approval = input("Approve this output? (yes/no): ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        approval = "yes"
        print("  (auto-approved in non-interactive mode)")
    review_ms = int((time.time() - t_review_start) * 1000)

    reviewer_action = "approved" if approval in ("yes", "y") else "rejected"

    step6_id = recorder.record(StepEvent(
        step_type="human_checkpoint",
        summary=f"Human reviewer {reviewer_action} the output (reviewed {review_ms}ms)",
        parent_step_id=step5_id,
        actor="operator",
        presented_text=final_output,
        presentation_mode="full_output" if not slack_result.blocked else "redacted",
        reviewer_action=reviewer_action,
        review_duration_ms=review_ms,
        inputs=[make_data_ref("ref-for-review", final_output)],
        outputs=[make_data_ref("ref-reviewed-output", final_output)] if reviewer_action == "approved" else [],
        classifications=[{"tag": "PROPRIETARY", "confidence": 1.0,
                          "method": "rule_based", "rule_id": "reviewed-output-001"}],
    ))

    # --- Build receipt ---
    print()
    print("[*] Building receipt...")

    if slack_result.blocked:
        if reviewer_action == "approved":
            verdict = "compliant"
            notes = "CUI detected and blocked before boundary crossing. Content redacted. Human approved redacted version."
            risk = 2.0
            controls = []
            status = "success"
        else:
            verdict = "review_required"
            notes = "CUI blocked, content redacted, but human rejected output."
            risk = 4.0
            controls = []
            status = "partial"
    else:
        verdict = "compliant"
        notes = "No sensitive content detected in output. Sent to Slack. Human approved."
        risk = 0.5
        controls = []
        status = "success" if reviewer_action == "approved" else "partial"

    receipt = recorder.build_receipt(
        run_status=status,
        run_inputs=[make_data_ref("ref-run-input", document, source_hint="User document")],
        run_outputs=[make_data_ref("ref-run-output", final_output, source_hint="Final output")],
        compliance_verdict=verdict,
        violated_controls=controls,
        risk_score=risk,
        compliance_notes=notes,
        labels=["LIVE", "ANTHROPIC", "CMMC"] + (["CUI-BLOCKED"] if slack_result.blocked else []),
    )

    # --- Save and verify ---
    output_path = os.path.join(OUTPUT_DIR, "live-anthropic-run.json")
    save_and_verify(receipt, output_path, SCHEMA_PATH)

    print()
    print(f"  Receipt ID:    {receipt['receipt']['receipt_id']}")
    print(f"  Steps:         {len(receipt['execution']['steps'])}")
    print(f"  Compliance:    {receipt['compliance']['verdict']}")
    print(f"  CUI blocked:   {slack_result.blocked}")
    print(f"  Human action:  {reviewer_action}")
    print()


if __name__ == "__main__":
    run_agent()
