"""
Scenario: Human Checkpoint Rejection
Agent drafts a response to a DFARS clause inquiry. The compliance lead
reviews the draft and rejects it — the agent hallucinated a regulation
reference. Run completes as 'partial' with the rejection documented.

This demonstrates the schema handling human-in-the-loop rejection paths.
"""

import json
import hashlib
import hmac as hmac_mod
import uuid
import os
import sys
import base64
from datetime import datetime, timezone, timedelta

SECRET_KEY = os.environ.get(
    "AAR_SIGNING_KEY", "demo-secret-key-do-not-use-in-production"
).encode()
SIGNING_KEY_ID = os.environ.get("AAR_SIGNING_KEY_ID", "demo-key-001")
SCHEMA_VERSION = "0.1.1"


def canonical_json(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def make_data_ref(ref_id, content, representation="hash_only", **kw):
    ref = {"ref_id": ref_id, "representation": representation, "hash": sha256_hex(content.encode()), "hash_alg": "sha256"}
    for k in ("source_hint", "mime_type"):
        if k in kw:
            ref[k] = kw[k]
    if representation == "full_text":
        ref["content"] = content
    elif representation == "redacted_text":
        ref["content"] = content
        ref["content_redaction"] = {"method": kw.get("redaction_method", "regex"), "redaction_count": kw.get("redaction_count", 0)}
    return ref


def build_receipt():
    base_time = datetime(2026, 3, 5, 11, 15, 0, tzinfo=timezone.utc)
    receipt_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())

    def ts(offset):
        return (base_time + timedelta(seconds=offset)).isoformat()

    schema_path = os.path.join(os.path.dirname(__file__), "..", "schema.json")
    if os.path.exists(schema_path):
        with open(schema_path, "rb") as f:
            schema_hash = sha256_hex(f.read())
    else:
        schema_hash = "0" * 64

    # Simulated content
    dfars_question = "Does DFARS 252.204-7012 require us to report cyber incidents within 24 hours?"
    llm_draft = "Yes. DFARS 252.204-7012 requires contractors to report cyber incidents to the DoD within 24 hours of discovery. This is mandated under section 4(c) of the regulation, which specifies rapid reporting to DC3."
    # Note: The actual requirement is 72 hours, not 24. The agent hallucinated.

    steps = [
        {
            "step_id": "step-001",
            "parent_step_id": None,
            "timestamp_utc": ts(0),
            "type": "human_checkpoint",
            "summary": "Contracts specialist submitted DFARS clause inquiry to agent",
            "actor": "operator",
            "human_checkpoint": {
                "presented_artifact": make_data_ref("ref-question-preview", dfars_question, "full_text"),
                "presentation_mode": "full_output",
                "reviewer_action": "approved",
                "review_duration_ms": 2100,
            },
            "artifacts": {
                "inputs": [make_data_ref("ref-question", dfars_question, source_hint="User input")],
                "outputs": [],
                "classifications": [
                    {"tag": "PUBLIC", "confidence": 1.0, "method": "rule_based", "rule_id": "dfars-ref-public-001"}
                ],
            },
        },
        {
            "step_id": "step-002",
            "parent_step_id": "step-001",
            "timestamp_utc": ts(4),
            "type": "llm_call",
            "summary": "Called GPT-4 to draft DFARS clause interpretation",
            "actor": "agent",
            "model": {
                "provider": "OpenAI",
                "model_id": "gpt-4-turbo-2025-12-01",
                "region": "us-east-1",
            },
            "artifacts": {
                "inputs": [make_data_ref("ref-prompt", "Answer this DFARS question accurately, citing the specific clause: " + dfars_question, source_hint="Prompt template")],
                "outputs": [make_data_ref("ref-draft", llm_draft)],
                "classifications": [
                    {"tag": "PROPRIETARY", "confidence": 0.6, "method": "rule_based", "rule_id": "internal-analysis-tag-001"}
                ],
            },
            "metrics": {"latency_ms": 1800, "tokens_in": 320, "tokens_out": 185},
        },
        {
            "step_id": "step-003",
            "parent_step_id": "step-002",
            "timestamp_utc": ts(8),
            "type": "tool_call",
            "summary": "Ran factual cross-check against DFARS regulation database",
            "actor": "agent",
            "tool": {
                "tool_name": "dfars_reference_lookup",
                "tool_version": "2.0.1",
                "endpoint_hint": "internal:dfars-db/***",
                "permission_scope": "read_regulations",
            },
            "artifacts": {
                "inputs": [make_data_ref("ref-lookup-query", "DFARS 252.204-7012 reporting timeline")],
                "outputs": [make_data_ref("ref-lookup-result", "DFARS 252.204-7012(c): 72 hours, not 24 hours. Section reference: (c)(1).")],
                "classifications": [
                    {"tag": "PUBLIC", "confidence": 1.0, "method": "rule_based", "rule_id": "regulation-public-001"}
                ],
            },
            "metrics": {"latency_ms": 120},
        },
        {
            "step_id": "step-004",
            "parent_step_id": "step-003",
            "timestamp_utc": ts(10),
            "type": "guardrail_event",
            "summary": "WARNING: Factual inconsistency detected — LLM output contradicts regulation database",
            "actor": "system",
            "artifacts": {
                "inputs": [make_data_ref("ref-inconsistency-input", llm_draft + " vs 72 hours per DB")],
                "outputs": [],
                "classifications": [],
                "guardrails": [
                    {
                        "event_id": "gr-warn-001",
                        "timestamp_utc": ts(10),
                        "event_type": "warn",
                        "action": "warned",
                        "reason": "LLM stated 24-hour reporting requirement; regulation database confirms 72-hour requirement under DFARS 252.204-7012(c)(1). Possible hallucination.",
                        "policy_rule_id": "factual-consistency-check-001",
                        "attempted_action": "Present draft with unverified regulatory claim to human reviewer",
                        "target_resource_hint": "Agent output buffer",
                    }
                ],
            },
        },
        {
            "step_id": "step-005",
            "parent_step_id": "step-004",
            "timestamp_utc": ts(12),
            "type": "human_checkpoint",
            "summary": "REJECTED: Compliance lead rejected draft — incorrect reporting timeline (24h vs 72h)",
            "actor": "operator",
            "human_checkpoint": {
                "presented_artifact": make_data_ref(
                    "ref-review-draft", llm_draft + "\n\n[SYSTEM WARNING: Factual inconsistency detected. DB says 72 hours, draft says 24 hours.]",
                    "full_text",
                ),
                "presentation_mode": "full_output",
                "reviewer_action": "rejected",
                "review_duration_ms": 67000,
            },
            "artifacts": {
                "inputs": [make_data_ref("ref-draft-for-review", llm_draft)],
                "outputs": [],
                "classifications": [
                    {"tag": "PROPRIETARY", "confidence": 0.5, "method": "rule_based", "rule_id": "draft-internal-001"}
                ],
            },
        },
    ]

    # Hash chain
    ZERO = "0" * 64
    chain = []
    prev = ZERO
    for step in steps:
        h = sha256_hex(prev.encode() + canonical_json(step))
        chain.append({"step_id": step["step_id"], "hash": h, "prev_hash": prev})
        prev = h
    final_hash = prev

    sig_b64 = base64.b64encode(
        hmac_mod.new(SECRET_KEY, final_hash.encode(), hashlib.sha256).digest()
    ).decode()

    return {
        "receipt": {
            "receipt_id": receipt_id,
            "schema_version": SCHEMA_VERSION,
            "schema_hash": schema_hash,
            "created_at_utc": ts(14),
            "status": "active",
            "issuer": {
                "organization": "Apex Defense Solutions",
                "product": "NeoXFortress AAE",
                "build": {"version": "0.1.1-ref", "commit": "7afa8bb"},
            },
            "receipt_type": "agent_execution",
            "labels": ["DFARS", "COMPLIANCE", "REJECTED", "HALLUCINATION"],
        },
        "context": {
            "subject": {
                "agent": {
                    "agent_id": "agent-dfars-advisor-003",
                    "name": "DFARS Clause Advisor",
                    "type": "assistant",
                    "agent_version": "2.0.0",
                    "agent_code_hash": sha256_hex(b"dfars-advisor-v2.0.0-bundle"),
                    "framework": {"name": "custom", "version": "1.0.0"},
                    "purpose": "Answer DFARS clause interpretation questions for contracts team",
                    "owner_team": "AI Engineering",
                    "runtime": {"language": "python", "language_version": "3.11.8"},
                },
                "operator": {
                    "principal_id": "usr-akumar-0067",
                    "principal_type": "human_user",
                    "authn": {"idp": "Entra ID", "authn_method": "MFA", "session_id": "sess-" + uuid.uuid4().hex[:12]},
                    "role": "Contracts Specialist",
                },
                "sponsor": {
                    "principal_id": "usr-rliu-0023",
                    "principal_type": "human_user",
                    "role": "Compliance Lead",
                },
            },
            "environment": {
                "deployment_model": "self_hosted",
                "host": {
                    "hostname_hash": sha256_hex(b"apex-ai-workstation-05"),
                    "os": "Ubuntu 22.04 LTS",
                    "network_boundary": "Corp IT",
                    "ip_hash": sha256_hex(b"10.10.20.55"),
                },
                "clock": {"time_source": "NTP stratum 2", "skew_ms": 1},
                "deployment_fingerprint": {
                    "container_image_digest": "sha256:" + sha256_hex(b"apex-aae-runtime:0.1.1"),
                    "sbom_hash": sha256_hex(b"sbom-apex-aae-0.1.1.spdx"),
                    "dependency_lockfile_hash": sha256_hex(b"poetry.lock-frozen-2026-03-01"),
                },
            },
            "time_window": {"started_at_utc": ts(0), "ended_at_utc": ts(12)},
        },
        "policy": {
            "policy_id": "pol-apex-ai-governance",
            "policy_version": "2.1.0",
            "policy_hash": sha256_hex(b"apex-ai-governance-policy-v2.1.0"),
            "controls": {
                "logging_mode": "metadata_only",
                "content_capture": "none",
                "classification_mode": "rule_based",
                "human_approval_required": True,
                "tool_allowlist_enforced": True,
            },
        },
        "execution": {
            "run": {
                "run_id": run_id,
                "run_purpose": "Answer DFARS 252.204-7012 reporting timeline question",
                "status": "partial",
                "error_summary": "Human reviewer rejected agent draft due to factual error (hallucinated 24h vs actual 72h reporting requirement).",
                "inputs": [make_data_ref("ref-run-in", dfars_question, source_hint="User input")],
                "outputs": [],
            },
            "steps": steps,
        },
        "data_handling": {
            "storage": {"receipt_storage_location": "local_fs", "content_storage_location": "none", "byok": False},
            "retention": {
                "receipt_days": 365,
                "content_days": 0,
                "retention_enforcement": {"method": "automated_cron", "last_verified_utc": ts(-86400)},
            },
            "keys": {"signing_key_id": SIGNING_KEY_ID, "key_management": "local_kms"},
        },
        "integrity": {
            "canonicalization": {"method": "json_canonicalization_scheme", "notes": "JCS per RFC 8785."},
            "hash_chain": {"alg": "sha256", "chain": chain, "final_hash": final_hash},
            "signature": {
                "type": "hmac_sha256",
                "key_id": SIGNING_KEY_ID,
                "value": sig_b64,
                "signed_at_utc": ts(14),
                "signed_payload": "canonical_receipt_plus_final_hash",
                "encoding": "base64",
                "verification": {"procedure": "1. Canonicalize via JCS. 2. Concat with final_hash. 3. HMAC-SHA256 with key_id. 4. Compare base64. NOTE: Symmetric HMAC in v0.1.1."},
            },
        },
        "compliance": {
            "verdict": "review_required",
            "assessed_by": "engine_rule_set",
            "violated_controls": [],
            "risk_score": 4.0,
            "framework": "CMMC L2",
            "notes": "No policy violations detected. Human reviewer rejected output due to factual inaccuracy (hallucination). Agent correctly flagged inconsistency before human review. Review_required because rejected outputs should be assessed for systemic hallucination patterns.",
        },
        "cui_flow": [],
    }


if __name__ == "__main__":
    receipt = build_receipt()
    output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "human-checkpoint-rejected.json")
    with open(output, "w") as f:
        json.dump(receipt, f, indent=2)
    print(f"Written: {output}")

    sys_path = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, sys_path)
    import importlib
    gen = importlib.import_module("generate_receipt")

    print()
    gen.verify_hash_chain(receipt)
    gen.verify_signature(receipt)

    schema_path = os.path.join(sys_path, "..", "schema.json")
    from jsonschema import validate, ValidationError
    with open(schema_path) as f:
        schema = json.load(f)
    try:
        validate(instance=receipt, schema=schema)
        print("  PASS: Schema validation")
    except ValidationError as e:
        print(f"  FAIL: {e.message}")
        print(f"  Path: {'.'.join(str(p) for p in e.absolute_path)}")
