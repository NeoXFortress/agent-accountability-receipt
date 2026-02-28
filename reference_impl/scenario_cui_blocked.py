"""
Scenario: CUI Exfiltration Blocked
Agent attempts to send a CUI-marked document summary to an external
collaboration tool (Slack webhook). Guardrail detects CUI in the outbound
payload, blocks the action, and the run aborts. Receipt status: failed.

This demonstrates the schema handling a security-critical failure path.
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


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_data_ref(ref_id, content, representation="hash_only", **kwargs):
    ref = {
        "ref_id": ref_id,
        "representation": representation,
        "hash": sha256_hex(content.encode()),
        "hash_alg": "sha256",
    }
    for k in ("source_hint", "mime_type"):
        if k in kwargs:
            ref[k] = kwargs[k]
    if representation == "full_text":
        ref["content"] = content
    elif representation == "redacted_text":
        ref["content"] = content
        ref["content_redaction"] = {
            "method": kwargs.get("redaction_method", "regex"),
            "redaction_count": kwargs.get("redaction_count", 0),
        }
    return ref


def build_receipt():
    base_time = datetime(2026, 3, 4, 9, 30, 0, tzinfo=timezone.utc)
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
    contract_brief = "CONTRACT BRIEF: Classified satellite communications upgrade. CUI//SP-EXPT. Distribution limited to USG and cleared contractors."
    llm_summary = "Summary: The contract covers a satellite comms upgrade for DoD. Budget ceiling is $42M over 3 years. Requires TS/SCI clearance for lead engineers. Key deliverable dates in Q3 2026."
    slack_payload = json.dumps({"channel": "#bids", "text": llm_summary})

    steps = [
        {
            "step_id": "step-001",
            "parent_step_id": None,
            "timestamp_utc": ts(0),
            "type": "human_checkpoint",
            "summary": "Analyst uploaded classified contract brief for summarization",
            "actor": "operator",
            "human_checkpoint": {
                "presented_artifact": make_data_ref(
                    "ref-upload", "contract-brief-satcom-2026.pdf",
                    "full_text", source_hint="Local file"
                ),
                "presentation_mode": "summary",
                "reviewer_action": "approved",
                "review_duration_ms": 3100,
            },
            "artifacts": {
                "inputs": [
                    make_data_ref("ref-contract", contract_brief,
                                  source_hint="Local file", mime_type="application/pdf")
                ],
                "outputs": [],
                "classifications": [
                    {"tag": "CUI_SPECIFIED", "confidence": 1.0, "method": "rule_based",
                     "rule_id": "cui-sp-header-001", "notes": "CUI//SP-EXPT marking detected in header"}
                ],
            },
        },
        {
            "step_id": "step-002",
            "parent_step_id": "step-001",
            "timestamp_utc": ts(3),
            "type": "llm_call",
            "summary": "Called Claude to summarize classified contract brief",
            "actor": "agent",
            "model": {
                "provider": "Anthropic",
                "model_id": "claude-sonnet-4-5-20250929",
                "region": "us-east-1",
            },
            "artifacts": {
                "inputs": [make_data_ref("ref-prompt", "Summarize this contract brief for the BD team.", source_hint="Prompt template")],
                "outputs": [make_data_ref("ref-llm-out", llm_summary)],
                "classifications": [
                    {"tag": "CUI_SPECIFIED", "confidence": 0.92, "method": "rule_based",
                     "rule_id": "cui-keyword-budget-clearance-004"}
                ],
            },
            "metrics": {"latency_ms": 2800, "tokens_in": 4200, "tokens_out": 890},
        },
        {
            "step_id": "step-003",
            "parent_step_id": "step-002",
            "timestamp_utc": ts(7),
            "type": "guardrail_event",
            "summary": "BLOCKED: Agent attempted to send CUI summary to external Slack webhook",
            "actor": "system",
            "artifacts": {
                "inputs": [make_data_ref("ref-slack-payload", slack_payload)],
                "outputs": [],
                "classifications": [
                    {"tag": "CUI_SPECIFIED", "confidence": 1.0, "method": "rule_based",
                     "rule_id": "cui-exfil-detect-001"}
                ],
                "guardrails": [
                    {
                        "event_id": "gr-block-001",
                        "timestamp_utc": ts(7),
                        "event_type": "block",
                        "action": "blocked",
                        "reason": "CUI//SP-EXPT content detected in outbound payload to external endpoint. Transmission blocked per policy pol-apex-data-boundary v3.0.",
                        "policy_rule_id": "cui-exfil-block-001",
                        "attempted_action": "POST CUI-containing JSON payload to Slack webhook (external SaaS)",
                        "target_resource_hint": "Slack:webhook/T0****/B0****/****",
                    }
                ],
            },
            "error": {
                "code": "CUI_BOUNDARY_VIOLATION",
                "message": "Agent attempted to transmit CUI data across boundary to external SaaS endpoint. Action blocked by guardrail.",
                "recoverable": False,
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
            "created_at_utc": ts(8),
            "status": "active",
            "issuer": {
                "organization": "Apex Defense Solutions",
                "product": "NeoXFortress AAE",
                "build": {"version": "0.1.1-ref", "commit": "7afa8bb"},
            },
            "receipt_type": "agent_execution",
            "labels": ["CMMC", "CUI", "INCIDENT", "BLOCKED"],
        },
        "context": {
            "subject": {
                "agent": {
                    "agent_id": "agent-contract-summarizer-002",
                    "name": "Contract Brief Summarizer",
                    "type": "assistant",
                    "agent_version": "1.1.0",
                    "agent_code_hash": sha256_hex(b"contract-summarizer-v1.1.0-bundle"),
                    "framework": {"name": "custom", "version": "1.0.0"},
                    "purpose": "Summarize contract briefs for BD team review",
                    "owner_team": "AI Engineering",
                    "runtime": {"language": "python", "language_version": "3.11.8"},
                },
                "operator": {
                    "principal_id": "usr-tchen-0091",
                    "principal_type": "human_user",
                    "authn": {
                        "idp": "Entra ID",
                        "authn_method": "MFA",
                        "session_id": "sess-" + uuid.uuid4().hex[:12],
                    },
                    "role": "Business Development Analyst",
                },
            },
            "environment": {
                "deployment_model": "self_hosted",
                "host": {
                    "hostname_hash": sha256_hex(b"apex-ai-workstation-03"),
                    "os": "Ubuntu 22.04 LTS",
                    "network_boundary": "CUI enclave",
                    "ip_hash": sha256_hex(b"10.10.42.103"),
                },
                "clock": {"time_source": "NTP stratum 2", "skew_ms": 2},
                "deployment_fingerprint": {
                    "container_image_digest": "sha256:" + sha256_hex(b"apex-aae-runtime:0.1.1"),
                    "sbom_hash": sha256_hex(b"sbom-apex-aae-0.1.1.spdx"),
                    "dependency_lockfile_hash": sha256_hex(b"poetry.lock-frozen-2026-03-01"),
                },
            },
            "time_window": {"started_at_utc": ts(0), "ended_at_utc": ts(7)},
            "case": {"case_id": "SEC-2026-0087", "case_system": "ServiceNow"},
        },
        "policy": {
            "policy_id": "pol-apex-data-boundary",
            "policy_version": "3.0.0",
            "policy_hash": sha256_hex(b"apex-data-boundary-policy-v3.0.0"),
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
                "run_purpose": "Summarize contract brief for BD team Slack channel",
                "status": "failed",
                "error_summary": "CUI boundary violation: agent attempted to exfiltrate CUI data to external SaaS. Blocked by guardrail.",
                "inputs": [
                    make_data_ref("ref-run-in", contract_brief, source_hint="Local file", mime_type="application/pdf")
                ],
                "outputs": [],
            },
            "steps": steps,
        },
        "data_handling": {
            "storage": {
                "receipt_storage_location": "local_fs",
                "content_storage_location": "none",
                "byok": False,
            },
            "retention": {
                "receipt_days": 730,
                "content_days": 0,
                "retention_enforcement": {
                    "method": "automated_cron",
                    "last_verified_utc": ts(-86400),
                },
            },
            "keys": {"signing_key_id": SIGNING_KEY_ID, "key_management": "local_kms"},
        },
        "integrity": {
            "canonicalization": {
                "method": "json_canonicalization_scheme",
                "notes": "JCS per RFC 8785.",
            },
            "hash_chain": {"alg": "sha256", "chain": chain, "final_hash": final_hash},
            "signature": {
                "type": "hmac_sha256",
                "key_id": SIGNING_KEY_ID,
                "value": sig_b64,
                "signed_at_utc": ts(8),
                "signed_payload": "canonical_receipt_plus_final_hash",
                "encoding": "base64",
                "verification": {
                    "procedure": "1. Canonicalize via JCS. 2. Concat with final_hash. 3. HMAC-SHA256 with key_id. 4. Compare base64. NOTE: Symmetric HMAC in v0.1.1."
                },
            },
        },
        "compliance": {
            "verdict": "non_compliant",
            "assessed_by": "engine_rule_set",
            "violated_controls": ["SC.L2-3.13.1", "SC.L2-3.13.2"],
            "risk_score": 8.5,
            "framework": "CMMC L2",
            "notes": "Agent attempted CUI exfiltration to external SaaS. Blocked by guardrail. No data left the enclave. Incident logged for review.",
        },
        "cui_flow": [
            {
                "direction": "in",
                "boundary": "Local file system (CUI enclave) to agent memory",
                "data_hash": sha256_hex(contract_brief.encode()),
                "classification": "CUI_SPECIFIED",
                "redacted": False,
                "step_ids": ["step-001"],
                "timestamp_utc": ts(0),
                "policy_rule_id": "cui-ingest-allow-001",
            },
            {
                "direction": "out",
                "boundary": "Agent memory to Anthropic API (external)",
                "data_hash": sha256_hex(llm_summary.encode()),
                "classification": "CUI_SPECIFIED",
                "redacted": False,
                "step_ids": ["step-002"],
                "timestamp_utc": ts(3),
                "policy_rule_id": "cui-llm-transit-002",
            },
            {
                "direction": "out",
                "boundary": "BLOCKED: Agent memory to Slack webhook (external SaaS)",
                "data_hash": sha256_hex(slack_payload.encode()),
                "classification": "CUI_SPECIFIED",
                "redacted": False,
                "step_ids": ["step-003"],
                "timestamp_utc": ts(7),
                "policy_rule_id": "cui-exfil-block-001",
            },
        ],
    }


if __name__ == "__main__":
    receipt = build_receipt()
    output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "cui-exfiltration-blocked.json")
    with open(output, "w") as f:
        json.dump(receipt, f, indent=2)
    print(f"Written: {output}")

    # Validate
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
