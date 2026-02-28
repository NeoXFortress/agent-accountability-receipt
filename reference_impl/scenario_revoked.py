"""
Scenario: Receipt Revocation After Key Compromise
A receipt was generated and signed normally. Three days later, the security
team discovers the HMAC signing key was exposed in a misconfigured backup.
The receipt is revoked with full attribution: who revoked it, when, and why.
A new receipt (superseding) is referenced.

This demonstrates receipt lifecycle management — the schema's ability to
invalidate previously-trusted evidence.
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
    # Original execution happened March 1
    exec_time = datetime(2026, 3, 1, 10, 0, 0, tzinfo=timezone.utc)
    # Key compromise discovered March 4
    revoke_time = datetime(2026, 3, 4, 16, 45, 0, tzinfo=timezone.utc)

    receipt_id = "019536a1-7c4e-7000-8000-" + uuid.uuid4().hex[:12]
    superseding_receipt_id = "019539f2-8d5f-7000-8000-" + uuid.uuid4().hex[:12]
    run_id = str(uuid.uuid4())

    def ts(base, offset=0):
        return (base + timedelta(seconds=offset)).isoformat()

    schema_path = os.path.join(os.path.dirname(__file__), "..", "schema.json")
    if os.path.exists(schema_path):
        with open(schema_path, "rb") as f:
            schema_hash = sha256_hex(f.read())
    else:
        schema_hash = "0" * 64

    # Simulated content — a normal, successful run
    task_input = "Generate weekly security posture report from SIEM data for ISSO review."
    siem_summary = "Weekly SIEM Summary (Feb 24-28): 12,847 events processed. 3 medium-severity alerts (resolved). 0 critical. Mean detection time: 4.2min. All endpoints compliant."

    steps = [
        {
            "step_id": "step-001",
            "parent_step_id": None,
            "timestamp_utc": ts(exec_time, 0),
            "type": "tool_call",
            "summary": "Queried SIEM API for weekly event summary",
            "actor": "agent",
            "tool": {
                "tool_name": "siem_query",
                "tool_version": "3.1.0",
                "endpoint_hint": "internal:siem-api/***",
                "permission_scope": "read_events_summary",
            },
            "artifacts": {
                "inputs": [make_data_ref("ref-siem-query", "GET /api/v2/events/summary?range=7d", source_hint="SIEM API")],
                "outputs": [make_data_ref("ref-siem-data", siem_summary)],
                "classifications": [
                    {"tag": "PROPRIETARY", "confidence": 1.0, "method": "rule_based", "rule_id": "siem-data-proprietary-001"}
                ],
            },
            "metrics": {"latency_ms": 890},
        },
        {
            "step_id": "step-002",
            "parent_step_id": "step-001",
            "timestamp_utc": ts(exec_time, 5),
            "type": "llm_call",
            "summary": "Called Claude to draft weekly security posture report",
            "actor": "agent",
            "model": {
                "provider": "Anthropic",
                "model_id": "claude-sonnet-4-5-20250929",
                "region": "us-east-1",
            },
            "artifacts": {
                "inputs": [make_data_ref("ref-prompt", "Draft a weekly security posture report from this SIEM data for ISSO review: " + siem_summary, source_hint="Prompt template")],
                "outputs": [make_data_ref("ref-report-draft", "Weekly Security Posture Report: All systems nominal. 3 medium alerts resolved within SLA. Recommendation: no escalation needed.")],
                "classifications": [
                    {"tag": "PROPRIETARY", "confidence": 1.0, "method": "rule_based", "rule_id": "security-report-proprietary-001"}
                ],
            },
            "metrics": {"latency_ms": 2100, "tokens_in": 1200, "tokens_out": 340},
        },
        {
            "step_id": "step-003",
            "parent_step_id": "step-002",
            "timestamp_utc": ts(exec_time, 10),
            "type": "human_checkpoint",
            "summary": "ISSO reviewed and approved weekly security posture report",
            "actor": "operator",
            "human_checkpoint": {
                "presented_artifact": make_data_ref("ref-report-for-review", "Weekly Security Posture Report: All systems nominal...", "full_text"),
                "presentation_mode": "full_output",
                "reviewer_action": "approved",
                "review_duration_ms": 120000,
            },
            "artifacts": {
                "inputs": [make_data_ref("ref-draft-in", "Weekly Security Posture Report draft")],
                "outputs": [make_data_ref("ref-approved-report", "Weekly Security Posture Report: All systems nominal. Approved by ISSO.", source_hint="Output file")],
                "classifications": [
                    {"tag": "PROPRIETARY", "confidence": 1.0, "method": "rule_based", "rule_id": "approved-report-001"}
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
            "created_at_utc": ts(exec_time, 12),
            "status": "revoked",
            "revocation_reason": "HMAC signing key (demo-key-001) was exposed in a misconfigured S3 backup discovered on 2026-03-04. All receipts signed with this key between 2026-02-15 and 2026-03-04 are revoked. A replacement receipt has been generated with a new signing key.",
            "revoked_at_utc": ts(revoke_time, 0),
            "revoked_by": {
                "principal_id": "usr-dpark-0005",
                "principal_type": "human_user",
                "role": "Chief Information Security Officer",
            },
            "superseded_by": superseding_receipt_id,
            "issuer": {
                "organization": "Apex Defense Solutions",
                "product": "NeoXFortress AAE",
                "build": {"version": "0.1.1-ref", "commit": "7afa8bb"},
            },
            "receipt_type": "agent_execution",
            "related_receipts": [
                {
                    "receipt_id": superseding_receipt_id,
                    "relationship": "supersedes",
                    "description": "Replacement receipt generated with rotated signing key (key-002) after key compromise incident SEC-2026-0091.",
                }
            ],
            "labels": ["REVOKED", "KEY-COMPROMISE", "SECURITY-INCIDENT"],
        },
        "context": {
            "subject": {
                "agent": {
                    "agent_id": "agent-security-reporter-004",
                    "name": "Weekly Security Posture Reporter",
                    "type": "workflow",
                    "agent_version": "1.3.0",
                    "agent_code_hash": sha256_hex(b"security-reporter-v1.3.0-bundle"),
                    "framework": {"name": "custom", "version": "1.0.0"},
                    "purpose": "Generate weekly security posture reports from SIEM data for ISSO review",
                    "owner_team": "Security Operations",
                    "runtime": {"language": "python", "language_version": "3.11.8"},
                },
                "operator": {
                    "principal_id": "svc-secops-reporter",
                    "principal_type": "service_account",
                    "role": "Automated Security Reporting",
                },
            },
            "environment": {
                "deployment_model": "self_hosted",
                "host": {
                    "hostname_hash": sha256_hex(b"apex-secops-server-01"),
                    "os": "Ubuntu 22.04 LTS",
                    "network_boundary": "Corp IT",
                    "ip_hash": sha256_hex(b"10.10.30.10"),
                },
                "clock": {"time_source": "NTP stratum 2", "skew_ms": 1},
                "deployment_fingerprint": {
                    "container_image_digest": "sha256:" + sha256_hex(b"apex-aae-runtime:0.1.1"),
                    "sbom_hash": sha256_hex(b"sbom-apex-aae-0.1.1.spdx"),
                    "dependency_lockfile_hash": sha256_hex(b"poetry.lock-frozen-2026-02-28"),
                },
            },
            "time_window": {"started_at_utc": ts(exec_time, 0), "ended_at_utc": ts(exec_time, 10)},
            "case": {"case_id": "SEC-2026-0091", "case_system": "ServiceNow"},
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
                "run_purpose": "Generate weekly security posture report (Feb 24-28, 2026)",
                "status": "success",
                "inputs": [make_data_ref("ref-run-in", task_input, source_hint="Scheduled task")],
                "outputs": [make_data_ref("ref-run-out", "Weekly Security Posture Report: Approved.", source_hint="Output file")],
            },
            "steps": steps,
        },
        "data_handling": {
            "storage": {"receipt_storage_location": "local_fs", "content_storage_location": "none", "byok": False},
            "retention": {
                "receipt_days": 365,
                "content_days": 0,
                "retention_enforcement": {"method": "automated_cron", "last_verified_utc": ts(exec_time, -86400)},
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
                "signed_at_utc": ts(exec_time, 12),
                "signed_payload": "canonical_receipt_plus_final_hash",
                "encoding": "base64",
                "verification": {
                    "procedure": "WARNING: This receipt has been REVOKED. The signing key (demo-key-001) was compromised. Do NOT trust this signature. See superseding receipt " + superseding_receipt_id + " for the re-signed version. Original verification: 1. Canonicalize via JCS. 2. Concat with final_hash. 3. HMAC-SHA256 with key_id. 4. Compare base64."
                },
            },
            "attestations": [
                {
                    "attester": {
                        "principal_id": "usr-dpark-0005",
                        "principal_type": "human_user",
                        "role": "Chief Information Security Officer",
                    },
                    "attested_at_utc": ts(revoke_time, 0),
                    "statement": "I am revoking this receipt and all receipts signed with key demo-key-001 between 2026-02-15 and 2026-03-04 due to key exposure in misconfigured S3 backup. Incident SEC-2026-0091. Replacement receipts are being generated with rotated key.",
                }
            ],
        },
        "compliance": {
            "verdict": "review_required",
            "assessed_by": "human_reviewer",
            "assessor_id": "usr-dpark-0005",
            "violated_controls": ["SC.L2-3.13.10"],
            "risk_score": 6.0,
            "framework": "CMMC L2",
            "notes": "Original execution was compliant. Receipt revoked due to post-hoc signing key compromise (not an execution-time violation). SC.L2-3.13.10 (key management) cited because the key exposure represents a cryptographic material handling failure. The execution itself is not in question — only the integrity of the signature.",
        },
        "cui_flow": [],
    }


if __name__ == "__main__":
    receipt = build_receipt()
    output = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "examples", "receipt-revoked.json")
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
