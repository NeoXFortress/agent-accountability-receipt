"""
Agent Accountability Receipt — Reference Implementation
Generates a schema-compliant, hash-chained, HMAC-signed demo receipt.

This is a reference generator for demonstration and validation purposes.
The commercial NeoXFortress AAE SDK is a separate proprietary product.

Copyright (c) 2026 Julio Berroa / NeoXFortress LLC
"""

import json
import hashlib
import hmac as hmac_mod
import uuid
import os
import base64
from datetime import datetime, timezone, timedelta


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# In production: load from KMS / env / HSM. Never hardcode.
SECRET_KEY = os.environ.get(
    "AAR_SIGNING_KEY", "demo-secret-key-do-not-use-in-production"
).encode()
SIGNING_KEY_ID = os.environ.get("AAR_SIGNING_KEY_ID", "demo-key-001")
SCHEMA_VERSION = "0.1.1"


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def canonical_json(data: dict) -> bytes:
    """JCS-like canonicalization: sorted keys, no whitespace."""
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    """Returns lowercase hex SHA-256 digest (64 chars)."""
    return hashlib.sha256(data).hexdigest()


def make_data_ref(
    ref_id: str,
    content: str,
    representation: str = "hash_only",
    source_hint: str = None,
    mime_type: str = None,
    redaction_method: str = None,
    redaction_count: int = None,
) -> dict:
    """Build a schema-compliant data_ref object."""
    content_bytes = content.encode("utf-8")
    ref = {
        "ref_id": ref_id,
        "representation": representation,
        "hash": sha256_hex(content_bytes),
        "hash_alg": "sha256",
    }
    if source_hint:
        ref["source_hint"] = source_hint
    if mime_type:
        ref["mime_type"] = mime_type
    if representation == "full_text":
        ref["content"] = content
    elif representation == "redacted_text":
        ref["content"] = content
        ref["content_redaction"] = {
            "method": redaction_method or "regex",
            "redaction_count": redaction_count or 0,
        }
    return ref


# ---------------------------------------------------------------------------
# Demo scenario builder
# ---------------------------------------------------------------------------

def build_demo_receipt() -> dict:
    """
    Scenario: A 200-person defense contractor's internal AI agent summarizes
    an RFP document. The agent reads the PDF, calls an LLM to summarize,
    extracts key requirements, hits a guardrail on a CUI paragraph, gets
    human approval, and outputs a structured summary.
    """

    base_time = datetime(2026, 2, 27, 14, 0, 0, tzinfo=timezone.utc)
    receipt_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())

    def ts(offset_seconds: int) -> str:
        return (base_time + timedelta(seconds=offset_seconds)).isoformat()

    # Compute schema hash from the actual schema file
    schema_path = os.path.join(os.path.dirname(__file__), "..", "schema.json")
    if os.path.exists(schema_path):
        with open(schema_path, "rb") as f:
            schema_hash = sha256_hex(f.read())
    else:
        schema_hash = "0" * 64

    # --- Simulated content for hashing ---
    rfp_document = (
        "REQUEST FOR PROPOSAL: Cloud Migration Services for DoD Program "
        "Office X. CUI content follows..."
    )
    llm_prompt = (
        "Summarize the following RFP document for internal review. Focus on "
        "key requirements, deadlines, and evaluation criteria."
    )
    llm_output = (
        "The RFP requests cloud migration services for a DoD program office. "
        "Key requirements include FedRAMP High authorization, CMMC Level 2 "
        "compliance, and 99.99% uptime SLA. Proposal deadline is April 15, 2026."
    )
    extracted_reqs = json.dumps(
        {
            "requirements_count": 12,
            "categories": ["security", "performance", "compliance", "timeline"],
        }
    )
    final_summary = (
        "Structured summary: 12 requirements across 4 categories. "
        "Primary compliance: CMMC L2 + FedRAMP High. Deadline: 2026-04-15."
    )

    # --- Build steps ---
    steps = [
        {
            "step_id": "step-001",
            "parent_step_id": None,
            "timestamp_utc": ts(0),
            "type": "human_checkpoint",
            "summary": "Operator uploaded RFP document for agent processing",
            "actor": "operator",
            "human_checkpoint": {
                "presented_artifact": make_data_ref(
                    "ref-upload-preview",
                    "RFP filename: cloud-migration-rfp-2026.pdf (142 pages)",
                    "full_text",
                    source_hint="Local file",
                ),
                "presentation_mode": "summary",
                "reviewer_action": "approved",
                "review_duration_ms": 4200,
            },
            "artifacts": {
                "inputs": [
                    make_data_ref(
                        "ref-rfp-doc",
                        rfp_document,
                        source_hint="Local file",
                        mime_type="application/pdf",
                    )
                ],
                "outputs": [],
                "classifications": [
                    {
                        "tag": "CUI",
                        "confidence": 1.0,
                        "method": "rule_based",
                        "rule_id": "cui-header-detect-001",
                        "notes": "Document header contains CUI marking",
                    }
                ],
            },
        },
        {
            "step_id": "step-002",
            "parent_step_id": "step-001",
            "timestamp_utc": ts(5),
            "type": "llm_call",
            "summary": "Called GPT-4 to summarize RFP document",
            "actor": "agent",
            "model": {
                "provider": "OpenAI",
                "model_id": "gpt-4-turbo-2025-12-01",
                "region": "us-east-1",
            },
            "artifacts": {
                "inputs": [
                    make_data_ref(
                        "ref-prompt", llm_prompt, source_hint="Agent prompt template"
                    )
                ],
                "outputs": [make_data_ref("ref-llm-output", llm_output)],
                "classifications": [
                    {
                        "tag": "CUI",
                        "confidence": 0.85,
                        "method": "rule_based",
                        "rule_id": "cui-keyword-scan-003",
                    }
                ],
            },
            "metrics": {"latency_ms": 3200, "tokens_in": 8450, "tokens_out": 1240},
        },
        {
            "step_id": "step-003",
            "parent_step_id": "step-002",
            "timestamp_utc": ts(9),
            "type": "tool_call",
            "summary": "Extracted structured requirements from LLM output",
            "actor": "agent",
            "tool": {
                "tool_name": "requirement_extractor",
                "tool_version": "1.2.0",
                "permission_scope": "read_llm_output",
            },
            "artifacts": {
                "inputs": [
                    make_data_ref("ref-llm-output-for-extract", llm_output)
                ],
                "outputs": [make_data_ref("ref-extracted-reqs", extracted_reqs)],
                "classifications": [
                    {
                        "tag": "PROPRIETARY",
                        "confidence": 1.0,
                        "method": "rule_based",
                        "rule_id": "internal-analysis-tag-001",
                    }
                ],
            },
            "metrics": {"latency_ms": 450},
        },
        {
            "step_id": "step-004",
            "parent_step_id": "step-003",
            "timestamp_utc": ts(10),
            "type": "guardrail_event",
            "summary": "CUI content detected in agent output — redaction applied",
            "actor": "system",
            "artifacts": {
                "inputs": [make_data_ref("ref-guardrail-input", llm_output)],
                "outputs": [
                    make_data_ref(
                        "ref-guardrail-output",
                        "[REDACTED: CUI paragraph removed] " + llm_output[:50],
                        "redacted_text",
                        redaction_method="regex_cui_pattern",
                        redaction_count=2,
                    )
                ],
                "classifications": [
                    {
                        "tag": "CUI",
                        "confidence": 1.0,
                        "method": "rule_based",
                        "rule_id": "cui-boundary-check-007",
                    }
                ],
                "guardrails": [
                    {
                        "event_id": "gr-001",
                        "timestamp_utc": ts(10),
                        "event_type": "redaction",
                        "action": "redacted",
                        "reason": "CUI content detected in output destined for non-CUI system",
                        "policy_rule_id": "cui-boundary-check-007",
                        "attempted_action": "Write summary containing CUI to internal wiki (non-CUI)",
                        "target_resource_hint": "Wiki:internal/rfp-summaries/***",
                    }
                ],
            },
        },
        {
            "step_id": "step-005",
            "parent_step_id": "step-004",
            "timestamp_utc": ts(15),
            "type": "human_checkpoint",
            "summary": "Compliance lead reviewed redacted summary before distribution",
            "actor": "operator",
            "human_checkpoint": {
                "presented_artifact": make_data_ref(
                    "ref-review-artifact",
                    "[Redacted summary presented to reviewer]",
                    "redacted_text",
                    redaction_method="regex_cui_pattern",
                    redaction_count=2,
                ),
                "presentation_mode": "redacted",
                "reviewer_action": "approved",
                "review_duration_ms": 45000,
            },
            "artifacts": {
                "inputs": [
                    make_data_ref(
                        "ref-redacted-for-review", "[REDACTED] " + final_summary
                    )
                ],
                "outputs": [make_data_ref("ref-approved-summary", final_summary)],
                "classifications": [
                    {
                        "tag": "PROPRIETARY",
                        "confidence": 1.0,
                        "method": "rule_based",
                        "rule_id": "post-redaction-reclass-001",
                        "notes": "Reclassified after CUI redaction",
                    }
                ],
            },
        },
        {
            "step_id": "step-006",
            "parent_step_id": "step-005",
            "timestamp_utc": ts(20),
            "type": "decision",
            "summary": "Agent finalized structured summary for distribution",
            "actor": "agent",
            "artifacts": {
                "inputs": [make_data_ref("ref-final-input", final_summary)],
                "outputs": [
                    make_data_ref(
                        "ref-final-output", final_summary, source_hint="Output file"
                    )
                ],
                "classifications": [
                    {
                        "tag": "PROPRIETARY",
                        "confidence": 1.0,
                        "method": "rule_based",
                        "rule_id": "output-class-001",
                    }
                ],
            },
        },
    ]

    # --- Build hash chain ---
    ZERO_HASH = "0" * 64
    hash_chain = []
    prev_hash = ZERO_HASH

    for step in steps:
        step_canonical = canonical_json(step)
        combined = prev_hash.encode() + step_canonical
        current_hash = sha256_hex(combined)
        hash_chain.append(
            {"step_id": step["step_id"], "hash": current_hash, "prev_hash": prev_hash}
        )
        prev_hash = current_hash

    final_hash = prev_hash

    # --- HMAC signature ---
    sig_bytes = hmac_mod.new(SECRET_KEY, final_hash.encode(), hashlib.sha256).digest()
    sig_b64 = base64.b64encode(sig_bytes).decode()
    sign_time = ts(22)

    # --- Assemble receipt ---
    receipt = {
        "receipt": {
            "receipt_id": receipt_id,
            "schema_version": SCHEMA_VERSION,
            "schema_hash": schema_hash,
            "created_at_utc": ts(22),
            "status": "active",
            "issuer": {
                "organization": "Apex Defense Solutions",
                "product": "NeoXFortress AAE",
                "build": {"version": "0.1.1-ref", "commit": "d5ec6e5"},
            },
            "receipt_type": "agent_execution",
            "labels": ["CMMC", "RFP", "CUI"],
        },
        "context": {
            "subject": {
                "agent": {
                    "agent_id": "agent-rfp-summarizer-001",
                    "name": "RFP Summarization Agent",
                    "type": "assistant",
                    "agent_version": "1.0.0",
                    "agent_code_hash": sha256_hex(
                        b"rfp-summarizer-v1.0.0-config-bundle"
                    ),
                    "framework": {"name": "custom", "version": "1.0.0"},
                    "purpose": "Summarize RFP documents for internal bid/no-bid review",
                    "owner_team": "AI Engineering",
                    "runtime": {"language": "python", "language_version": "3.11.8"},
                },
                "operator": {
                    "principal_id": "usr-jsmith-0042",
                    "principal_type": "human_user",
                    "authn": {
                        "idp": "Entra ID",
                        "authn_method": "MFA",
                        "session_id": "sess-" + uuid.uuid4().hex[:12],
                    },
                    "role": "Senior Contracts Analyst",
                },
                "sponsor": {
                    "principal_id": "usr-mwilliams-0018",
                    "principal_type": "human_user",
                    "role": "Director of Business Development",
                },
            },
            "environment": {
                "deployment_model": "self_hosted",
                "host": {
                    "hostname_hash": sha256_hex(b"apex-ai-workstation-07"),
                    "os": "Ubuntu 22.04 LTS",
                    "network_boundary": "CUI enclave",
                    "ip_hash": sha256_hex(b"10.10.42.107"),
                },
                "clock": {
                    "time_source": "NTP stratum 2 (time.nist.gov)",
                    "skew_ms": 3,
                },
                "deployment_fingerprint": {
                    "container_image_digest": "sha256:"
                    + sha256_hex(b"apex-aae-runtime:0.1.1"),
                    "sbom_hash": sha256_hex(b"sbom-apex-aae-0.1.1.spdx"),
                    "dependency_lockfile_hash": sha256_hex(
                        b"poetry.lock-frozen-2026-02-27"
                    ),
                },
            },
            "time_window": {
                "started_at_utc": ts(0),
                "ended_at_utc": ts(20),
            },
            "case": {"case_id": "BD-2026-0142", "case_system": "Jira"},
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
            "approvals": [
                {
                    "approval_id": "appr-001",
                    "approved_at_utc": ts(-3600),
                    "approver": {
                        "principal_id": "usr-mwilliams-0018",
                        "principal_type": "human_user",
                        "role": "Director of Business Development",
                    },
                    "scope": "Process RFP BD-2026-0142 through AI summarization pipeline",
                    "decision": "approved",
                    "notes": "Approved for internal bid/no-bid analysis only.",
                }
            ],
        },
        "execution": {
            "run": {
                "run_id": run_id,
                "run_purpose": "Summarize RFP for internal bid/no-bid decision (BD-2026-0142)",
                "status": "success",
                "inputs": [
                    make_data_ref(
                        "ref-run-input",
                        rfp_document,
                        source_hint="Local file",
                        mime_type="application/pdf",
                    )
                ],
                "outputs": [
                    make_data_ref(
                        "ref-run-output", final_summary, source_hint="Output file"
                    )
                ],
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
                "receipt_days": 365,
                "content_days": 0,
                "retention_enforcement": {
                    "method": "automated_cron",
                    "last_verified_utc": ts(-86400),
                },
            },
            "keys": {
                "signing_key_id": SIGNING_KEY_ID,
                "key_management": "local_kms",
            },
        },
        "integrity": {
            "canonicalization": {
                "method": "json_canonicalization_scheme",
                "notes": "JCS per RFC 8785. Sorted keys, no whitespace, ASCII-safe.",
            },
            "hash_chain": {
                "alg": "sha256",
                "chain": hash_chain,
                "final_hash": final_hash,
            },
            "signature": {
                "type": "hmac_sha256",
                "key_id": SIGNING_KEY_ID,
                "value": sig_b64,
                "signed_at_utc": sign_time,
                "signed_payload": "canonical_receipt_plus_final_hash",
                "encoding": "base64",
                "verification": {
                    "procedure": (
                        "1. Canonicalize receipt JSON using JCS (RFC 8785). "
                        "2. Concatenate canonical bytes with final_hash string. "
                        "3. Compute HMAC-SHA256 using key identified by key_id. "
                        "4. Compare with base64-decoded signature value. "
                        "NOTE: v0.1.1 uses symmetric HMAC. Both signer and "
                        "verifier share the key, limiting non-repudiation. "
                        "Asymmetric signatures planned for v0.2."
                    )
                },
            },
        },
        "compliance": {
            "verdict": "compliant",
            "assessed_by": "engine_rule_set",
            "violated_controls": [],
            "risk_score": 1.5,
            "framework": "CMMC L2",
            "notes": (
                "CUI detected and properly redacted before boundary crossing. "
                "Human checkpoint completed with adequate review time. "
                "All steps within policy."
            ),
        },
        "cui_flow": [
            {
                "direction": "in",
                "boundary": "Local file system (CUI enclave) to agent memory",
                "data_hash": sha256_hex(rfp_document.encode()),
                "classification": "CUI",
                "redacted": False,
                "step_ids": ["step-001"],
                "timestamp_utc": ts(0),
                "policy_rule_id": "cui-ingest-allow-001",
            },
            {
                "direction": "out",
                "boundary": "Agent memory to OpenAI API (external)",
                "data_hash": sha256_hex(llm_prompt.encode()),
                "classification": "CUI",
                "redacted": False,
                "step_ids": ["step-002"],
                "timestamp_utc": ts(5),
                "policy_rule_id": "cui-llm-transit-002",
            },
            {
                "direction": "out",
                "boundary": "Agent output to internal wiki (non-CUI system)",
                "data_hash": sha256_hex(final_summary.encode()),
                "classification": "PROPRIETARY",
                "redacted": True,
                "redaction_method": "regex_cui_pattern",
                "step_ids": ["step-004", "step-005"],
                "timestamp_utc": ts(15),
                "policy_rule_id": "cui-boundary-check-007",
            },
        ],
    }

    return receipt


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def verify_hash_chain(receipt: dict) -> bool:
    """Verify the hash chain is internally consistent."""
    chain = receipt["integrity"]["hash_chain"]["chain"]
    steps = receipt["execution"]["steps"]

    if len(chain) != len(steps):
        print(f"  FAIL: Chain length ({len(chain)}) != step count ({len(steps)})")
        return False

    prev_hash = "0" * 64
    for i, (entry, step) in enumerate(zip(chain, steps)):
        if entry["prev_hash"] != prev_hash:
            print(f"  FAIL: Step {i} prev_hash mismatch")
            return False
        expected = sha256_hex(prev_hash.encode() + canonical_json(step))
        if entry["hash"] != expected:
            print(f"  FAIL: Step {i} hash mismatch")
            return False
        prev_hash = entry["hash"]

    if prev_hash != receipt["integrity"]["hash_chain"]["final_hash"]:
        print("  FAIL: Final hash mismatch")
        return False

    print(f"  PASS: Hash chain verified ({len(chain)} steps)")
    return True


def verify_signature(receipt: dict, key: bytes = SECRET_KEY) -> bool:
    """Verify the HMAC signature."""
    final_hash = receipt["integrity"]["hash_chain"]["final_hash"]
    stored_sig = receipt["integrity"]["signature"]["value"]
    expected = base64.b64encode(
        hmac_mod.new(key, final_hash.encode(), hashlib.sha256).digest()
    ).decode()

    if hmac_mod.compare_digest(stored_sig, expected):
        print("  PASS: HMAC-SHA256 signature verified")
        return True
    else:
        print("  FAIL: HMAC signature mismatch")
        return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("  NeoXFortress AAE — Reference Receipt Generator")
    print("  Agent Accountability Receipt v0.1.1")
    print("=" * 60)
    print()

    receipt = build_demo_receipt()

    output_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "examples", "demo-receipt.json"
    )
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(receipt, f, indent=2)
    print(f"[+] Receipt written: {output_path}")
    print()

    print("[*] Integrity verification:")
    chain_ok = verify_hash_chain(receipt)
    sig_ok = verify_signature(receipt)
    print()

    schema_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "schema.json"
    )
    if os.path.exists(schema_path):
        try:
            from jsonschema import validate, ValidationError
            with open(schema_path) as f:
                schema = json.load(f)
            validate(instance=receipt, schema=schema)
            print("[*] Schema validation:")
            print("  PASS: Receipt validates against schema.json")
            schema_ok = True
        except ValidationError as e:
            print("[*] Schema validation:")
            print(f"  FAIL: {e.message}")
            print(f"  Path: {'.'.join(str(p) for p in e.absolute_path)}")
            schema_ok = False
        except ImportError:
            print("[*] Schema validation:")
            print("  SKIP: jsonschema not installed (pip install jsonschema)")
            schema_ok = None
    else:
        print(f"[*] Schema not found at {schema_path}")
        schema_ok = None

    print()
    print(f"  Receipt ID:    {receipt['receipt']['receipt_id']}")
    print(f"  Steps:         {len(receipt['execution']['steps'])}")
    print(f"  Hash chain:    {receipt['integrity']['hash_chain']['final_hash'][:16]}...")
    print(f"  Signature:     {receipt['integrity']['signature']['value'][:20]}...")
    print(f"  Compliance:    {receipt['compliance']['verdict']}")
    print(f"  CUI crossings: {len(receipt['cui_flow'])}")
    print()

    all_pass = chain_ok and sig_ok and (schema_ok is True)
    if all_pass:
        print("  ALL CHECKS PASSED")
    else:
        print("  SOME CHECKS FAILED — review output above")
        exit(1)
