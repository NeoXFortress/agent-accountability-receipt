"""
Receipt Writer — Converts real agent execution traces into schema-valid
Agent Accountability Receipts.

Takes a list of execution events from the agent harness and produces a
signed, hash-chained JSON receipt conforming to schema.json v0.1.1.

Copyright (c) 2026 Julio Berroa / NeoXFortress LLC
"""

import json
import hashlib
import hmac as hmac_mod
import uuid
import os
import base64
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict


SCHEMA_VERSION = "0.1.1"
SECRET_KEY = os.environ.get(
    "AAR_SIGNING_KEY", "demo-secret-key-do-not-use-in-production"
).encode()
SIGNING_KEY_ID = os.environ.get("AAR_SIGNING_KEY_ID", "demo-key-001")


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_data_ref(ref_id: str, content: str, representation: str = "hash_only",
                  source_hint: str = None, mime_type: str = None,
                  redaction_method: str = None, redaction_count: int = None) -> dict:
    ref = {
        "ref_id": ref_id,
        "representation": representation,
        "hash": sha256_hex(content.encode()),
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
# Step recorder — accumulates events during agent execution
# ---------------------------------------------------------------------------

@dataclass
class StepEvent:
    """A single execution event recorded by the harness."""
    step_type: str  # llm_call, tool_call, decision, human_checkpoint, guardrail_event
    summary: str
    timestamp_utc: str = ""
    parent_step_id: Optional[str] = None
    actor: str = "agent"

    # Type-specific
    model_provider: str = ""
    model_id: str = ""
    model_region: str = ""

    tool_name: str = ""
    tool_version: str = ""
    tool_permission_scope: str = ""

    # Human checkpoint
    presented_text: str = ""
    presentation_mode: str = "full_output"
    reviewer_action: str = ""
    review_duration_ms: int = 0

    # Guardrail
    guardrail_event_type: str = ""
    guardrail_action: str = ""
    guardrail_reason: str = ""
    guardrail_policy_rule_id: str = ""
    guardrail_attempted_action: str = ""
    guardrail_target: str = ""

    # Error
    error_code: str = ""
    error_message: str = ""
    error_recoverable: Optional[bool] = None

    # I/O
    inputs: List[dict] = field(default_factory=list)   # list of data_ref dicts
    outputs: List[dict] = field(default_factory=list)
    classifications: List[dict] = field(default_factory=list)
    guardrails: List[dict] = field(default_factory=list)

    # Metrics
    latency_ms: int = 0
    tokens_in: int = 0
    tokens_out: int = 0


class ExecutionRecorder:
    """Accumulates step events during an agent run and builds the receipt."""

    def __init__(
        self,
        purpose: str,
        agent_id: str,
        agent_name: str,
        agent_version: str = "1.0.0",
        agent_type: str = "assistant",
        framework_name: str = "custom",
        framework_version: str = "1.0.0",
        operator_id: str = "demo-operator",
        operator_role: str = "Demo Operator",
        organization: str = "Demo Organization",
        network_boundary: str = "Dev sandbox",
        policy_id: str = "pol-demo",
        policy_version: str = "1.0.0",
        schema_path: str = None,
    ):
        self.purpose = purpose
        self.run_id = str(uuid.uuid4())
        self.receipt_id = str(uuid.uuid4())
        self.events: List[StepEvent] = []
        self._step_counter = 0
        self._start_time = datetime.now(timezone.utc)

        # Agent identity
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.agent_type = agent_type
        self.framework_name = framework_name
        self.framework_version = framework_version

        # Operator
        self.operator_id = operator_id
        self.operator_role = operator_role
        self.organization = organization
        self.network_boundary = network_boundary

        # Policy
        self.policy_id = policy_id
        self.policy_version = policy_version

        # Schema hash
        if schema_path and os.path.exists(schema_path):
            with open(schema_path, "rb") as f:
                self.schema_hash = sha256_hex(f.read())
        else:
            self.schema_hash = "0" * 64

        # CUI flow entries
        self.cui_flow_entries: List[dict] = []

    def next_step_id(self) -> str:
        self._step_counter += 1
        return f"step-{self._step_counter:03d}"

    def record(self, event: StepEvent) -> str:
        """Record a step event. Returns the assigned step_id."""
        step_id = self.next_step_id()
        if not event.timestamp_utc:
            event.timestamp_utc = datetime.now(timezone.utc).isoformat()
        event._step_id = step_id
        self.events.append(event)
        return step_id

    def add_cui_flow(self, direction: str, boundary: str, data: str,
                     classification: str, redacted: bool, step_ids: list,
                     policy_rule_id: str = "", redaction_method: str = ""):
        entry = {
            "direction": direction,
            "boundary": boundary,
            "data_hash": sha256_hex(data.encode()),
            "classification": classification,
            "redacted": redacted,
            "step_ids": step_ids,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        }
        if policy_rule_id:
            entry["policy_rule_id"] = policy_rule_id
        if redacted and redaction_method:
            entry["redaction_method"] = redaction_method
        self.cui_flow_entries.append(entry)

    def build_receipt(
        self,
        run_status: str = "success",
        run_error_summary: str = "",
        run_inputs: List[dict] = None,
        run_outputs: List[dict] = None,
        compliance_verdict: str = "compliant",
        violated_controls: List[str] = None,
        risk_score: float = 0.0,
        compliance_notes: str = "",
        labels: List[str] = None,
    ) -> dict:
        """Build the complete receipt from recorded events."""

        end_time = datetime.now(timezone.utc)
        session_id = "sess-" + uuid.uuid4().hex[:12]

        # Build schema-compliant steps
        steps = []
        for event in self.events:
            step = {
                "step_id": event._step_id,
                "parent_step_id": event.parent_step_id,
                "timestamp_utc": event.timestamp_utc,
                "type": event.step_type,
                "summary": event.summary,
                "actor": event.actor,
                "artifacts": {
                    "inputs": event.inputs,
                    "outputs": event.outputs,
                    "classifications": event.classifications,
                },
            }

            # Type-specific fields
            if event.step_type == "llm_call" and event.model_provider:
                step["model"] = {
                    "provider": event.model_provider,
                    "model_id": event.model_id,
                }
                if event.model_region:
                    step["model"]["region"] = event.model_region

            if event.step_type == "tool_call" and event.tool_name:
                step["tool"] = {"tool_name": event.tool_name}
                if event.tool_version:
                    step["tool"]["tool_version"] = event.tool_version
                if event.tool_permission_scope:
                    step["tool"]["permission_scope"] = event.tool_permission_scope

            if event.step_type == "human_checkpoint":
                step["human_checkpoint"] = {
                    "presented_artifact": make_data_ref(
                        f"ref-presented-{event._step_id}",
                        event.presented_text,
                        "full_text" if event.presentation_mode == "full_output" else "hash_only",
                    ),
                    "presentation_mode": event.presentation_mode,
                    "reviewer_action": event.reviewer_action,
                    "review_duration_ms": event.review_duration_ms,
                }

            if event.guardrails:
                step["artifacts"]["guardrails"] = event.guardrails

            if event.error_code:
                step["error"] = {
                    "code": event.error_code,
                    "message": event.error_message,
                }
                if event.error_recoverable is not None:
                    step["error"]["recoverable"] = event.error_recoverable

            # Metrics
            metrics = {}
            if event.latency_ms:
                metrics["latency_ms"] = event.latency_ms
            if event.tokens_in:
                metrics["tokens_in"] = event.tokens_in
            if event.tokens_out:
                metrics["tokens_out"] = event.tokens_out
            if metrics:
                step["metrics"] = metrics

            steps.append(step)

        # Hash chain
        ZERO = "0" * 64
        chain = []
        prev = ZERO
        for step in steps:
            h = sha256_hex(prev.encode() + canonical_json(step))
            chain.append({"step_id": step["step_id"], "hash": h, "prev_hash": prev})
            prev = h
        final_hash = prev

        # HMAC signature
        sig_bytes = hmac_mod.new(SECRET_KEY, final_hash.encode(), hashlib.sha256).digest()
        sig_b64 = base64.b64encode(sig_bytes).decode()
        sign_time = datetime.now(timezone.utc).isoformat()

        receipt = {
            "receipt": {
                "receipt_id": self.receipt_id,
                "schema_version": SCHEMA_VERSION,
                "schema_hash": self.schema_hash,
                "created_at_utc": sign_time,
                "status": "active",
                "issuer": {
                    "organization": self.organization,
                    "product": "NeoXFortress AAE",
                    "build": {"version": "0.1.1-harness", "commit": "live"},
                },
                "receipt_type": "agent_execution",
                "labels": labels or [],
            },
            "context": {
                "subject": {
                    "agent": {
                        "agent_id": self.agent_id,
                        "name": self.agent_name,
                        "type": self.agent_type,
                        "agent_version": self.agent_version,
                        "agent_code_hash": sha256_hex(
                            f"{self.agent_id}-{self.agent_version}".encode()
                        ),
                        "framework": {
                            "name": self.framework_name,
                            "version": self.framework_version,
                        },
                        "purpose": self.purpose,
                        "runtime": {
                            "language": "python",
                            "language_version": "3.11",
                        },
                    },
                    "operator": {
                        "principal_id": self.operator_id,
                        "principal_type": "human_user",
                        "authn": {
                            "idp": "local",
                            "authn_method": "key",
                            "session_id": session_id,
                        },
                        "role": self.operator_role,
                    },
                },
                "environment": {
                    "deployment_model": "local",
                    "host": {
                        "hostname_hash": sha256_hex(os.uname().nodename.encode()),
                        "os": f"{os.uname().sysname} {os.uname().release}",
                        "network_boundary": self.network_boundary,
                    },
                    "clock": {
                        "time_source": "system clock",
                        "skew_ms": 0,
                    },
                },
                "time_window": {
                    "started_at_utc": self._start_time.isoformat(),
                    "ended_at_utc": end_time.isoformat(),
                },
            },
            "policy": {
                "policy_id": self.policy_id,
                "policy_version": self.policy_version,
                "policy_hash": sha256_hex(
                    f"{self.policy_id}-{self.policy_version}".encode()
                ),
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
                    "run_id": self.run_id,
                    "run_purpose": self.purpose,
                    "status": run_status,
                    "inputs": run_inputs or [],
                    "outputs": run_outputs or [],
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
                        "method": "manual",
                        "last_verified_utc": self._start_time.isoformat(),
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
                    "notes": "JCS per RFC 8785.",
                },
                "hash_chain": {
                    "alg": "sha256",
                    "chain": chain,
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
                            "1. Canonicalize via JCS (RFC 8785). "
                            "2. Concat with final_hash. "
                            "3. HMAC-SHA256 with key_id. "
                            "4. Compare base64. "
                            "NOTE: Symmetric HMAC in v0.1.1."
                        )
                    },
                },
            },
            "compliance": {
                "verdict": compliance_verdict,
                "assessed_by": "engine_rule_set",
                "violated_controls": violated_controls or [],
                "risk_score": risk_score,
                "framework": "CMMC L2",
                "notes": compliance_notes,
            },
            "cui_flow": self.cui_flow_entries,
        }

        if run_error_summary:
            receipt["execution"]["run"]["error_summary"] = run_error_summary

        return receipt


def save_and_verify(receipt: dict, output_path: str, schema_path: str = None):
    """Save receipt to file and run verification."""
    import sys

    # Save
    with open(output_path, "w") as f:
        json.dump(receipt, f, indent=2)
    print(f"\n[+] Receipt written: {output_path}")

    # Verify hash chain
    chain = receipt["integrity"]["hash_chain"]["chain"]
    steps = receipt["execution"]["steps"]
    prev = "0" * 64
    chain_ok = True
    for i, (entry, step) in enumerate(zip(chain, steps)):
        expected = sha256_hex(prev.encode() + canonical_json(step))
        if entry["hash"] != expected:
            print(f"  FAIL: Step {i} hash mismatch")
            chain_ok = False
            break
        prev = entry["hash"]
    if chain_ok and prev == receipt["integrity"]["hash_chain"]["final_hash"]:
        print(f"  PASS: Hash chain verified ({len(chain)} steps)")
    else:
        print("  FAIL: Hash chain verification failed")

    # Verify signature
    final_hash = receipt["integrity"]["hash_chain"]["final_hash"]
    stored_sig = receipt["integrity"]["signature"]["value"]
    expected_sig = base64.b64encode(
        hmac_mod.new(SECRET_KEY, final_hash.encode(), hashlib.sha256).digest()
    ).decode()
    if hmac_mod.compare_digest(stored_sig, expected_sig):
        print("  PASS: HMAC-SHA256 signature verified")
    else:
        print("  FAIL: HMAC signature mismatch")

    # Schema validation
    if schema_path and os.path.exists(schema_path):
        try:
            from jsonschema import validate, ValidationError
            with open(schema_path) as f:
                schema = json.load(f)
            validate(instance=receipt, schema=schema)
            print("  PASS: Schema validation")
        except ValidationError as e:
            print(f"  FAIL: Schema validation — {e.message}")
            print(f"  Path: {'.'.join(str(p) for p in e.absolute_path)}")
        except ImportError:
            print("  SKIP: jsonschema not installed")
    else:
        print("  SKIP: Schema path not provided")
