# neox-verify

**Open-source CLI verifier for [NeoXFortress Agent Accountability Receipts](https://github.com/NeoXFortress/agent-accountability-receipt)**

Independently verify the cryptographic integrity of any Agent Accountability Receipt produced by the NeoXFortress AAE — no account, no cloud, no dependencies beyond stdlib.

## Install

```bash
pip install neox-verify
```

## Usage

```bash
# Full verification (hash chain + HMAC + schema)
neox verify receipt.json

# Step-by-step hash chain trace
neox verify receipt.json --verbose

# Human-readable summary without crypto
neox info receipt.json

# Verify all receipts in a directory
neox batch ./receipts/

# Generate PDF verification report (AAE license required)
neox verify receipt.json --report
```

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | ALL CHECKS PASSED |
| `1` | One or more checks FAILED |
| `2` | File not found or invalid JSON |

Scriptable in CI/CD pipelines.

## What It Verifies

1. **Schema structure** — Receipt conforms to Agent Accountability Receipt schema v0.1.1
2. **Revocation status** — Receipt has not been revoked
3. **Hash chain integrity** — Every step's `prev_step_hash` matches SHA-256 of prior step; any tampering breaks the chain deterministically
4. **HMAC-SHA256 signature** — Signature block is well-formed and structurally valid

Full cryptographic HMAC verification requires the organization's signing key (not required for assessor use — structural verification is sufficient for CMMC evidence review).

## Example Output

```
  ╔══════════════════════════════════════════════════════════╗
  ║          NEOXFORTRESS  RECEIPT  VERIFIER  v0.1.1          ║
  ╚══════════════════════════════════════════════════════════╝
  Receipt ID:  rcpt-252afd32242d20be
  Agent:       RFP Intelligence Agent
  Status:      SUCCESS
  Verdict:     COMPLIANT

  PASS  Schema v0.1.1 structure
  PASS  Revocation status
  PASS  Hash chain integrity (6 steps)
  PASS  HMAC-SHA256 signature structure

  ✓  ALL CHECKS PASSED
```

## Links

- **Schema & Spec:** [github.com/NeoXFortress/agent-accountability-receipt](https://github.com/NeoXFortress/agent-accountability-receipt)
- **Enterprise PDF Reports:** [neoxfortress.com](https://neoxfortress.com)
- **CMMC / NIST 800-171 Evidence Packages:** [neoxfortress.com/contact](https://neoxfortress.com/contact)

---

MIT License — Copyright (c) 2026 Julio Berroa / NeoXFortress LLC
