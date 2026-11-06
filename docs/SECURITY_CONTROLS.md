# Security controls and mapping

## Reach

`/tools/messages` enforces an exact allowed mailbox, derived tenant, per-call maximum of 2 messages, and cumulative task budget of 3. Claims are verified using HMAC-SHA256 and expiry. The client cannot choose the tenant by passing an argument to the tool.

## Power

Deny by default. Role checks live in the gateway, not a prompt. Triage can only read and draft; reviewer can only approve and inspect tenant audit events; dispatcher can only simulate approved delivery. No unrestricted shell, external HTTP, or arbitrary code execution tool is present.

## Reversibility

Drafts are not sent on creation. An independent review identity approves the exact serialized draft, and dispatch compares the stored SHA-256 digest before consuming approval. The demo models a pre-send review boundary, not reliable recall after sending.

## Lifespan

Demo credentials contain `exp` and task identifiers. Approval is valid for 120 seconds and consumed once atomically under a process-local lock. The sample issuer limits credential lifetime to 15 minutes. Persistence and transactionality are required before moving beyond a single process.

## Verification

`tests/test_security.py` covers role tampering, expiry, tenant boundaries, message budgets, recipient restrictions, unauthorized send, separation of duties, approval misuse/replay, draft mutation, and audit visibility.

## Not claimed

This example is not a complete OAuth/OIDC implementation, does not deliver mail, and does not automatically detect prompt injection. Its purpose is to show that a system can reject unauthorized actions even when an agent requests them.
