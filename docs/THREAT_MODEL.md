# Threat model

## Trust boundaries

- Untrusted: email bodies and any text returned to an agent, as well as agent-proposed tool arguments.
- Trusted within the demo: signed identity claims, FastAPI authorization code, server-side state, local token issuer.
- Independent control: reviewer and dispatcher have separate signed roles and must share tenant/task scope with the draft.

## Attacker objective

Cause an agent reading a support email to retrieve other correspondence and exfiltrate it using available tools.

## Capabilities assumed

The attacker controls an inbound email body and may influence model-proposed tool arguments. The attacker does not know the HMAC secret and cannot change the trusted tool gateway, create reviewer/dispatcher credentials, or edit server memory. Those assumptions are important. If the host, signing secret, or identity issuer is compromised, this policy layer alone is insufficient.

## Abuse cases

- Executive mailbox read: denied by server-enforced allowed mailbox.
- Unauthorized tenant: mailbox access resolved from verified tenant, not a request parameter.
- Oversized retrieval: denied by per-call and per-task budgets.
- External recipient: rejected during draft creation.
- Unauthorized send: triage identity has no send role.
- Self approval: draft creator cannot approve even with another role token for same subject.
- Approval tampering: SHA-256 digest covers draft identifier, tenant, task, recipient, subject and body; changes invalidate approval.
- Replay: approval marked used under a lock; repeated dispatch denied.
- Expiration: both credential and approval checks reject stale requests.
- Alternate tools: intentionally not exposed. A real runtime must also isolate shell, network egress, and ambient credentials.

## Residual risks

- The model can create contaminated drafts or summaries inside permitted scope.
- Repeated reads of the same messages are counted as requests, not unique records; task identification is issued by trusted issuer.
- State and audit are process-local, reset on restart, and not tamper-evident.
- HMAC token role issuance is limited to a local CLI; no real IdP, issuer key rotation, audience validation, or revocation system.
- The example email contents contain only synthetic information.
- Reuse of a trusted issuer to create multiple subjects/tasks could change the budget accounting; the issuer must authenticate and constrain task creation in a real system.
- A human reviewer could approve malicious content; the demo checks role separation and digest, not content quality.
- No real SMTP/HTTP egress occurs; host-level egress restrictions remain a separate requirement.
