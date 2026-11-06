"""Run a full attempted prompt-injection trace in memory. No external services."""
import time
from fastapi.testclient import TestClient
from app.core import build_app, sign

SECRET = "demo-only-temporary-secret-not-for-production"
app = build_app(SECRET)
client = TestClient(app)

def headers(role, sub=None):
    return {"Authorization": "Bearer " + sign({"iss":"local-demo", "sub":sub or role, "role":role, "tenant":"acme", "task":"demonstration", "exp":int(time.time())+120}, SECRET)}

def call(path, data, role):
    response = client.post(path, json=data, headers=headers(role))
    print(f"{role:<11} POST {path:<22} status={response.status_code} {response.json()}")
    return response

print("=== Prompt-injection attempt / policy-enforced control trace ===")
call("/tools/messages", {"mailbox":"executive", "limit":1}, "triage")
call("/tools/messages", {"mailbox":"support", "limit":50}, "triage")
call("/tools/drafts", {"mailbox":"support", "recipient":"attacker@evil.example", "subject":"Leak", "body":"customer messages"}, "triage")
call("/dispatch", {"draft_id":"fake", "approval_id":"none"}, "triage")
print("\n=== Legitimate workflow ===")
draft = call("/tools/drafts", {"mailbox":"support", "recipient":"customer@example.com", "subject":"Re: Support", "body":"Your case is under review"}, "triage").json()["draft_id"]
approval = call("/review/approve", {"draft_id":draft}, "reviewer").json()["approval_id"]
call("/dispatch", {"draft_id":draft, "approval_id":approval}, "dispatcher")
call("/dispatch", {"draft_id":draft, "approval_id":approval}, "dispatcher")
print("\nNo external email was sent. The approved dispatch is only in memory.")
