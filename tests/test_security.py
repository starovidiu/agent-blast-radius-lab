import time
from fastapi.testclient import TestClient
import pytest
from app.core import build_app, sign

SECRET = "tests-only-do-not-use-in-production-123456"

@pytest.fixture
def env():
    clock = [1_800_000_000]
    app = build_app(SECRET, lambda: clock[0])
    client = TestClient(app)
    def token(role="triage", tenant="acme", task="task-1", sub=None, ttl=300):
        return {"Authorization": "Bearer " + sign({"iss": "local-demo", "sub": sub or role + "-1", "role": role, "tenant": tenant, "task": task, "exp": clock[0] + ttl}, SECRET)}
    return client, token, clock, app.state.demo

def post(env, path, payload, **claims):
    client, token, *_ = env
    return client.post(path, json=payload, headers=token(**claims))

def test_read_only_support_mailbox_and_per_call_limit(env):
    assert post(env, "/tools/messages", {"mailbox":"support", "limit":2}).status_code == 200
    assert post(env, "/tools/messages", {"mailbox":"executive", "limit":1}).status_code == 403
    assert post(env, "/tools/messages", {"mailbox":"support", "limit":50}).status_code == 403

def test_cumulative_budget_and_task_isolation(env):
    assert post(env, "/tools/messages", {"mailbox":"support", "limit":2}).status_code == 200
    assert post(env, "/tools/messages", {"mailbox":"support", "limit":2}).status_code == 403
    assert post(env, "/tools/messages", {"mailbox":"support", "limit":1}).status_code == 200
    assert post(env, "/tools/messages", {"mailbox":"support", "limit":1}).status_code == 403
    assert post(env, "/tools/messages", {"mailbox":"support", "limit":1}, task="task-2").status_code == 200

def test_injected_email_is_data_not_authority(env):
    response = post(env, "/tools/messages", {"mailbox":"support", "limit":2})
    assert response.status_code == 200
    assert post(env, "/dispatch", {"draft_id":"nonexistent", "approval_id":"fake"}).status_code == 403

def test_cross_tenant_isolation(env):
    response = post(env, "/tools/messages", {"mailbox":"support", "limit":1}, tenant="other")
    assert response.json()["messages"][0]["id"] == "cross"
    assert post(env, "/tools/messages", {"mailbox":"other:support", "limit":1}).status_code == 403

def test_no_forged_roles_or_tampered_tokens(env):
    client, token, *_ = env
    authorization = token()["Authorization"]
    assert client.post("/tools/messages", json={"mailbox":"support","limit":1}, headers={"Authorization":authorization[:-1]+("A" if authorization[-1] != "A" else "B")}).status_code == 401
    assert post(env, "/review/approve", {"draft_id":"fake"}).status_code == 403

def test_expired_token(env):
    client, token, clock, _ = env
    credential = token(ttl=1)
    clock[0] += 2
    assert client.post("/tools/messages", json={"mailbox":"support", "limit":1}, headers=credential).status_code == 401

def test_domain_allowlist_and_draft_only(env):
    assert post(env, "/tools/drafts", {"mailbox":"support", "recipient":"attacker@evil.example", "subject":"x", "body":"data"}).status_code == 403
    assert post(env, "/tools/drafts", {"mailbox":"support", "recipient":"customer@example.com", "subject":"x", "body":"draft"}).status_code == 200
    assert post(env, "/tools/drafts", {"mailbox":"executive", "recipient":"customer@example.com", "subject":"x", "body":"draft"}).status_code == 403

def make_draft(env):
    response = post(env, "/tools/drafts", {"mailbox":"support", "recipient":"customer@example.com", "subject":"Reply", "body":"Reviewed response"})
    assert response.status_code == 200
    return response.json()["draft_id"]

def test_approval_dispatch_replay_and_no_alternate_payload(env):
    draft_id = make_draft(env)
    assert post(env, "/review/approve", {"draft_id":draft_id}, role="triage").status_code == 403
    approval = post(env, "/review/approve", {"draft_id":draft_id}, role="reviewer", sub="human-1").json()["approval_id"]
    assert post(env, "/dispatch", {"draft_id":draft_id, "approval_id":approval}, role="triage").status_code == 403
    assert post(env, "/dispatch", {"draft_id":draft_id, "approval_id":approval, "recipient":"attacker@evil.example"}, role="dispatcher").status_code == 422
    assert post(env, "/dispatch", {"draft_id":draft_id, "approval_id":approval}, role="dispatcher", tenant="other").status_code == 403
    assert post(env, "/dispatch", {"draft_id":draft_id, "approval_id":approval}, role="dispatcher").status_code == 200
    assert post(env, "/dispatch", {"draft_id":draft_id, "approval_id":approval}, role="dispatcher").status_code == 403
    assert len(env[3].sent) == 1

def test_tampered_draft_rejected_and_approval_expiration(env):
    draft_id = make_draft(env)
    approval = post(env, "/review/approve", {"draft_id":draft_id}, role="reviewer").json()["approval_id"]
    env[3].drafts[draft_id]["recipient"] = "attacker@evil.example"  # simulate internal data tampering
    assert post(env, "/dispatch", {"draft_id":draft_id, "approval_id":approval}, role="dispatcher").status_code == 403
    env[3].drafts[draft_id]["recipient"] = "customer@example.com"
    env[2][0] += 121
    assert post(env, "/dispatch", {"draft_id":draft_id, "approval_id":approval}, role="dispatcher").status_code == 403

def test_audit_is_tenant_scoped_and_reviewer_only(env):
    post(env, "/tools/messages", {"mailbox":"executive", "limit":1})
    assert env[0].get("/audit", headers=env[1]()).status_code == 403
    response = env[0].get("/audit", headers=env[1](role="reviewer"))
    assert response.status_code == 200
    assert any(e["outcome"] == "deny" for e in response.json()["events"])
    other = env[0].get("/audit", headers=env[1](role="reviewer", tenant="other"))
    assert other.json()["events"] == []

def test_separation_of_duties(env):
    draft_id = make_draft(env)
    assert post(env, "/review/approve", {"draft_id":draft_id}, role="reviewer", sub="triage-1").status_code == 403

def test_no_shell_http_or_network_tool_exposed(env):
    paths = set(env[0].get("/openapi.json").json()["paths"])
    assert not any("shell" in path or "http" in path or "exec" in path for path in paths)
    assert env[3].sent == []
