"""Local developer-only credential issuer; NEVER expose as a web endpoint."""
import argparse
import os
import time
from app.core import sign

p = argparse.ArgumentParser()
p.add_argument("--role", choices=["triage", "reviewer", "dispatcher"], required=True)
p.add_argument("--sub", required=True)
p.add_argument("--tenant", choices=["acme", "other"], default="acme")
p.add_argument("--task", default="demo-task")
p.add_argument("--ttl", type=int, default=300)
a = p.parse_args()
secret = os.getenv("TOKEN_SECRET", "")
if len(secret) < 24:
    p.error("Set TOKEN_SECRET to a random value of at least 24 characters")
if not 1 <= a.ttl <= 900:
    p.error("TTL must be between 1 and 900 seconds")
print(sign({"iss": "local-demo", "sub": a.sub, "role": a.role, "tenant": a.tenant, "task": a.task, "exp": int(time.time()) + a.ttl}, secret))
