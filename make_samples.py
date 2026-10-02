"""
Generates the two synthetic sample logs used by the demo.

Both are fictional systems with a planted incident, so you can check that the
triage points at the right place:

  samples/checkout-outage.log    plain text; a bad payments deploy exhausts the DB pool
  samples/auth-cert-expiry.jsonl JSON lines; an expired upstream certificate breaks logins
"""

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).parent / "samples"
rng = random.Random(42)


def oid():
    return rng.randint(100000, 999999)


def ip():
    return f"10.{rng.randint(0, 40)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def ms(lo, hi):
    return rng.randint(lo, hi)


def checkout_outage():
    start = datetime(2026, 3, 14, 9, 0, tzinfo=timezone.utc)
    deploy = start + timedelta(minutes=71, seconds=12)
    pool_warn = deploy + timedelta(minutes=2, seconds=40)
    outage = deploy + timedelta(minutes=4)
    rollback = deploy + timedelta(minutes=16)
    recovered = rollback + timedelta(minutes=2)
    end = start + timedelta(minutes=120)
    lines = []

    def log(ts, level, svc, msg):
        lines.append((ts, f"{ts:%Y-%m-%dT%H:%M:%S}.{ts.microsecond // 1000:03d}Z {level:<5} [{svc}] {msg}"))

    t = start
    while t < end:
        t += timedelta(milliseconds=rng.randint(3000, 7000))
        degraded = outage <= t < recovered
        r = rng.random()
        if r < 0.30:
            log(t, "INFO", "api-gateway", f"POST /v1/checkout 200 {ms(80, 240)}ms client={ip()}")
        elif r < 0.50:
            log(t, "INFO", "checkout-svc", f"Order {oid()} created, total=EUR {rng.randint(9, 240)}.{rng.randint(0, 99):02d}")
        elif r < 0.65:
            log(t, "INFO", "payments-svc", f"Charge authorised for order {oid()} in {ms(60, 180)}ms")
        elif r < 0.78:
            log(t, "INFO", "inventory-svc", f"Reserved {rng.randint(1, 4)} item(s) for order {oid()}")
        elif r < 0.88:
            log(t, "DEBUG", "auth-svc", f"Token validated for user {rng.randint(1000, 99999)}")
        elif r < 0.95:
            log(t, "WARN", "inventory-svc", f"Cache miss for sku-{rng.randint(1000, 9999)}, falling back to DB")
        elif r < 0.985:
            log(t, "WARN", "checkout-svc", f"Slow query on orders table took {ms(800, 1900)}ms")
        else:
            log(t, "ERROR", "api-gateway", f"POST /v1/checkout 499 client closed request after {ms(2000, 5000)}ms")

        if degraded:
            for _ in range(rng.randint(2, 5)):
                u = t + timedelta(milliseconds=rng.randint(0, 2500))
                k = rng.random()
                if k < 0.40:
                    log(u, "ERROR", "payments-svc", f"DB connection pool exhausted (active=50/50, waiting={rng.randint(8, 40)})")
                elif k < 0.70:
                    log(u, "ERROR", "checkout-svc", f"Upstream payments-svc returned 503 for order {oid()} after {ms(2900, 3100)}ms")
                elif k < 0.92:
                    log(u, "ERROR", "api-gateway", f"POST /v1/checkout 504 Gateway Timeout {ms(5000, 5100)}ms client={ip()}")
                else:
                    log(u, "WARN", "checkout-svc", f"Retrying payment for order {oid()} (attempt {rng.randint(2, 3)}/3)")

    log(deploy, "INFO", "payments-svc", "Deploy started: version=2.14.0 (previous=2.13.4) by ci-pipeline")
    log(deploy + timedelta(seconds=48), "INFO", "payments-svc", "Deploy finished: 6/6 pods ready, version=2.14.0")
    for i in range(6):
        log(pool_warn + timedelta(seconds=i * 15), "WARN", "payments-svc",
            f"Connection pool nearing capacity (active={44 + i}/50) - connections not returned after refund lookup")
    log(rollback, "INFO", "payments-svc", "Rollback started: version=2.13.4 (incident INC-2291)")
    log(rollback + timedelta(seconds=55), "INFO", "payments-svc", "Rollback finished: 6/6 pods ready, version=2.13.4")
    log(recovered + timedelta(seconds=30), "INFO", "payments-svc", "DB connection pool healthy (active=12/50, waiting=0)")

    lines.sort(key=lambda x: x[0])
    return "\n".join(line for _, line in lines) + "\n"


def auth_cert_expiry():
    start = datetime(2026, 5, 2, 22, 30, tzinfo=timezone.utc)
    expiry = datetime(2026, 5, 3, 0, 0, tzinfo=timezone.utc)
    fixed = expiry + timedelta(minutes=23)
    end = start + timedelta(minutes=150)
    lines = []

    def log(ts, level, svc, msg, **extra):
        rec = {"@timestamp": f"{ts:%Y-%m-%dT%H:%M:%S}.{ts.microsecond // 1000:03d}Z",
               "level": level.lower(), "service": svc, "message": msg}
        rec.update(extra)
        lines.append((ts, json.dumps(rec)))

    t = start
    while t < end:
        t += timedelta(milliseconds=rng.randint(2500, 6000))
        broken = expiry <= t < fixed
        r = rng.random()
        if r < 0.35:
            if broken:
                if rng.random() < 0.6:
                    log(t + timedelta(milliseconds=800), "warn", "web-app", "Login failed, client retrying (attempt 2/3)")
                    log(t + timedelta(milliseconds=900), "error", "auth-svc",
                        "Token exchange with idp.example.net failed: certificate has expired",
                        trace_id=f"{rng.getrandbits(64):016x}")
                log(t, "error", "auth-svc", "Token exchange with idp.example.net failed: certificate has expired",
                    trace_id=f"{rng.getrandbits(64):016x}")
            else:
                log(t, "info", "auth-svc", f"Login succeeded for user {rng.randint(1000, 99999)} in {ms(90, 300)}ms")
        elif r < 0.55:
            if broken:
                log(t, "error", "web-app", f"GET /account 401 Unauthorized session={rng.getrandbits(48):012x}")
            else:
                log(t, "info", "web-app", f"GET /account 200 {ms(40, 160)}ms")
        elif r < 0.75:
            log(t, "info", "catalog-api", f"Served {rng.randint(10, 60)} titles for profile {rng.randint(1, 9)} in {ms(20, 90)}ms")
        elif r < 0.90:
            log(t, "debug", "auth-svc", f"Refreshed signing keys cache ({rng.randint(3, 5)} keys)")
        elif r < 0.97:
            log(t, "warn", "catalog-api", f"Recommendation call exceeded budget: {ms(300, 700)}ms")
        else:
            log(t, "error", "web-app", f"GET /search 500 upstream reset by peer {ip()}")

    for m in (60, 30, 10, 1):
        log(expiry - timedelta(minutes=m), "warn", "auth-svc",
            f"TLS certificate for idp.example.net expires in {m}m (notAfter=2026-05-03T00:00:00Z)")
    log(expiry + timedelta(seconds=2), "error", "auth-svc",
        "x509: certificate has expired or is not yet valid: current time 2026-05-03T00:00:02Z is after 2026-05-03T00:00:00Z")
    log(fixed - timedelta(minutes=1), "info", "auth-svc", "Reloaded trust bundle: idp.example.net cert valid until 2027-05-03")

    lines.sort(key=lambda x: x[0])
    return "\n".join(line for _, line in lines if start <= _ <= end) + "\n"


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    (OUT / "checkout-outage.log").write_text(checkout_outage())
    (OUT / "auth-cert-expiry.jsonl").write_text(auth_cert_expiry())
    for p in sorted(OUT.iterdir()):
        print(f"{p.name}: {sum(1 for _ in p.open())} lines")
