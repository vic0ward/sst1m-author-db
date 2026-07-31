#!/usr/bin/env python3
"""SSO bridge smoke test for the MediaWiki integration.

Mints an SSO handoff token the same way the PHP extension does (base64url + HMAC
over a JSON payload) and checks the app's read_sso_token() validator against:
  * a valid token        -> accepted (returns the username)
  * a forged signature   -> rejected
  * an expired token      -> rejected
  * a wrong-type token    -> rejected

Run from the repo root:
    AUTHOR_DB_SECRET=test-secret python tools/sso_smoketest.py

This verifies the PHP <-> Python token contract WITHOUT needing MediaWiki or a
running server. (Set the same AUTHOR_DB_SECRET you'll use in $wgAuthorDBSecret.)
"""
import base64
import hashlib
import hmac
import json
import os
import sys
import time

# Import the app's real validator + signer so we test the exact contract.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import read_sso_token, SECRET  # noqa: E402


def base64url(b: bytes) -> str:
    """URL-safe base64 with padding kept — matches PHP strtr(base64_encode())."""
    return base64.urlsafe_b64encode(b).decode("utf-8")


def mint_php_style(username: str, secret: str, ttl: int = 60, typ: str = "sso") -> str:
    """Replicate SpecialAuthorDB::mintSsoToken() from PHP."""
    payload = {"u": username, "exp": int(time.time()) + ttl, "typ": typ}
    js = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), js, hashlib.sha256).digest()
    return base64url(js) + "." + base64url(sig)


def check(label: str, got, expected) -> bool:
    ok = got == expected
    print(f"  [{'PASS' if ok else 'FAIL'}] {label}: got={got!r} expected={expected!r}")
    return ok


def main() -> int:
    print(f"Using SECRET={'(default)' if SECRET == 'dev-secret-change-me' else '(custom)'}")
    results = []

    # 1. Valid token
    tok = mint_php_style("WikiAdmin", SECRET)
    results.append(check("valid token accepted", read_sso_token(tok), "WikiAdmin"))

    # 2. Forged signature
    forged = tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB")
    results.append(check("forged signature rejected", read_sso_token(forged), None))

    # 3. Expired token
    expired = mint_php_style("WikiAdmin", SECRET, ttl=-10)
    results.append(check("expired token rejected", read_sso_token(expired), None))

    # 4. Wrong type
    wrong = mint_php_style("WikiAdmin", SECRET, typ="other")
    results.append(check("wrong-type token rejected", read_sso_token(wrong), None))

    # 5. Wrong secret
    other = mint_php_style("WikiAdmin", "a-different-secret")
    results.append(check("wrong-secret token rejected", read_sso_token(other), None))

    print()
    if all(results):
        print("ALL CHECKS PASSED — PHP/Python SSO token contract is consistent.")
        return 0
    print("SOME CHECKS FAILED.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
