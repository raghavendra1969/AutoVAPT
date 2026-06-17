#!/usr/bin/env python3
"""
AutoVAPT - Module 1: JWT Analyzer
==================================
Decodes a JSON Web Token (JWT) and reports its header, payload, algorithm,
claims, and expiration -- without requiring the signing secret/key.

This tool only DECODES the token (base64url + JSON parsing). It does not
verify or crack signatures.

Usage:
    python jwt_analyzer.py <token>
    python jwt_analyzer.py --file token.txt
    echo "<token>" | python jwt_analyzer.py
    python jwt_analyzer.py <token> --json      # machine-readable output
"""

import argparse
import base64
import json
import sys
from datetime import datetime, timezone


# --------------------------------------------------------------------------
# Core decoding
# --------------------------------------------------------------------------

def base64url_decode(data: str) -> bytes:
    """Decode a base64url-encoded string, padding as needed."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def decode_jwt(token: str) -> dict:
    """Split a JWT into header/payload and decode each from base64url JSON."""
    token = token.strip()
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT structure: expected 3 dot-separated parts, got {len(parts)}")

    header_b64, payload_b64, signature_b64 = parts

    try:
        header = json.loads(base64url_decode(header_b64))
    except Exception as e:
        raise ValueError(f"Could not decode header: {e}")

    try:
        payload = json.loads(base64url_decode(payload_b64))
    except Exception as e:
        raise ValueError(f"Could not decode payload: {e}")

    return {"header": header, "payload": payload, "signature_raw": signature_b64}


def format_timestamp(ts) -> str:
    try:
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(ts)


# --------------------------------------------------------------------------
# Lightweight, non-exploitative security sanity checks
# --------------------------------------------------------------------------

def security_checks(header: dict, payload: dict) -> list:
    findings = []
    alg = str(header.get("alg", "")).lower()

    if alg == "none":
        findings.append(
            "[CRITICAL] alg=none -- token requires no signature. If the server "
            "accepts tokens like this, authentication can likely be bypassed."
        )
    elif alg in ("hs256", "hs384", "hs512"):
        findings.append(
            f"[INFO] {alg.upper()} is a symmetric algorithm. Confirm the signing "
            "secret is strong (long, random) and never exposed client-side."
        )
    elif alg in ("rs256", "rs384", "rs512", "es256", "es384", "es512", "ps256", "ps384", "ps512"):
        findings.append(f"[INFO] {alg.upper()} is an asymmetric algorithm -- generally a good choice.")
    elif not alg:
        findings.append("[WARNING] No 'alg' field present in header.")
    else:
        findings.append(f"[INFO] Algorithm declared: {alg.upper()}")

    if "exp" not in payload:
        findings.append("[WARNING] No 'exp' (expiration) claim -- token may never expire.")
    else:
        try:
            exp_dt = datetime.fromtimestamp(int(payload["exp"]), tz=timezone.utc)
            if exp_dt < datetime.now(timezone.utc):
                findings.append(f"[INFO] Token is EXPIRED (was valid until {format_timestamp(payload['exp'])}).")
            else:
                findings.append(f"[INFO] Token is currently valid, expires {format_timestamp(payload['exp'])}.")
        except Exception:
            findings.append("[WARNING] 'exp' claim present but not a valid timestamp.")

    if "iat" not in payload:
        findings.append("[INFO] No 'iat' (issued-at) claim present.")

    sensitive_keys = {"password", "secret", "ssn", "credit_card", "card_number", "api_key"}
    leaked = sensitive_keys.intersection(k.lower() for k in payload.keys())
    if leaked:
        findings.append(f"[HIGH] Payload contains sensitive-looking field name(s): {', '.join(sorted(leaked))}")

    return findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_report(decoded: dict):
    header = decoded["header"]
    payload = decoded["payload"]

    print("=" * 60)
    print("AutoVAPT -- JWT Analyzer")
    print("=" * 60)

    print("\n[Header]")
    print(json.dumps(header, indent=2))

    print("\n[Payload]")
    print(json.dumps(payload, indent=2))

    print("\n[Summary]")
    print(f"Algorithm   : {header.get('alg', 'N/A')}")
    print(f"Token Type  : {header.get('typ', 'N/A')}")
    if "sub" in payload:
        print(f"Subject     : {payload['sub']}")
    if "email" in payload:
        print(f"Email       : {payload['email']}")
    for role_key in ("role", "roles", "scope", "scopes"):
        if role_key in payload:
            print(f"{role_key.capitalize():12}: {payload[role_key]}")
    if "iat" in payload:
        print(f"Issued At   : {format_timestamp(payload['iat'])}")
    if "exp" in payload:
        print(f"Expires     : {format_timestamp(payload['exp'])}")
    if "iss" in payload:
        print(f"Issuer      : {payload['iss']}")
    if "aud" in payload:
        print(f"Audience    : {payload['aud']}")

    print("\n[Security Notes]")
    for finding in security_checks(header, payload):
        print(f" - {finding}")

    print("\n[Note] Signature was NOT cryptographically verified -- this tool only decodes.")
    print("=" * 60)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="AutoVAPT JWT Analyzer -- decode & inspect a JWT.")
    parser.add_argument("token", nargs="?", help="JWT string to analyze")
    parser.add_argument("--file", "-f", help="Path to a file containing the JWT")
    parser.add_argument("--json", action="store_true", help="Output raw decoded JSON instead of a formatted report")
    args = parser.parse_args(argv)

    if args.file:
        with open(args.file) as fh:
            token = fh.read().strip()
    elif args.token:
        token = args.token
    elif not sys.stdin.isatty():
        token = sys.stdin.read().strip()
    else:
        parser.error("Provide a JWT as an argument, via --file, or via stdin.")
        return

    try:
        decoded = decode_jwt(token)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        print(json.dumps({"header": decoded["header"], "payload": decoded["payload"]}, indent=2))
    else:
        print_report(decoded)


if __name__ == "__main__":
    main()
