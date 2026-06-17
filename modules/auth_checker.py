#!/usr/bin/env python3
"""
AutoVAPT - Module 2: Username / Account Enumeration Detector
==============================================================
Sends authentication attempts against a login endpoint using different
identities (e.g. one registered, one not) and flags cases where the
application's response differs between groups -- a classic OWASP
A07:2021 (Identification & Authentication Failures) issue known as
"username enumeration via different responses".

IMPORTANT: Only run this against systems you own or are explicitly
authorized to test. Unauthorized testing may be illegal.

Usage:
    python auth_checker.py --config ../findings/auth_checker_config.sample.json
    python auth_checker.py --config myconfig.json --yes --save ../reports/enum_result.json
"""

import argparse
import difflib
import json
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List

try:
    import requests
except ImportError:
    print("This module requires the 'requests' package: pip install requests", file=sys.stderr)
    sys.exit(1)


# --------------------------------------------------------------------------
# Data structures
# --------------------------------------------------------------------------

@dataclass
class Probe:
    label: str
    identity: str
    password: str = "WrongPassword!123"


@dataclass
class ProbeResult:
    probe: Probe
    status_code: int
    elapsed_ms: float
    body: str
    body_len: int


# --------------------------------------------------------------------------
# Config / requests
# --------------------------------------------------------------------------

def load_config(path: str) -> dict:
    with open(path) as fh:
        return json.load(fh)


def build_probes(raw_probes: list) -> List[Probe]:
    return [
        Probe(label=p["label"], identity=p["identity"], password=p.get("password", "WrongPassword!123"))
        for p in raw_probes
    ]


def send_login(session, url, method, identity_field, password_field,
               probe: Probe, extra_fields: dict, timeout: int) -> ProbeResult:
    payload = {identity_field: probe.identity, password_field: probe.password}
    payload.update(extra_fields or {})

    start = time.perf_counter()
    resp = session.request(method.upper(), url, json=payload, timeout=timeout)
    elapsed_ms = (time.perf_counter() - start) * 1000

    return ProbeResult(
        probe=probe,
        status_code=resp.status_code,
        elapsed_ms=elapsed_ms,
        body=resp.text,
        body_len=len(resp.content),
    )


# --------------------------------------------------------------------------
# Analysis
# --------------------------------------------------------------------------

def similarity(a: str, b: str) -> float:
    """0..1 similarity ratio between two response bodies."""
    return difflib.SequenceMatcher(None, a, b).ratio()


def analyze(results: List[ProbeResult]) -> dict:
    """Group results by label and compare response signatures across groups."""
    by_label = {}
    for r in results:
        by_label.setdefault(r.probe.label, []).append(r)

    labels = list(by_label.keys())
    flagged = []

    for i in range(len(labels)):
        for j in range(i + 1, len(labels)):
            label_a, label_b = labels[i], labels[j]
            for ra in by_label[label_a]:
                for rb in by_label[label_b]:
                    diff_status = ra.status_code != rb.status_code
                    sim = similarity(ra.body, rb.body)
                    diff_len = abs(ra.body_len - rb.body_len)

                    is_different = diff_status or sim < 0.95 or diff_len > 5

                    if is_different:
                        flagged.append({
                            "group_a": label_a,
                            "group_b": label_b,
                            "identity_a": ra.probe.identity,
                            "identity_b": rb.probe.identity,
                            "status_a": ra.status_code,
                            "status_b": rb.status_code,
                            "body_a_snippet": ra.body.strip()[:300],
                            "body_b_snippet": rb.body.strip()[:300],
                            "similarity": round(sim, 4),
                            "len_a": ra.body_len,
                            "len_b": rb.body_len,
                            "timing_diff_ms": round(abs(ra.elapsed_ms - rb.elapsed_ms), 2),
                        })
    return {"flagged": flagged, "comparisons": len(flagged)}


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_findings(analysis: dict):
    if not analysis["flagged"]:
        print("\nNo response differences detected between identity groups.")
        print("(This does not guarantee the absence of enumeration -- try more")
        print(" identities, check timing differences, and review HTTP headers manually.)")
        return

    print("\n" + "!" * 60)
    print("Potential Username Enumeration Detected")
    print("!" * 60)
    for f in analysis["flagged"]:
        print(f"\n{f['group_a']} ({f['identity_a']}):")
        print(f"  Status: {f['status_a']}")
        print(f'  Response: "{f["body_a_snippet"]}"')
        print(f"\n{f['group_b']} ({f['identity_b']}):")
        print(f"  Status: {f['status_b']}")
        print(f'  Response: "{f["body_b_snippet"]}"')
        print(f"\n  Body similarity: {f['similarity']*100:.1f}%  |  "
              f"Length diff: {f['len_a']} vs {f['len_b']} bytes  |  "
              f"Timing diff: {f['timing_diff_ms']} ms")
        print("-" * 60)


def confirm_authorization(url: str, auto_yes: bool) -> bool:
    print("=" * 60)
    print("AutoVAPT - Username Enumeration Detector")
    print("Only run this against systems you own or are explicitly")
    print("authorized to test. Unauthorized testing may be illegal.")
    print("=" * 60)
    print(f"Target: {url}")
    if auto_yes:
        return True
    try:
        answer = input("Confirm you are authorized to test this target [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer == "y"


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description="AutoVAPT Username Enumeration Detector")
    parser.add_argument("--config", "-c", required=True, help="Path to JSON config file")
    parser.add_argument("--yes", action="store_true", help="Skip the interactive authorization prompt")
    parser.add_argument("--save", help="Path to save full JSON results")
    args = parser.parse_args(argv)

    cfg = load_config(args.config)
    url = cfg["url"]

    if not confirm_authorization(url, args.yes):
        print("Authorization not confirmed. Exiting.")
        sys.exit(1)

    probes = build_probes(cfg["probes"])
    session = requests.Session()
    results = []

    for probe in probes:
        try:
            result = send_login(
                session, url, cfg.get("method", "POST"),
                cfg.get("identity_field", "email"), cfg.get("password_field", "password"),
                probe, cfg.get("extra_fields", {}), cfg.get("timeout", 10),
            )
        except requests.RequestException as e:
            print(f"Request failed for {probe.label} ({probe.identity}): {e}", file=sys.stderr)
            continue
        results.append(result)
        print(f"[{probe.label}] {probe.identity} -> HTTP {result.status_code}, "
              f"{result.body_len} bytes, {result.elapsed_ms:.1f} ms")

    analysis = analyze(results)
    print_findings(analysis)

    if args.save:
        Path(args.save).parent.mkdir(parents=True, exist_ok=True)
        with open(args.save, "w") as fh:
            json.dump(analysis, fh, indent=2)
        print(f"\nFull results saved to {args.save}")


if __name__ == "__main__":
    main()
