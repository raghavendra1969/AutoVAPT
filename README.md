# AutoVAPT — Web & API Security Assessment Framework

A small, modular toolkit for web/API penetration-testing workflows: decoding
and sanity-checking JWTs, detecting username/account enumeration in login
flows, cataloging discovered API endpoints, and producing a professional
write-up of findings.

> ⚠️ **Authorized use only.** These tools are for testing systems you own or
> are explicitly authorized to test (e.g. your own application, a sanctioned
> pentest engagement, or a bug bounty program's defined scope). Running
> these against systems without permission may be illegal in your
> jurisdiction.

## Project Structure

```
AutoVAPT/
├── README.md
├── requirements.txt
├── main.py                                 # unified CLI entry point
├── modules/
│   ├── jwt_analyzer.py                     # Module 1: JWT Analyzer
│   ├── auth_checker.py                     # Module 2: Username Enumeration Detector
│   └── api_mapper.py                       # Module 3: API Mapper
├── findings/
│   ├── endpoints.json                      # discovered API endpoints (Module 3 data)
│   └── auth_checker_config.sample.json     # template config for Module 2
└── reports/
    ├── api_inventory_report.md             # sample generated report (Module 3)
    └── VAPT_Finding_Username_Enumeration.md# Module 4: finding write-up
```

## Setup

```bash
cd AutoVAPT
python3 -m venv venv && source venv/bin/activate   # optional
pip install -r requirements.txt
```

Everything below can be run either via the unified `main.py` entry point or
by calling each module script directly.

## Module 1 — JWT Analyzer

Decodes a JWT's header and payload (no signature verification/cracking) and
prints algorithm, claims, and expiration, plus a few non-exploitative
sanity checks (e.g. `alg: none`, missing `exp`, sensitive-looking claim
names).

```bash
python main.py jwt <token>
python main.py jwt --file token.txt
echo "<token>" | python main.py jwt --json     # machine-readable output
```

Example output:
```
Algorithm   : RS256
Subject     : raghavendraonline99@gmail.com
Role        : user
Expires     : 2027-01-03 19:31:33 UTC
```

## Module 2 — Username / Account Enumeration Detector

Sends a small set of login attempts (defined in a JSON config) against a
login endpoint and flags differences in status code, response body, length,
or timing between identity groups (e.g. "registered" vs "unregistered").
This automates the classic OWASP WSTG-IDNT-04 check.

1. Copy `findings/auth_checker_config.sample.json` and fill in your
   authorized target URL and test identities.
2. Run:

```bash
python main.py enum --config findings/my_config.json --yes
```

(Omit `--yes` to get an interactive authorization confirmation prompt
first.) Add `--save reports/enum_result.json` to persist full results.

Example output:
```
Potential Username Enumeration Detected

User A (unregistered):
"Given Email is not registered!"

User B (registered):
"Invalid Credentials"
```

## Module 3 — API Mapper

Maintains a simple JSON inventory of endpoints discovered during recon and
generates a Markdown report from it.

```bash
python main.py map --list
python main.py map --add /workshop/api/shop/products --method GET --auth yes --desc "Product listing"
python main.py map --report reports/api_inventory_report.md
```

`findings/endpoints.json` ships with the three endpoints already on file:

```json
[
  "/identity/api/auth/login",
  "/identity/api/v2/vehicle/vehicles",
  "/workshop/api/shop/products"
]
```

## Module 4 — VAPT Report

`reports/VAPT_Finding_Username_Enumeration.md` is a ready-to-use,
professionally structured write-up of the enumeration finding (Title,
Severity, Description, Steps to Reproduce, Evidence, Impact,
Recommendation, References). Fill in the bracketed placeholders
(target name, dates, redacted test identifiers) before sharing externally.

## Notes

- `auth_checker.py` only sends requests you configure (no hard-coded
  hostnames) and requires you to type a confirmation (or pass `--yes`)
  before firing requests, as a basic safeguard against accidental misuse.
- None of these modules attempt to crack JWT signatures, brute-force
  passwords, or exploit anything beyond observing/comparing ordinary HTTP
  responses — they're assessment/reporting aids, not attack tools.
