# Vulnerability Assessment Report

## Finding: Username / Account Enumeration via Inconsistent Authentication Error Messages

| Field | Detail |
|---|---|
| **Finding ID** | AVAPT-2026-001 |
| **Target** | `[Application / Host Name]` — Login endpoint: `/identity/api/auth/login` |
| **Tested By** | `[Your Name]` |
| **Date** | `[Test Date]` |
| **Severity** | **Medium** |
| **CVSS v3.1 (indicative)** | 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N) |
| **OWASP Reference** | A07:2021 – Identification and Authentication Failures; OWASP WSTG-IDNT-04 (Testing for Account Enumeration) |
| **Status** | Open |

---

## 1. Title

Username / Account Enumeration via Inconsistent Login Error Messages

## 2. Severity

**Medium.** The vulnerability does not directly disclose credentials or grant
unauthorized access, but it allows an attacker to reliably determine which
email addresses/usernames are registered on the platform. This materially
lowers the cost of follow-on attacks such as credential stuffing, targeted
phishing, and password-spraying, and may itself constitute a privacy/PII
disclosure issue depending on applicable regulations (e.g. data protection
laws governing confirmation of an individual's association with a service).

## 3. Description

The application's login endpoint (`POST /identity/api/auth/login`) returns
**different error messages depending on whether the supplied identity
(email/username) exists in the system**, even though the supplied password
is incorrect in both cases.

- When an unregistered identity is submitted, the API returns a message
  indicating the email is not registered.
- When a registered identity is submitted with a wrong password, the API
  returns a generic "invalid credentials" message.

Because the two cases are distinguishable, an attacker can script a large
number of login attempts using a list of candidate email addresses/usernames
and use the response differences to build a list of confirmed, registered
accounts — without ever needing a valid password.

## 4. Steps to Reproduce

1. Identify the authentication endpoint: `POST /identity/api/auth/login`.
2. Send a login request using an email address **known to be registered**
   on the platform, paired with an incorrect password. Record the HTTP
   status code and response body.
3. Send a second login request using an email address **known/highly
   likely to be unregistered** (e.g. a randomly generated address), paired
   with the same incorrect password. Record the HTTP status code and
   response body.
4. Compare the two responses (status code, message text, response length,
   and optionally response timing).
5. Observe that the responses differ in a way that discloses account
   existence.
6. (Optional, for proof-of-concept only, with authorization) Repeat the
   process with a small list of candidate addresses to demonstrate that the
   behavior is consistent and scriptable — the included
   `modules/auth_checker.py` tool automates steps 2–5.

## 5. Evidence

**Request A — Unregistered identity**
```
POST /identity/api/auth/login
Content-Type: application/json

{
  "email": "<unregistered_test_address>",
  "password": "<incorrect_password>"
}
```
Response:
```
HTTP/1.1 404 Not Found
{
  "message": "Given Email is not registered!"
}
```

**Request B — Registered identity, wrong password**
```
POST /identity/api/auth/login
Content-Type: application/json

{
  "email": "<registered_test_address>",
  "password": "<incorrect_password>"
}
```
Response:
```
HTTP/1.1 401 Unauthorized
{
  "message": "Invalid Credentials"
}
```

**Observed difference:** distinct HTTP status codes (404 vs 401) and
distinct response bodies, both keyed directly to whether the email exists,
independent of the password supplied.

> Replace the bracketed test addresses above with sanitized/redacted
> identifiers before sharing this report externally. Do not include real,
> non-test user data such as third-party email addresses in the final
> evidence section.

## 6. Impact

- **Account enumeration at scale:** An attacker can automate this check
  against large candidate lists (e.g. breach-derived email lists) to build
  a verified set of registered accounts.
- **Credential stuffing / password spraying:** A verified account list
  significantly increases the efficiency and success rate of subsequent
  credential-stuffing or password-spraying attacks, since effort is no
  longer wasted on non-existent accounts.
- **Targeted phishing:** Confirmed account existence can be used to craft
  more convincing, targeted phishing campaigns against known users of the
  service.
- **Privacy exposure:** Confirming that a specific email address is
  associated with the platform may itself be sensitive, depending on the
  nature of the service and applicable privacy regulations.

## 7. Recommendation

1. **Return identical responses** for "user not found" and "invalid
   password" scenarios — same HTTP status code, same generic message body
   (e.g. `"Invalid email or password."`) — for both the login endpoint and
   any related endpoints (password reset, registration, OTP request, etc.).
2. **Normalize timing.** Ensure both code paths take a comparable amount of
   time to respond (e.g. always perform a password hash comparison, even
   against a dummy hash, for non-existent users) to prevent timing-based
   enumeration.
3. **Rate-limit and monitor authentication endpoints** (e.g. per-IP and
   per-identity throttling, CAPTCHA after repeated failures, alerting on
   high-volume distinct-identity login attempts) to reduce the practicality
   of automated enumeration even if message parity is imperfect.
4. **Apply the same generic-response principle** consistently across all
   account-related flows (signup "email already exists" messages, password
   reset flows, OTP/2FA flows), since enumeration commonly leaks through
   more than one endpoint.
5. **Re-test after remediation** using the same paired-request methodology
   (see `modules/auth_checker.py` in this repository) to confirm responses
   are indistinguishable across status code, body content, length, and
   timing.

## 8. References

- OWASP Top 10 2021 — A07: Identification and Authentication Failures
  (https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- OWASP Web Security Testing Guide — WSTG-IDNT-04: Testing for Account
  Enumeration and Guessable User Account
  (https://owasp.org/www-project-web-security-testing-guide/)
- CWE-203: Observable Discrepancy

---
*This report was produced as part of an authorized security assessment.
Sensitive details (target name, real identifiers, dates) should be filled
in/redacted appropriately before distribution.*
