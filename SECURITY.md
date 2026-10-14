# Security policy

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private vulnerability reporting ("Report a vulnerability" under the Security tab of this repository).

We aim to acknowledge reports within 3 business days and to publish a fix or mitigation within 30 days for high-severity issues. We credit reporters unless they prefer otherwise.

## Scope

- Vulnerabilities in PostShor itself: code execution through crafted input files, path traversal, unsafe parsing, report injection (for example script injection into HTML reports).
- Incorrect security guidance: a rule or remediation that would lead users to a *less* secure configuration.

Missed detections and false positives are ordinary bugs; please open a normal issue.

## How PostShor handles your code

- Scans run locally. A code scan makes no network requests.
- `postshor tls` connects only to the endpoints you name and performs standard TLS handshakes.
- No telemetry is collected.
