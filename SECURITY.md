# Security policy

Quiver is intended only for authorized testing of local, deliberately
vulnerable targets. Do not point it at systems you do not own or have explicit
permission to assess.

## Reporting a vulnerability

Please do not disclose a vulnerability, credential, or campaign report in a
public issue. Use the repository's private vulnerability-reporting feature in
the Security tab. Include the affected revision, impact, and a minimal safe
reproduction when possible.

If private vulnerability reporting is unavailable, ask the maintainers to
enable a private reporting channel without including sensitive details in the
request.

## Handling campaign output

Campaign reports can contain application data and reproduction requests.
Credential-shaped values are redacted, but reports should still be treated as
sensitive assessment artifacts. Store them under the ignored `.prototype/`
directory, inspect them before sharing, and never commit reports from a real
assessment.
