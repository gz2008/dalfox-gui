# Security Policy

## Intended Use

Dalfox GUI is designed for local labs, CTF environments, and systems for
which the user has explicit authorization. The GUI blocks public targets
before invoking Dalfox.

Do not use this project to test systems without permission.

## Sensitive Data

- Cookies, Authorization headers, API keys, and OOB secrets are redacted
  from command previews.
- Sensitive fields are not persisted by the GUI.
- Logs are only saved when the user explicitly chooses a path.
- Review saved logs before sharing them because scan output may contain
  target responses or parameter values.

## Reporting a Vulnerability

Open a GitHub issue for non-sensitive defects. Do not include credentials,
cookies, private URLs, or other sensitive data in reports.
