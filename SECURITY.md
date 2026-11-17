# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes (experimental) |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting ("Security" tab → "Report a
vulnerability") on this repository. Include:

- affected version / commit,
- what an attacker could do (for example: escape a decoy, reach the dashboard,
  read unredacted credentials, suppress alerts),
- steps to reproduce on a lab setup.

We aim to acknowledge reports within 3 business days and to agree on a
disclosure date with you. Please give us up to 90 days to ship a fix before
public disclosure.

## Scope

In scope: PhantomNet's own code, container hardening, compose configuration,
isolation scripts, and documentation that could lead to unsafe deployments.

Vulnerabilities in upstream projects (OpenCanary, FastAPI, Docker, etc.) should
be reported to those projects; tell us too if PhantomNet's configuration makes
them exploitable.

Operational hardening guidance: [docs/SECURITY.md](docs/SECURITY.md).
