# Security Policy

OpenXS is a security scanner that runs as root on real production servers.
A vulnerability here is more serious than in most projects - please report
it privately, not through a public issue.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/mrpc/OpenXS/security/advisories/new)
(Security tab → Report a vulnerability). This opens a private advisory
visible only to the maintainers until a fix is ready - it is not a public
issue or discussion.

Please include:
- The affected file(s)/component (e.g. `openxs-watchd.py`, the Webmin module,
  the mod_security hook).
- Steps to reproduce, or a minimal proof of concept.
- The impact as you see it (e.g. RCE, privilege escalation, DoS, information
  disclosure).

## Supported versions

Only the latest released version is supported with security fixes. There is
no long-term-support branch at this stage of the project.

## Response

This is currently a single-maintainer project. There's no guaranteed SLA,
but reports are read as soon as possible and a real vulnerability will be
prioritized over other work.
