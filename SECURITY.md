# Security policy

## Supported scope

Security review covers the current default branch only. Earlier commits,
unmerged branches, locally modified copies, and unofficial distributions are
not maintained security releases. This repository has no published release,
service deployment, license grant, or response-time service-level agreement.

The application is designed for an unprivileged loopback-only deployment using
the documented Waitress command. Treat a change to the bind address, transport,
authentication model, session model, storage, or request boundary as a new
security design that requires separate review.

## Report a vulnerability privately

Use
[GitHub private vulnerability reporting](https://github.com/omar07ibrahim/PasswordGenerator/security/advisories/new)
for a suspected vulnerability. Please include:

- the exact commit SHA and Python/platform versions;
- the affected command, local route, or source component;
- a minimal reproduction using synthetic data;
- the expected and observed behavior; and
- the likely impact and any suggested containment.

Do not include a real password, API token, private key, personal data, or other
credential. Do not probe a deployment you do not own or have explicit
permission to test. If private reporting is unavailable, open a public issue
containing only non-sensitive coordination details.

Reports are handled on a best-effort basis. A report may be closed as out of
scope when it depends on an unsupported deployment boundary or does not affect
the current default branch.

## Explicit security limits

This project demonstrates exact counting and one uniform application-level
rank selection. It is not an authentication system, password-strength meter,
secret vault, breach checker, calibration service, or hosted generator.

The deterministic `rank` and `unrank` commands are reversible inspection tools
for public test vectors. They must not be used with credentials. Generated
values are not persisted by project code, but Python, terminal, browser, and
clipboard memory cannot provide zeroization guarantees.

Direct dependencies are version-pinned, while the development install is not a
hash-locked dependency environment. The canonical distribution attestation
does not claim dependency integrity, a signature, cross-platform byte
reproducibility, or safety for arbitrary archives. Repository-hosted scanning,
protection, and alert settings are operational GitHub state rather than
properties proven by committed evidence.
