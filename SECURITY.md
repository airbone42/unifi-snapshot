# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub Security Advisories:
<https://github.com/<owner>/unifi-snapshot/security/advisories/new>

Do not open a public issue for security problems. If a report involves real configuration data, strip it down to a minimal, invented example first. Never attach a real snapshot, API key, certificate or private key.

You can expect an initial response within a few days. Fixes are released as a new patch version and noted in `CHANGELOG.md`.

## What counts as a vulnerability

- A secret (password, passphrase, pre-shared key, private key, token, API key) that ends up unredacted in a snapshot or passes through `redact_text`.
- Anything that makes the tool send requests other than `GET` to the controller.
- TLS verification or certificate pinning that can be bypassed.
- Snapshot files written outside the given output directory.

## Supported versions

Only the latest release receives fixes.

## Operating the tool safely

- **Snapshot repositories must always be private.** Redaction removes secrets, but a snapshot still describes your whole network: addresses, firewall rules, client names and MAC addresses.
- Keep the API key in an environment file with restrictive permissions on a dedicated host, never in a repository.
- Pin the console certificate with `UNIFI_CA_FILE` instead of disabling TLS verification.
- Install from a pinned release tag, not from `main`.
