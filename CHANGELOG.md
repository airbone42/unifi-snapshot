# Changelog

All notable changes to this project are documented in this file. Versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-20

First public release.

### Added

- `unifi-snapshot export --out DIR`: read-only export of the UniFi Network configuration (Integration API plus optional legacy API) as normalized YAML, one file per object, written atomically.
- `unifi-snapshot check`: tests connection and API key.
- Configuration via `UNIFI_HOST`, `UNIFI_API_KEY`, `UNIFI_VERIFY_TLS`, `UNIFI_CA_FILE`, `UNIFI_LEGACY`.
- TLS certificate pinning by SHA-256 fingerprint.
- Redaction by key name plus content-based detection of PEM and base64-encoded PEM private keys.
- Export of the legacy v2 objects used by the OpenTofu provider `ubiquiti-community/unifi` (firewall policies, firewall zones, static DNS) under `legacy/v2/`, with raw IDs and without hit counters.
- `unifi_snapshot.normalize.redact_text` for redacting private keys in free text.
- `unifi_snapshot.model` with `load_v2` and `policy_from_v2` for invariant checks on v2 data.
- Example commit script and systemd units in `examples/`.
