# unifi-snapshot

Read-only export of a UniFi Network configuration as normalized YAML, one file per object, with secret redaction. Commit the output to a **private** Git repository on a schedule and every change made in the UniFi UI (or by automation) shows up as a readable diff.

The snapshot also serves as an independent check after automated changes: it exports the legacy v2 objects used by the OpenTofu/Terraform provider [`ubiquiti-community/unifi`](https://registry.terraform.io/providers/ubiquiti-community/unifi), with their raw IDs, so a fresh export can be compared against a plan. The module `unifi_snapshot.model` loads these objects for invariant checks.

> **Disclaimer:** This project is not affiliated with, endorsed by, or supported by Ubiquiti Inc. "UniFi" is a trademark of Ubiquiti Inc. Parts of the export use the unofficial, undocumented legacy API, which may change or break with any UniFi Network release. Tested with UniFi Network 10.6 on a UDM.

The tool only sends `GET` requests. It never changes anything on the controller.

## What is exported

Official Integration API (`/proxy/network/integration/v1`, API key):
networks, WiFi broadcasts, firewall zones, firewall policies (grouped by zone pair) including their ordering, ACL rules including ordering, DNS policies, traffic matching lists, RADIUS profiles, WANs, VPN servers, site-to-site tunnels, device tags.

Unofficial legacy API (best effort, disable with `UNIFI_LEGACY=false`):
`networkconf`, `wlanconf` (including PPSK assignments), port forwards, firewall groups, static routes, port profiles, dynamic DNS, controller settings, WireGuard peers, and known clients that carry configuration (VLAN override, fixed IP, local DNS record, fixed AP, blocked).

Legacy v2 objects (same switch `UNIFI_LEGACY`), as used by the OpenTofu provider:
firewall policies (`/v2/api/site/<site>/firewall-policies`), firewall zones (`.../firewall/zone`), static DNS records (`.../static-dns`).

Not exported: device and client state (uptime, statistics) and anything else without configuration character.

## Installation

Requires Python 3.13 or newer. The only dependency is PyYAML.

```bash
pip install "git+https://github.com/airbone42/unifi-snapshot@v0.1.0"
```

Pin a release tag. This installs the console script `unifi-snapshot`; `python -m unifi_snapshot` works as well.

## Configuration

All settings come from environment variables (see `.env.example`):

| Variable | Default | Meaning |
|---|---|---|
| `UNIFI_HOST` | (required) | Console URL without path, e.g. `https://192.0.2.1` |
| `UNIFI_API_KEY` | (required) | API key: Settings > Control Plane > Integrations > Create API Key |
| `UNIFI_CA_FILE` | (unset) | PEM file of the console certificate. Enables SHA-256 fingerprint pinning (recommended) |
| `UNIFI_VERIFY_TLS` | `true` | Normal certificate chain validation. `false` disables TLS verification (first tests only) |
| `UNIFI_LEGACY` | `true` | Also export the unofficial legacy API (v1 and v2). Set to `false` if the console rejects the key there |

Create a dedicated local account for the API key and keep the key out of every repository.

**TLS pinning.** UniFi consoles usually present a self-signed certificate whose "CA" lacks the CA flag, so normal chain validation fails. Pin the leaf certificate instead:

```bash
openssl s_client -connect 192.0.2.1:443 </dev/null 2>/dev/null | openssl x509 > /etc/unifi-snapshot/console.pem
```

The tool then compares the SHA-256 fingerprint of the server certificate with this file and does not validate the chain or the hostname. When the console renews its certificate, run the command again.

## Usage

```bash
set -a; . ./.env; set +a
unifi-snapshot check                 # test connection and API key
unifi-snapshot export --out state    # write the snapshot
```

`--no-legacy` has the same effect as `UNIFI_LEGACY=false`. `-v` enables debug logging.

Exit codes: `0` success, `1` missing configuration, `2` API error (the previous snapshot stays untouched).

## Output structure

```
state/
  _meta.yaml                                  Network version, skipped endpoints per site
  default/                                    one folder per site (legacy site name)
    networks/<name>.yaml
    wifi/<name>.yaml
    firewall/zones/<name>.yaml
    firewall/policies/<source>__<destination>/<name>.yaml
    firewall/ordering/<source>__<destination>.yaml
    acl-rules/...
    dns-policies/<domain>.yaml
    legacy/networkconf/<name>.yaml
    legacy/wireguard-users/<network>.yaml
    legacy/...
    legacy/v2/firewall-policies/<name>-<id suffix>.yaml
    legacy/v2/firewall-zones/<name>-<id suffix>.yaml
    legacy/v2/static-dns/<key>-<id suffix>.yaml
```

Normalization:

- **Secrets:** values of keys such as `passphrase`, `password`, `x_*`, `private_key`, `preshared_key` are replaced by `<redacted>`. Independent of the key name, any string that contains a PEM private key, or a base64-encoded PEM private key, is redacted as well. Public keys and certificates stay. See `SECRET_KEY_RE` in `unifi_snapshot/normalize.py`.
- **IDs (Integration API and legacy v1):** references are resolved to readable names, e.g. `zoneId: zone:lan`. The object's own `id`/`_id` stays.
- **IDs (legacy v2):** kept raw. `_id`, `source.zone_id`, `destination.zone_id` and all other IDs are not replaced, so the files can be compared with OpenTofu plan JSON. Only the volatile hit counters `hits` and `last_hit` are removed. File names carry the last six characters of the ID because names are often not unique.
- **Noise:** fields like `updatedAt` are removed (`VOLATILE_KEYS`).
- **Atomic:** the export first writes to a temporary directory next to the target. On an API error the existing snapshot stays unchanged, so an outage is never committed as "everything deleted".

Error handling: endpoints that do not exist in the running Network version (404/405) are skipped with a warning and listed in `_meta.yaml`. The legacy v2 endpoints are also skipped on 401/403. Any other error aborts the export.

## Library use

Redaction for free text, e.g. log lines or chat messages that might contain key material:

```python
from unifi_snapshot.normalize import redact_text

safe = redact_text(message)   # masks PEM and base64-encoded PEM private keys
```

Normalized v2 policies for invariant checks:

```python
from unifi_snapshot.model import load_v2

snap = load_v2("state", site="default")
for p in snap.policies:
    if p.source_zone == "isolated" and p.destination_zone == "External" and p.action == "ALLOW":
        print("isolated segment may only reach the outside through its gateway:", p.name, p.id)
```

`load_v2` returns `zones` (ID to name), `policies` (list of `Policy` with zone names resolved and the raw object in `raw`) and `dns` (raw static DNS records). It raises `FileNotFoundError` if zones or policies are missing, so a check never passes on empty data.

## Scheduled snapshots

`examples/` contains a commit script and systemd units:

```bash
install -D -m 755 examples/snapshot.sh /usr/local/lib/unifi-snapshot/snapshot.sh
cp examples/unifi-snapshot.service examples/unifi-snapshot.timer /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now unifi-snapshot.timer
```

The script exports into a working copy of your snapshot repository, commits changes and pushes. Paths (`SNAPSHOT_REPO`, `SNAPSHOT_SUBDIR`, `UNIFI_ENV_FILE`, `UNIFI_SNAPSHOT`, `SNAPSHOT_PUSH`, `SNAPSHOT_LOCK`) are defaults that can be overridden via environment, for example in a systemd drop-in. Run it on a small dedicated host that can reach only the console API and your Git server, not on the Git server itself.

## Security

- **Always keep snapshot repositories private.** Even with redaction, a snapshot reveals your network layout, addresses, firewall rules, client names and MAC addresses.
- Redaction is a safety net, not a guarantee. Review the first snapshots before you push them anywhere, and report gaps (see [SECURITY.md](SECURITY.md)).
- `.env`, `*.pem` and API keys never belong in a repository.
- The API key often has admin rights. Protect the host and the environment file accordingly (mode 600 or 640 with a dedicated group).

## Development

```bash
python -m unittest discover -s tests -v
```

The tests run against a mock controller with invented data and check, among other things, that no secrets end up in the snapshot and that the export is deterministic. Code comments are in German.

## License

MIT, see [LICENSE](LICENSE).
