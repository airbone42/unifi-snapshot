from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .client import ApiError, UnifiClient
from .export import export


def _bool(v: str | None, default: bool) -> bool:
    if v is None or v == "":
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _client() -> UnifiClient:
    host = os.environ.get("UNIFI_HOST")
    key = os.environ.get("UNIFI_API_KEY")
    if not host or not key:
        sys.exit("UNIFI_HOST und UNIFI_API_KEY müssen gesetzt sein (siehe .env.example)")
    return UnifiClient(
        host,
        key,
        verify_tls=_bool(os.environ.get("UNIFI_VERIFY_TLS"), True),
        ca_file=os.environ.get("UNIFI_CA_FILE") or None,
    )


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="unifi-snapshot", description="UniFi-Konfiguration als YAML-Snapshot exportieren")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="Verbindung und API-Key testen")
    e = sub.add_parser("export", help="Live-Konfiguration als YAML-Snapshot schreiben")
    e.add_argument("--out", default="state", type=Path)
    e.add_argument("--no-legacy", action="store_true", help="nur offizielle Integration API (wie UNIFI_LEGACY=false)")
    e.add_argument("--workers", type=int, default=None,
                   help="parallele Abfragen für Details und Reihenfolgen (wie UNIFI_WORKERS, Standard 1)")
    e.add_argument("--full", action="store_true",
                   help="alle Detail- und Reihenfolge-Abfragen ohne Stichprobe (wie UNIFI_FULL_EXPORT=true)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(levelname)s %(message)s")
    client = _client()
    try:
        if args.cmd == "check":
            info = client.integration("/v1/info")
            sites = client.paginate("/v1/sites")
            print(f"OK, Network {info.get('applicationVersion', '?')}, Sites: "
                  + ", ".join(f"{s.get('name')} ({s.get('internalReference')})" for s in sites))
            return 0
        legacy = not args.no_legacy and _bool(os.environ.get("UNIFI_LEGACY"), True)
        workers = args.workers if args.workers is not None else int(os.environ.get("UNIFI_WORKERS") or 1)
        full = args.full or _bool(os.environ.get("UNIFI_FULL_EXPORT"), False)
        n = export(client, args.out, legacy=legacy, workers=max(1, workers), full=full)
        print(f"{n} Dateien nach {args.out} geschrieben")
        return 0
    except ApiError as err:
        print(f"Abbruch, Snapshot unverändert: {err}", file=sys.stderr)
        is_legacy = "/proxy/network/api/" in err.url or "/proxy/network/v2/api/" in err.url
        if err.status in (401, 403) and is_legacy:
            print("Hinweis: Legacy-API lehnt den Key ab? Dann UNIFI_LEGACY=false setzen.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
