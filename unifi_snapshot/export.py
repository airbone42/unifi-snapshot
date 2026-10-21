"""Snapshot der Live-Konfiguration als YAML, eine Datei pro Objekt."""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

import yaml

from .client import ApiError, UnifiClient
from .normalize import (
    V2_VOLATILE_KEYS,
    VOLATILE_KEYS,
    build_names,
    display_name,
    object_id,
    redact,
    resolve_ids,
    slugify,
    strip_volatile,
)

log = logging.getLogger(__name__)

T = TypeVar("T")
R = TypeVar("R")

# kind, Zielordner, Listen-Pfad, Detail-Pfad (oder None)
INTEGRATION_RESOURCES = [
    ("network", "networks", "/networks", "/networks/{id}"),
    ("wifi", "wifi", "/wifi/broadcasts", "/wifi/broadcasts/{id}"),
    ("zone", "firewall/zones", "/firewall/zones", "/firewall/zones/{id}"),
    ("policy", "firewall/policies", "/firewall/policies", "/firewall/policies/{id}"),
    ("acl", "acl-rules", "/acl-rules", "/acl-rules/{id}"),
    ("dns", "dns-policies", "/dns/policies", "/dns/policies/{id}"),
    ("tml", "traffic-matching-lists", "/traffic-matching-lists", "/traffic-matching-lists/{id}"),
    ("radius", "radius-profiles", "/radius/profiles", None),
    ("wan", "wans", "/wans", None),
    ("vpn-server", "vpn/servers", "/vpn/servers", None),
    ("s2s", "vpn/site-to-site", "/vpn/site-to-site-tunnels", None),
    ("tag", "device-tags", "/device-tags", None),
]

# kind, Zielordner, Pfad ({s} = Site-Referenz, z. B. "default")
LEGACY_RESOURCES = [
    ("lnet", "legacy/networkconf", "/api/s/{s}/rest/networkconf"),
    ("lwlan", "legacy/wlanconf", "/api/s/{s}/rest/wlanconf"),
    ("portforward", "legacy/portforward", "/api/s/{s}/rest/portforward"),
    ("fwgroup", "legacy/firewallgroup", "/api/s/{s}/rest/firewallgroup"),
    ("route", "legacy/routing", "/api/s/{s}/rest/routing"),
    ("portprofile", "legacy/portconf", "/api/s/{s}/rest/portconf"),
    ("ddns", "legacy/dynamicdns", "/api/s/{s}/rest/dynamicdns"),
    ("setting", "legacy/setting", "/api/s/{s}/get/setting"),
    ("client", "legacy/clients", "/api/s/{s}/rest/user"),
]

# Legacy-v2-Objekte, die der OpenTofu-Provider ubiquiti-community/unifi verwendet.
# kind, Zielordner, Pfad ({s} = Legacy-Site-Name, z. B. "default").
# Diese Objekte bleiben weitgehend roh (keine ID-Auflösung), damit `_id` und Zonen-IDs
# direkt mit dem Plan-JSON von OpenTofu vergleichbar sind.
LEGACY_V2_RESOURCES = [
    ("v2-policy", "legacy/v2/firewall-policies", "/v2/api/site/{s}/firewall-policies"),
    ("v2-zone", "legacy/v2/firewall-zones", "/v2/api/site/{s}/firewall/zone"),
    ("v2-dns", "legacy/v2/static-dns", "/v2/api/site/{s}/static-dns"),
]

# Bekannte Clients nur dann exportieren, wenn an ihnen Konfiguration hängt
CLIENT_CONFIG_FLAGS = (
    "use_fixedip",
    "local_dns_record_enabled",
    "virtual_network_override_enabled",
    "fixed_ap_enabled",
    "blocked",
)
CLIENT_KEEP_KEYS = {
    "_id", "mac", "name", "note", "usergroup_id", "network_id", "blocked",
    "use_fixedip", "fixed_ip", "local_dns_record_enabled", "local_dns_record",
    "virtual_network_override_enabled", "virtual_network_override_id",
    "fixed_ap_enabled", "fixed_ap_mac",
}


@dataclass
class Item:
    kind: str
    folder: str
    obj: dict
    subfolder: str = ""


@dataclass
class Snapshot:
    items: list[Item] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)  # relpath -> Daten
    raw_extra: dict[str, Any] = field(default_factory=dict)  # relpath -> Daten ohne ID-Auflösung
    skipped: list[str] = field(default_factory=list)
    idmap: dict[str, str] = field(default_factory=dict)


def _not_available(e: ApiError) -> bool:
    # 404/405: Endpoint gibt es in dieser Network-Version nicht
    return e.status in (404, 405)


def _v2_skippable(e: ApiError) -> bool:
    # v2-Endpunkte sind optional: fehlen (404/405) oder Key abgelehnt (401/403) -> überspringen
    return e.status in (401, 403, 404, 405)


def _map(fn: Callable[[T], R], args: Iterable[T], workers: int) -> list[R]:
    """fn auf alle args anwenden, mit workers > 1 parallel. Reihenfolge bleibt, Fehler werfen.

    Detail- und Reihenfolge-Abfragen machen den Großteil des Exports aus (eine je Policy,
    eine je Zonenpaar) und sind voneinander unabhängig.
    """
    args = list(args)
    if workers <= 1 or len(args) <= 1:
        return [fn(a) for a in args]
    with ThreadPoolExecutor(max_workers=workers) as ex:
        return list(ex.map(fn, args))


def collect_site(client: UnifiClient, site: dict, legacy: bool, workers: int = 1) -> Snapshot:
    snap = Snapshot()
    sid = site["id"]
    base = f"/v1/sites/{sid}"
    zones_raw: dict[str, str] = {}

    for kind, folder, list_path, detail_path in INTEGRATION_RESOURCES:
        try:
            objs = client.paginate(base + list_path)
        except ApiError as e:
            if _not_available(e):
                snap.skipped.append(f"integration{list_path} ({e.status})")
                continue
            raise

        def detail(o: dict, detail_path: str | None = detail_path) -> dict:
            if detail_path and object_id(o):
                try:
                    return {**o, **client.integration(base + detail_path.format(id=object_id(o)))}
                except ApiError as e:
                    if not _not_available(e):
                        raise
            return o

        full = _map(detail, objs, workers)
        names = build_names(full)
        for o in full:
            if object_id(o):
                snap.idmap[object_id(o)] = f"{kind}:{names[object_id(o)]}"
            snap.items.append(Item(kind, folder, o))
        if kind == "zone":
            zones_raw = {object_id(o): names[object_id(o)] for o in full if object_id(o)}

    # Firewall-Policies nach Zonenpaar gruppieren, Reihenfolge je Paar mitsichern
    pairs = set()
    for it in snap.items:
        if it.kind != "policy":
            continue
        src = (it.obj.get("source") or {}).get("zoneId", "")
        dst = (it.obj.get("destination") or {}).get("zoneId", "")
        it.subfolder = f"{slugify(zones_raw.get(src, src or 'any'))}__{slugify(zones_raw.get(dst, dst or 'any'))}"
        if src and dst:
            pairs.add((src, dst))

    def ordering(pair: tuple[str, str]) -> Any:
        try:
            return client.integration(
                base + "/firewall/policies/ordering",
                {"sourceFirewallZoneId": pair[0], "destinationFirewallZoneId": pair[1]},
            )
        except ApiError as e:
            if _not_available(e):
                return None
            raise

    for (src, dst), order in zip(sorted(pairs), _map(ordering, sorted(pairs), workers)):
        if order is None:
            if "integration/firewall/policies/ordering" not in snap.skipped:
                snap.skipped.append("integration/firewall/policies/ordering")
            continue
        rel = f"firewall/ordering/{slugify(zones_raw.get(src, src))}__{slugify(zones_raw.get(dst, dst))}.yaml"
        snap.extra[rel] = order

    try:
        snap.extra["acl-rules/_ordering.yaml"] = client.integration(base + "/acl-rules/ordering")
    except ApiError as e:
        if not _not_available(e):
            raise

    if legacy:
        _collect_legacy(client, site, snap)
    return snap


def _collect_legacy(client: UnifiClient, site: dict, snap: Snapshot) -> None:
    ref = site.get("internalReference") or "default"
    wg_nets = []
    for kind, folder, path in LEGACY_RESOURCES:
        try:
            objs = client.legacy(path.format(s=ref)) or []
        except ApiError as e:
            if _not_available(e):
                snap.skipped.append(f"legacy {path} ({e.status})")
                continue
            raise
        if kind == "client":
            objs = [
                {k: v for k, v in o.items() if k in CLIENT_KEEP_KEYS}
                for o in objs
                if any(o.get(f) for f in CLIENT_CONFIG_FLAGS)
            ]
        if kind == "lnet":
            wg_nets = [
                o for o in objs
                if o.get("purpose") == "remote-user-vpn" and "wireguard" in str(o.get("vpn_type", ""))
            ]
        names = build_names(objs)
        for o in objs:
            if object_id(o):
                snap.idmap[object_id(o)] = f"{kind}:{names[object_id(o)]}"
            snap.items.append(Item(kind, folder, o))

    for net in wg_nets:
        try:
            users = client.legacy(f"/v2/api/site/{ref}/wireguard/{net['_id']}/users")
        except ApiError as e:
            if _not_available(e):
                snap.skipped.append("legacy v2 wireguard users")
                break
            raise
        snap.extra[f"legacy/wireguard-users/{slugify(net.get('name', net['_id']))}.yaml"] = users

    _collect_legacy_v2(client, ref, snap)


def _v2_list(resp: Any) -> list[dict] | None:
    """v2-Antworten sind je nach Endpunkt eine Liste oder {"data": [...]}. None = unbekanntes Format."""
    if isinstance(resp, dict) and "data" in resp:
        resp = resp["data"]
    if resp is None:
        return []
    if not isinstance(resp, list):
        return None
    return [o for o in resp if isinstance(o, dict)]


def _collect_legacy_v2(client: UnifiClient, ref: str, snap: Snapshot) -> None:
    for _kind, folder, path in LEGACY_V2_RESOURCES:
        try:
            objs = _v2_list(client.legacy(path.format(s=ref)))
        except ApiError as e:
            if _v2_skippable(e):
                snap.skipped.append(f"legacy {path} ({e.status})")
                continue
            raise
        if objs is None:
            snap.skipped.append(f"legacy {path} (unerwartetes Antwortformat)")
            continue
        used: set[str] = set()
        for o in sorted(objs, key=object_id):
            oid = object_id(o)
            base = slugify(display_name(o))
            rel = f"{folder}/{base}-{oid[-6:]}.yaml" if oid else f"{folder}/{base}.yaml"
            if rel in used:  # gleicher Name und gleiches ID-Kürzel: volle ID nehmen
                rel = f"{folder}/{base}-{slugify(oid) if oid else len(used)}.yaml"
            used.add(rel)
            snap.raw_extra[rel] = o


def _clean(data: Any, idmap: dict[str, str]) -> Any:
    return resolve_ids(redact(strip_volatile(data)), idmap)


def _clean_raw(data: Any) -> Any:
    # Wie _clean, aber ohne ID-Auflösung und zusätzlich ohne Trefferzähler
    return redact(strip_volatile(data, VOLATILE_KEYS | V2_VOLATILE_KEYS))


def _dump(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        yaml.safe_dump(data, f, sort_keys=True, allow_unicode=True, default_flow_style=False, width=120)


def render(snap: Snapshot, root: Path) -> int:
    count = 0
    used: set[Path] = set()
    for it in sorted(snap.items, key=lambda i: (i.folder, i.subfolder, object_id(i.obj))):
        name = snap.idmap.get(object_id(it.obj), "").split(":", 1)[-1] or display_name(it.obj)
        folder = root / it.folder / it.subfolder if it.subfolder else root / it.folder
        path = folder / f"{slugify(name)}.yaml"
        if path in used and object_id(it.obj):  # Kollision nach Slugify
            path = folder / f"{slugify(name)}-{object_id(it.obj)[-6:]}.yaml"
        n = 2
        while path in used:  # Objekte ohne ID oder gleiches ID-Kürzel: nie überschreiben
            path = folder / f"{slugify(name)}-{n}.yaml"
            n += 1
        used.add(path)
        _dump(path, _clean(it.obj, snap.idmap))
        count += 1
    for rel, data in sorted(snap.extra.items()):
        _dump(root / rel, _clean(data, snap.idmap))
        count += 1
    for rel, data in sorted(snap.raw_extra.items()):
        _dump(root / rel, _clean_raw(data))
        count += 1
    return count


def export(client: UnifiClient, out: Path, legacy: bool = True, workers: int = 1) -> int:
    """Exportiert alle Sites nach `out`. Bricht bei Fehlern ab, ohne `out` anzufassen.

    workers > 1: Detail- und Reihenfolge-Abfragen parallel (gleiches Ergebnis, kürzer).
    """
    info = client.integration("/v1/info")
    sites = client.paginate("/v1/sites")
    out = out.resolve()
    tmp = Path(tempfile.mkdtemp(prefix=".unifi-export-", dir=out.parent))
    try:
        total = 0
        meta = {"application": strip_volatile(info), "sites": {}}
        for site in sites:
            snap = collect_site(client, site, legacy, workers)
            site_dir = tmp / slugify(site.get("internalReference") or site.get("name") or site["id"])
            total += render(snap, site_dir)
            meta["sites"][site.get("name", site["id"])] = {
                "id": site["id"],
                "internalReference": site.get("internalReference"),
                "skipped_endpoints": sorted(set(snap.skipped)),
            }
            for s in snap.skipped:
                log.warning("nicht verfügbar, übersprungen: %s", s)
        _dump(tmp / "_meta.yaml", meta)
        if out.exists():
            shutil.rmtree(out)
        os.replace(tmp, out)
        return total
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
