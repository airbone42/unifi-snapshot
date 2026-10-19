"""Snapshot-Modell für Invarianten-Checks auf den Legacy-v2-Daten.

Liest die von `export` geschriebenen Ordner `<site>/legacy/v2/...` und liefert
normalisierte Firewall-Policies, deren Zonen als Namen aufgelöst sind. Die rohen
Objekte bleiben in `Policy.raw` erhalten, IDs werden nicht verändert.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

V2_DIR = Path("legacy") / "v2"
POLICIES_DIR = "firewall-policies"
ZONES_DIR = "firewall-zones"
DNS_DIR = "static-dns"


@dataclass
class Policy:
    id: str
    name: str
    action: str
    enabled: bool
    index: int | None
    predefined: bool
    source_zone: str | None  # Zonen-NAME, bei unbekannter ID die ID selbst, ohne Zone None
    destination_zone: str | None
    source: dict = field(default_factory=dict)  # rohes source-Objekt
    destination: dict = field(default_factory=dict)  # rohes destination-Objekt
    raw: dict = field(default_factory=dict)  # komplettes Objekt wie im Snapshot


@dataclass
class V2Snapshot:
    zones: dict[str, str]  # Zonen-ID -> Zonen-Name
    policies: list[Policy]
    dns: list[dict]


def _zone_name(zone_id: Any, zones: dict[str, str]) -> str | None:
    if not zone_id:
        return None
    return zones.get(str(zone_id), str(zone_id))


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def policy_from_v2(obj: dict, zones: dict[str, str]) -> Policy:
    """Baut eine `Policy` aus einem v2-Objekt (`/v2/api/site/<site>/firewall-policies`).

    `zones` bildet Zonen-IDs auf Namen ab. Unbekannte Zonen-IDs bleiben als ID stehen,
    damit ein Check sie sieht, statt sie stillschweigend zu verlieren.
    """
    src = obj.get("source") or {}
    dst = obj.get("destination") or {}
    return Policy(
        id=str(obj.get("_id") or obj.get("id") or ""),
        name=str(obj.get("name") or ""),
        action=str(obj.get("action") or "").upper(),
        enabled=bool(obj.get("enabled", False)),
        index=_int_or_none(obj.get("index")),
        predefined=bool(obj.get("predefined", False)),
        source_zone=_zone_name(src.get("zone_id"), zones),
        destination_zone=_zone_name(dst.get("zone_id"), zones),
        source=src,
        destination=dst,
        raw=obj,
    )


def _load_dir(path: Path, required: bool) -> list[dict]:
    if not path.is_dir():
        if required:
            raise FileNotFoundError(f"{path} fehlt (Export mit UNIFI_LEGACY=false oder Endpunkt übersprungen?)")
        return []
    objs = []
    for f in sorted(path.glob("*.yaml")):
        with f.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, dict):
            objs.append(data)
    return objs


def load_v2(snapshot_dir: str | Path, site: str = "default") -> V2Snapshot:
    """Lädt die v2-Daten einer Site aus einem Snapshot-Ordner (Ausgabe von `export --out`).

    Zonen und Policies sind Pflicht, sonst `FileNotFoundError`: Ein Invarianten-Check
    auf leeren Daten würde sonst fälschlich bestehen. Statische DNS-Einträge sind
    optional, weil der Ordner bei null Einträgen nicht angelegt wird.
    """
    base = Path(snapshot_dir) / site / V2_DIR
    zone_objs = _load_dir(base / ZONES_DIR, required=True)
    zones = {str(z.get("_id") or z.get("id")): str(z.get("name") or "") for z in zone_objs if z.get("_id") or z.get("id")}
    policies = [policy_from_v2(o, zones) for o in _load_dir(base / POLICIES_DIR, required=True)]
    policies.sort(key=lambda p: (p.index if p.index is not None else -1, p.id))
    dns = _load_dir(base / DNS_DIR, required=False)
    dns.sort(key=lambda d: (str(d.get("key") or d.get("name") or ""), str(d.get("_id") or "")))
    return V2Snapshot(zones=zones, policies=policies, dns=dns)
