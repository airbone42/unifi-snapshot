"""Normalisierung: Secrets entfernen, flüchtige Felder streichen, IDs in Namen auflösen."""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from typing import Any

REDACTED = "<redacted>"

# Schlüssel, deren String-Werte nie im Repo landen dürfen.
# UniFi kennzeichnet Secrets in der Legacy-API mit dem Präfix "x_".
SECRET_KEY_RE = re.compile(
    r"(^x_)|passphrase|password|passwd|secret|preshared|private_?key|certificate_key|psk|token|api_?key|device_auth",
    re.IGNORECASE,
)

# Felder, die sich ohne Konfigurationsänderung ändern und nur Rauschen im Diff erzeugen.
# Bei neuem Rauschen nach dem ersten Lauf hier ergänzen.
VOLATILE_KEYS = {
    "updatedAt",
    "lastModified",
    "last_modified",
    "lastSeen",
    "last_seen",
    "uptime",
    "_uptime",
    "first_seen",
    "setting_preference_last_updated",
    "last_alert_id",
    "last_honeypot_id",
    "last_nmap_id",
}

# Zusätzlich flüchtig nur in den Legacy-v2-Objekten (Trefferzähler der Firewall-Policies).
# Bewusst nicht in VOLATILE_KEYS, damit sich der übrige Export nicht ändert.
V2_VOLATILE_KEYS = {"hits", "last_hit"}


def _looks_like_private_key(value: str) -> bool:
    """Sicherheitsnetz unabhängig vom Feldnamen: PEM-Private-Keys, auch base64-kodiert."""
    if "PRIVATE KEY" in value:
        return True
    if value.startswith("LS0tLS1CRUdJTi"):  # base64 von "-----BEGIN"
        try:
            return b"PRIVATE KEY" in base64.b64decode(value, validate=False)
        except (binascii.Error, ValueError):
            return False
    return False


def redact(obj: Any, _key: str | None = None) -> Any:
    if isinstance(obj, dict):
        return {k: redact(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [redact(v, _key) for v in obj]
    if isinstance(obj, str) and obj:
        if (_key and SECRET_KEY_RE.search(_key)) or _looks_like_private_key(obj):
            return REDACTED
    return obj


# PEM-Block eines Private Keys, auch ohne END-Zeile (z. B. abgeschnittene Logs): dann bis zum Textende
_PEM_BLOCK_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
# END-Zeile ohne BEGIN (Text vorne abgeschnitten): vorangehende base64-Zeilen mit maskieren,
# Backslash erlaubt, damit auch JSON-escapte Zeilenumbrüche ("\n" als Zeichen) erfasst werden
_PEM_ORPHAN_END_RE = re.compile(
    r"(?:^[A-Za-z0-9+/=\\]+[ \t]*\r?\n)*[A-Za-z0-9+/=\\]*-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.MULTILINE,
)
# base64-kodiertes PEM ("-----BEGIN" wird zu "LS0tLS1CRUdJTi")
_B64_PEM_RE = re.compile(r"LS0tLS1CRUdJTi[A-Za-z0-9+/=]*")


def _b64_is_private_key(token: str) -> bool:
    # Auf ein Vielfaches von 4 kürzen, damit auch abgeschnittene Tokens dekodierbar sind
    token = token.rstrip("=")
    token = token[: len(token) - len(token) % 4]
    try:
        return b"PRIVATE KEY" in base64.b64decode(token, validate=False)
    except (binascii.Error, ValueError):
        return False


def redact_text(text: str) -> str:
    """Maskiert Private Keys in Freitext (Logs, Telegram-Nachrichten, Plan-Ausgaben).

    Erkennt PEM-Blöcke ("-----BEGIN ... PRIVATE KEY-----" bis zur END-Zeile, ohne END-Zeile
    bis zum Textende), verwaiste END-Zeilen samt vorangehender base64-Zeilen und
    base64-kodierte PEM-Private-Keys. Zertifikate und Public Keys bleiben stehen.
    Feldnamen-basierte Redaction gibt es nur in `redact`, weil Freitext keine Schlüssel hat.
    """
    if not text:
        return text
    text = _PEM_BLOCK_RE.sub(REDACTED, text)
    text = _PEM_ORPHAN_END_RE.sub(REDACTED, text)
    return _B64_PEM_RE.sub(lambda m: REDACTED if _b64_is_private_key(m.group(0)) else m.group(0), text)


def strip_volatile(obj: Any, keys: set[str] | None = None) -> Any:
    """Entfernt flüchtige Felder rekursiv, standardmäßig `VOLATILE_KEYS`."""
    if keys is None:
        keys = VOLATILE_KEYS
    if isinstance(obj, dict):
        return {k: strip_volatile(v, keys) for k, v in obj.items() if k not in keys}
    if isinstance(obj, list):
        return [strip_volatile(v, keys) for v in obj]
    return obj


def resolve_ids(obj: Any, idmap: dict[str, str], _key: str | None = None) -> Any:
    """Ersetzt bekannte IDs in Referenzfeldern durch lesbare Namen (z. B. "zone:lan").

    Das eigene "id"/"_id"-Feld eines Objekts bleibt unverändert, damit die Zuordnung
    zur Live-Konfiguration erhalten bleibt.
    """
    if isinstance(obj, dict):
        return {k: resolve_ids(v, idmap, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [resolve_ids(v, idmap, _key) for v in obj]
    if isinstance(obj, str) and _key not in ("id", "_id") and obj in idmap:
        return idmap[obj]
    return obj


def slugify(value: str) -> str:
    value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-._").lower()
    return value or "unnamed"


def display_name(obj: dict) -> str:
    for key in ("name", "key", "domain", "hostname", "mac", "id", "_id"):
        if obj.get(key):
            return str(obj[key])
    return "unnamed"


def object_id(obj: dict) -> str:
    return str(obj.get("id") or obj.get("_id") or "")


def build_names(objs: list[dict]) -> dict[str, str]:
    """Liefert id -> eindeutiger Name. Doppelte Namen bekommen ein ID-Suffix."""
    counts: dict[str, int] = {}
    for o in objs:
        n = display_name(o)
        counts[n] = counts.get(n, 0) + 1
    names = {}
    for o in objs:
        n = display_name(o)
        oid = object_id(o)
        names[oid] = f"{n}#{oid[-6:]}" if counts[n] > 1 and oid else n
    return names
