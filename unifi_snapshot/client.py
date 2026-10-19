"""Minimaler HTTP-Client für die UniFi Network API (Integration API + Legacy API).

Nur Standardbibliothek, damit das Tool ohne venv auf einem LXC läuft.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

INTEGRATION_PREFIX = "/proxy/network/integration"
LEGACY_PREFIX = "/proxy/network"


class ApiError(Exception):
    def __init__(self, status: int | None, url: str, body: str = ""):
        self.status = status
        self.url = url
        self.body = body[:500]
        super().__init__(f"HTTP {status} bei {url}: {self.body}")


def _pinned_handler(pem_file: str) -> urllib.request.HTTPSHandler:
    """Akzeptiert genau das Zertifikat aus `pem_file` (SHA-256-Fingerprint-Pinning).

    Die UDM liefert ein selbstsigniertes Zertifikat samt eigener "CA" ohne CA-Flag.
    Eine normale Kettenprüfung scheitert daran ("invalid CA certificate"), daher wird
    statt der Kette der Fingerprint des Server-Zertifikats verglichen.
    """
    with open(pem_file, encoding="ascii") as f:
        pinned = hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read())).hexdigest()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class PinnedConnection(http.client.HTTPSConnection):
        def connect(self):
            super().connect()
            der = self.sock.getpeercert(binary_form=True)
            actual = hashlib.sha256(der).hexdigest() if der else ""
            if actual != pinned:
                self.sock.close()
                raise ssl.SSLError(f"Zertifikat passt nicht zum Pin (erwartet {pinned[:16]}..., erhalten {actual[:16]}...)")

    class PinnedHandler(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(PinnedConnection, req, context=ctx)

    return PinnedHandler()


class UnifiClient:
    def __init__(
        self,
        host: str,
        api_key: str,
        verify_tls: bool = True,
        ca_file: str | None = None,
        timeout: int = 30,
    ):
        if not host.startswith(("http://", "https://")):
            host = "https://" + host
        self.base = host.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        if ca_file:
            handler = _pinned_handler(ca_file)
        elif verify_tls:
            handler = urllib.request.HTTPSHandler(context=ssl.create_default_context())
        else:
            handler = urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
        self.opener = urllib.request.build_opener(handler)

    # -- low level -----------------------------------------------------------

    def get(self, path: str, query: dict[str, Any] | None = None) -> Any:
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"X-API-KEY": self.api_key, "Accept": "application/json"},
        )
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise ApiError(e.code, url, e.read().decode("utf-8", "replace")) from None
        except urllib.error.URLError as e:
            raise ApiError(None, url, str(e.reason)) from None
        return json.loads(raw) if raw else None

    # -- Integration API (offiziell) -----------------------------------------

    def integration(self, path: str, query: dict[str, Any] | None = None) -> Any:
        return self.get(INTEGRATION_PREFIX + path, query)

    def paginate(self, path: str, page_size: int = 200) -> list[dict]:
        items: list[dict] = []
        offset = 0
        while True:
            resp = self.integration(path, {"offset": offset, "limit": page_size})
            if isinstance(resp, list):
                return resp
            data = resp.get("data") or []
            items.extend(data)
            total = resp.get("totalCount", resp.get("total", len(items)))
            offset += len(data)
            if not data or offset >= total:
                return items

    # -- Legacy API (inoffiziell, best effort) -------------------------------

    def legacy(self, path: str) -> Any:
        resp = self.get(LEGACY_PREFIX + path)
        # v1-Legacy: {"meta": {"rc": "ok"}, "data": [...]}, v2: direkt Liste/Objekt
        if isinstance(resp, dict) and "meta" in resp and "data" in resp:
            return resp["data"]
        return resp
