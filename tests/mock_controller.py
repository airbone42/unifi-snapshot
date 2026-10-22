"""Mock-Controller für die Tests. Alle Daten sind erfunden (Zonen, IDs, MACs, Adressen)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

API_KEY = "testkey"

SITE = "2ff01f4b-3cb7-4be9-8c0f-36b276c58177"
# Integration API (UUIDs)
Z_ISO, Z_EXT, Z_LAN = (
    "a1a6ab31-03c3-419e-97ae-e8cd14cc1d47",
    "2c37c24b-9b8e-4a36-b745-acf0e33afa2e",
    "6f390d25-50a6-42d0-b424-1e19b2e9b78b",
)
NET_ISO = "feb0fb8e-c338-427f-8789-6298c2d21fca"
WIFI_1 = "d9f7d587-bb6f-4c9d-9843-d465b498615d"
POL_1, POL_2, POL_3 = (
    "7fe011eb-31bf-4da3-b2e3-2dba1cffc144",
    "5c67c002-79ae-446c-bc14-746f896251a4",
    "2e1a1ae5-4487-44f0-ae8a-c211b81b5d7f",
)
DNS_1 = "71895106-4da1-4a0c-8e07-2ba3c45ce6e2"
DEVICE_AUTH = "f80ea0ee-e205-4217-8817-0d91a1040646"

# Legacy-API (24 Hex)
LNET_VPN = "662560cce727cfe1a7d3efa4"
LWLAN_1 = "49c9982c1fd6ec7b583e3a7c"
USER_1, USER_2 = "4a3acf8185ea1680afdaa47c", "5b43d972fc4a5113106e894a"
SET_1, SET_2, SET_3, SET_4 = (
    "1be206d37ee529807ed202cf",
    "b805b1f71e65a6d2b929ba70",
    "f192f311abb2724ea44db42e",
    "b8b3314364f011237464e199",
)

# Legacy v2 (24 Hex), wie sie der OpenTofu-Provider verwendet
V2Z_LAN, V2Z_IOT, V2Z_GUEST, V2Z_ISO, V2Z_EXT = (
    "ec61eff867f604c2e00dbcd7",
    "037e1ef53ac2fb5ec72e6167",
    "bed356d1d9b6267225f3f1c2",
    "6fa6e5b830d87bb37df07b2d",
    "1061fd084ceed876936126b5",
)
V2P_BLOCK, V2P_ALLOW_A, V2P_ALLOW_B, V2P_SYS = (
    "9e55e7cc5b7723ea75d0bdf2",
    "690cd8f19e3b0a141613be85",
    "29213c888ade1f8b36074d93",
    "20a544d2d088e6b707a23295",
)
V2D_CNAME, V2D_A = "b9c56a0907377fe82d007d89", "5cc83b85686629670b0a776e"

I = f"/proxy/network/integration/v1/sites/{SITE}"
L = "/proxy/network/api/s/default"
V2 = "/proxy/network/v2/api/site/default"

# Absichtlich kein Private Key am Stück im Quelltext (Secret-Scanner)
PEM_KEY_FRAGMENT = "-----BEGIN " + "PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"

ROUTES = {
    "/proxy/network/integration/v1/info": {"applicationVersion": "10.6.106"},
    "/proxy/network/integration/v1/sites": {
        "offset": 0, "limit": 200, "count": 1, "totalCount": 1,
        "data": [{"id": SITE, "internalReference": "default", "name": "Default"}],
    },
    f"{I}/networks": {"data": [{"id": NET_ISO, "name": "isolated", "vlanId": 30}], "totalCount": 1},
    f"{I}/networks/{NET_ISO}": {"id": NET_ISO, "name": "isolated", "vlanId": 30, "zoneId": Z_ISO},
    f"{I}/wifi/broadcasts": {"data": [{"id": WIFI_1, "name": "lan-wifi"}], "totalCount": 1},
    f"{I}/wifi/broadcasts/{WIFI_1}": {
        "id": WIFI_1, "name": "lan-wifi", "network": {"networkId": NET_ISO},
        "securityConfiguration": {"type": "WPA2_PERSONAL", "passphrase": "geheim123"},
    },
    f"{I}/firewall/zones": {"data": [
        {"id": Z_ISO, "name": "isolated", "networkIds": [NET_ISO]},
        {"id": Z_EXT, "name": "External"},
        {"id": Z_LAN, "name": "lan"},
    ], "totalCount": 3},
    f"{I}/firewall/policies": {"data": [
        {"id": POL_1, "name": "Block isolated direct", "action": {"type": "BLOCK"}, "description": "",
         "source": {"zoneId": Z_ISO}, "destination": {"zoneId": Z_EXT}, "updatedAt": "2026-10-19"},
        # Abgeleitete Policy ohne ID: darf keinen leeren String als ID belegen
        {"name": "Derived", "source": {"zoneId": Z_LAN}, "destination": {"zoneId": Z_EXT}},
        {"name": "Derived", "source": {"zoneId": Z_LAN}, "destination": {"zoneId": Z_EXT}},
        {"id": POL_2, "name": "Allow", "source": {"zoneId": Z_LAN}, "destination": {"zoneId": Z_EXT}},
        {"id": POL_3, "name": "Allow", "source": {"zoneId": Z_LAN}, "destination": {"zoneId": Z_EXT}},
    ], "totalCount": 3},
    f"{I}/firewall/policies/ordering": {"orderedFirewallPolicyIds": {"beforeSystemDefined": [POL_1]}},
    f"{I}/acl-rules": {"data": [], "totalCount": 0},
    f"{I}/acl-rules/ordering": {"orderedAclRuleIds": []},
    # traffic-matching-lists & Co. fehlen absichtlich -> 404 -> übersprungen
    f"{L}/rest/networkconf": {"meta": {"rc": "ok"}, "data": [
        {"_id": LNET_VPN, "name": "VPN", "purpose": "remote-user-vpn", "vpn_type": "wireguard-server",
         "x_wireguard_private_key": "PRIVKEY"},
    ]},
    f"{L}/rest/wlanconf": {"meta": {"rc": "ok"}, "data": [
        {"_id": LWLAN_1, "name": "lan-wifi", "x_passphrase": "geheim123", "networkconf_id": LNET_VPN,
         "private_preshared_keys_enabled": True,
         "private_preshared_keys": [{"networkconf_id": LNET_VPN, "password": "iotkey"}]},
    ]},
    f"{L}/rest/user": {"meta": {"rc": "ok"}, "data": [
        {"_id": USER_1, "mac": "02:00:00:00:00:01", "name": "device-1", "virtual_network_override_enabled": True,
         "virtual_network_override_id": LNET_VPN, "last_seen": 123, "oui": "Example"},
        {"_id": USER_2, "mac": "02:00:00:00:00:02", "name": "device-2", "last_seen": 456},
    ]},
    f"{L}/get/setting": {"meta": {"rc": "ok"}, "data": [
        {"_id": SET_1, "key": "mgmt", "x_ssh_password": "root", "x_ssh_enabled": True},
        {"_id": SET_2, "key": "radius", "server_certificate": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t",
         "server_certificate_key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURB",
         "other_blob": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIB"},
        {"_id": SET_3, "key": "super_cloudaccess", "device_auth": DEVICE_AUTH},
        {"_id": SET_4, "key": "ips", "last_alert_id": 4711, "ips_mode": "ids"},
    ]},
    f"{I}/dns/policies": {"data": [
        {"id": DNS_1, "type": "CNAME_RECORD", "domain": "app.home.arpa", "targetDomain": "host-1.home.arpa"},
    ], "totalCount": 1},
    f"{V2}/wireguard/{LNET_VPN}/users": [
        {"name": "peer-1", "public_key": "PUB", "preshared_key": "PSK"},
    ],
    # v2: Zonen als nackte Liste
    f"{V2}/firewall/zone": [
        {"_id": V2Z_LAN, "name": "lan", "zone_key": "internal", "default_zone": True, "network_ids": [LNET_VPN]},
        {"_id": V2Z_IOT, "name": "iot", "zone_key": None, "default_zone": False, "network_ids": []},
        {"_id": V2Z_GUEST, "name": "guest", "zone_key": "hotspot", "default_zone": True, "network_ids": []},
        {"_id": V2Z_ISO, "name": "isolated", "zone_key": None, "default_zone": False, "network_ids": []},
        {"_id": V2Z_EXT, "name": "External", "zone_key": "external", "default_zone": True, "network_ids": []},
    ],
    # v2: Policies als {"data": [...]}
    f"{V2}/firewall-policies": {"data": [
        {"_id": V2P_BLOCK, "name": "Block isolated direct", "action": "BLOCK", "enabled": True, "index": 10000,
         "predefined": False, "protocol": "all", "hits": 42, "last_hit": 1760000000,
         "description": PEM_KEY_FRAGMENT,
         "source": {"zone_id": V2Z_ISO, "matching_target": "ANY"},
         "destination": {"zone_id": V2Z_EXT, "matching_target": "ANY"}},
        {"_id": V2P_ALLOW_A, "name": "Allow", "action": "ALLOW", "enabled": True, "index": 10001,
         "predefined": False, "protocol": "tcp", "hits": 7,
         "source": {"zone_id": V2Z_LAN, "matching_target": "NETWORK", "network_ids": [LNET_VPN]},
         "destination": {"zone_id": V2Z_IOT, "matching_target": "IP", "ips": ["10.0.20.5"], "port": "443"}},
        {"_id": V2P_ALLOW_B, "name": "Allow", "action": "ALLOW", "enabled": False, "index": 10000,
         "predefined": False, "protocol": "all",
         "source": {"zone_id": V2Z_LAN, "matching_target": "ANY"},
         "destination": {"zone_id": V2Z_IOT, "matching_target": "ANY"}},
        {"_id": V2P_SYS, "name": "Allow All Traffic", "action": "ALLOW", "enabled": True, "index": 30000,
         "predefined": True, "protocol": "all", "hits": 1000, "last_hit": 1760000001,
         "source": {"zone_id": V2Z_GUEST, "matching_target": "ANY"},
         "destination": {"zone_id": V2Z_EXT, "matching_target": "ANY"}},
    ]},
    # v2: statische DNS-Einträge als nackte Liste
    f"{V2}/static-dns": [
        {"_id": V2D_CNAME, "key": "app.home.arpa", "record_type": "CNAME", "value": "host-1.home.arpa",
         "enabled": True, "ttl": 0},
        {"_id": V2D_A, "key": "device-1.home.arpa", "record_type": "A", "value": "10.0.20.5",
         "enabled": True, "ttl": 300},
    ],
}

# Pfad -> HTTP-Status, zum gezielten Erzeugen von Fehlern in einzelnen Tests
FAIL: dict[str, int] = {}
# (Quellzone, Zielzone) -> Antwort der Reihenfolge-Abfrage, sonst die aus ROUTES
ORDERING: dict[tuple[str, str], dict] = {}
# Alle angefragten Pfade (mit Query), zum Zählen der Abfragen
REQUESTS: list[str] = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        u = urlparse(self.path)
        REQUESTS.append(self.path)
        if self.headers.get("X-API-KEY") != API_KEY:
            self.send_response(401); self.end_headers(); return
        if u.path in FAIL:
            self.send_response(FAIL[u.path]); self.end_headers(); self.wfile.write(b'{"code":"error"}'); return
        body = ROUTES.get(u.path)
        if body is None:
            self.send_response(404); self.end_headers(); self.wfile.write(b'{"code":"not found"}'); return
        if u.path.endswith("/policies/ordering"):
            q = parse_qs(u.query)
            assert q["sourceFirewallZoneId"] and q["destinationFirewallZoneId"]
            body = ORDERING.get((q["sourceFirewallZoneId"][0], q["destinationFirewallZoneId"][0]), body)
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def start() -> tuple[HTTPServer, str]:
    """Startet den Mock-Controller auf einem freien Port. Rückgabe: (Server, Basis-URL)."""
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_port}"
