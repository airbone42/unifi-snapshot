"""Export gegen einen Mock-Controller. Start: python -m unittest discover -s tests -v"""

import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

import yaml

import mock_controller as mc
from unifi_snapshot.cli import main
from unifi_snapshot.client import ApiError, UnifiClient
from unifi_snapshot.export import export

V2_OUT = "default/legacy/v2"


class MockTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.host = mc.start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def tearDown(self):
        mc.FAIL.clear()

    def run_export(self, out: Path, key=mc.API_KEY, legacy=True):
        return export(UnifiClient(self.host, key), out, legacy=legacy)


class ExportTest(MockTestCase):
    def test_export(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            self.run_export(out)
            files = sorted(p.relative_to(out).as_posix() for p in out.rglob("*.yaml"))
            all_text = "\n".join((out / f).read_text(encoding="utf-8") for f in files)

            # Keine Secrets im Snapshot
            for secret in ("geheim123", "iotkey", "PRIVKEY", "PSK", "root", "LS0tLS1CRUdJTiBQUklW",
                           "BEGIN RSA PRIVATE", mc.DEVICE_AUTH[:8]):
                self.assertNotIn(secret, all_text, secret)
            self.assertIn("PUB", all_text)  # public keys bleiben
            self.assertIn("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t", all_text)  # Zertifikate bleiben
            self.assertNotIn("last_alert_id", all_text)
            self.assertIn("default/dns-policies/app.home.arpa.yaml", files)

            # Struktur
            self.assertIn("default/firewall/policies/isolated__external/block-isolated-direct.yaml", files)
            self.assertIn("default/firewall/ordering/isolated__external.yaml", files)
            self.assertIn("default/legacy/wireguard-users/vpn.yaml", files)
            self.assertIn("_meta.yaml", files)
            # doppelte Namen kollidieren nicht
            allow = [f for f in files if "policies/lan__external/allow" in f]
            self.assertEqual(len(allow), 2, allow)
            self.assertTrue(any(f.endswith("__external/derived.yaml") for f in files))
            self.assertTrue(any(f.endswith("__external/derived-2.yaml") for f in files))

            # IDs aufgelöst, eigenes id-Feld bleibt
            pol = yaml.safe_load(
                (out / "default/firewall/policies/isolated__external/block-isolated-direct.yaml").read_text())
            self.assertEqual(pol["source"]["zoneId"], "zone:isolated")
            self.assertEqual(pol["id"], mc.POL_1)
            self.assertEqual(pol["description"], "")
            self.assertNotIn("updatedAt", pol)
            order = yaml.safe_load((out / "default/firewall/ordering/isolated__external.yaml").read_text())
            self.assertEqual(order["orderedFirewallPolicyIds"]["beforeSystemDefined"], ["policy:Block isolated direct"])

            # Clients nur mit Konfiguration, ohne Rauschen
            clients = [f for f in files if "/legacy/clients/" in f]
            self.assertEqual(clients, ["default/legacy/clients/device-1.yaml"])
            c = yaml.safe_load((out / clients[0]).read_text())
            self.assertEqual(c["virtual_network_override_id"], "lnet:VPN")
            self.assertNotIn("last_seen", c)

            meta = yaml.safe_load((out / "_meta.yaml").read_text())
            self.assertTrue(any("traffic-matching-lists" in s for s in meta["sites"]["Default"]["skipped_endpoints"]))

    def test_deterministic(self):
        with tempfile.TemporaryDirectory() as d:
            a, b = Path(d) / "a", Path(d) / "b"
            self.run_export(a)
            self.run_export(b)
            fa = {p.relative_to(a): p.read_text(encoding="utf-8") for p in a.rglob("*.yaml")}
            fb = {p.relative_to(b): p.read_text(encoding="utf-8") for p in b.rglob("*.yaml")}
            self.assertEqual(fa, fb)

    def test_error_keeps_old_state(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            self.run_export(out)
            before = sorted(out.rglob("*"))
            with self.assertRaises(ApiError):
                self.run_export(out, key="falsch")
            self.assertEqual(before, sorted(out.rglob("*")))
            self.assertEqual([p for p in Path(d).iterdir() if p.name.startswith(".unifi-export-")], [])


class LegacyV2Test(MockTestCase):
    def test_v2_files(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            self.run_export(out)
            v2 = out / V2_OUT
            files = sorted(p.relative_to(v2).as_posix() for p in v2.rglob("*.yaml"))
            self.assertEqual(files, sorted([
                f"firewall-policies/block-isolated-direct-{mc.V2P_BLOCK[-6:]}.yaml",
                f"firewall-policies/allow-{mc.V2P_ALLOW_A[-6:]}.yaml",
                f"firewall-policies/allow-{mc.V2P_ALLOW_B[-6:]}.yaml",
                f"firewall-policies/allow-all-traffic-{mc.V2P_SYS[-6:]}.yaml",
                f"firewall-zones/lan-{mc.V2Z_LAN[-6:]}.yaml",
                f"firewall-zones/iot-{mc.V2Z_IOT[-6:]}.yaml",
                f"firewall-zones/guest-{mc.V2Z_GUEST[-6:]}.yaml",
                f"firewall-zones/isolated-{mc.V2Z_ISO[-6:]}.yaml",
                f"firewall-zones/external-{mc.V2Z_EXT[-6:]}.yaml",
                f"static-dns/app.home.arpa-{mc.V2D_CNAME[-6:]}.yaml",
                f"static-dns/device-1.home.arpa-{mc.V2D_A[-6:]}.yaml",
            ]))

    def test_v2_objects_stay_raw(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            self.run_export(out)
            v2 = out / V2_OUT
            pol = yaml.safe_load((v2 / f"firewall-policies/block-isolated-direct-{mc.V2P_BLOCK[-6:]}.yaml").read_text())
            # IDs bleiben roh, damit sie mit dem OpenTofu-Plan vergleichbar sind
            self.assertEqual(pol["_id"], mc.V2P_BLOCK)
            self.assertEqual(pol["source"]["zone_id"], mc.V2Z_ISO)
            self.assertEqual(pol["destination"]["zone_id"], mc.V2Z_EXT)
            self.assertEqual(pol["index"], 10000)
            # flüchtige Zähler entfernt, Redaction angewendet
            self.assertNotIn("hits", pol)
            self.assertNotIn("last_hit", pol)
            self.assertEqual(pol["description"], "<redacted>")

            allow = yaml.safe_load((v2 / f"firewall-policies/allow-{mc.V2P_ALLOW_A[-6:]}.yaml").read_text())
            # Legacy-Netz-IDs werden in v2 nicht in "lnet:..." aufgelöst
            self.assertEqual(allow["source"]["network_ids"], [mc.LNET_VPN])
            self.assertEqual(allow["destination"]["ips"], ["10.0.20.5"])

            zone = yaml.safe_load((v2 / f"firewall-zones/lan-{mc.V2Z_LAN[-6:]}.yaml").read_text())
            self.assertEqual(zone["_id"], mc.V2Z_LAN)
            self.assertEqual(zone["network_ids"], [mc.LNET_VPN])

            dns = yaml.safe_load((v2 / f"static-dns/app.home.arpa-{mc.V2D_CNAME[-6:]}.yaml").read_text())
            self.assertEqual(dns, {"_id": mc.V2D_CNAME, "key": "app.home.arpa", "record_type": "CNAME",
                                   "value": "host-1.home.arpa", "enabled": True, "ttl": 0})

            all_text = "\n".join(p.read_text(encoding="utf-8") for p in v2.rglob("*.yaml"))
            self.assertNotIn("MIIEvQIBADAN", all_text)
            # keine aufgelösten Referenzen wie "zone:lan" oder "lnet:VPN"
            self.assertNotIn(": zone:", all_text)
            self.assertNotIn("lnet:", all_text)

    def test_v2_skipped_on_401_and_404(self):
        mc.FAIL[f"{mc.V2}/firewall/zone"] = 404
        mc.FAIL[f"{mc.V2}/static-dns"] = 401
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            with self.assertLogs("unifi_snapshot.export", "WARNING") as logs:
                self.run_export(out)
            v2 = out / V2_OUT
            self.assertTrue((v2 / "firewall-policies").is_dir())
            self.assertFalse((v2 / "firewall-zones").exists())
            self.assertFalse((v2 / "static-dns").exists())
            skipped = yaml.safe_load((out / "_meta.yaml").read_text())["sites"]["Default"]["skipped_endpoints"]
            self.assertIn("legacy /v2/api/site/{s}/firewall/zone (404)", skipped)
            self.assertIn("legacy /v2/api/site/{s}/static-dns (401)", skipped)
            self.assertTrue(any("static-dns" in m for m in logs.output))

    def test_v2_server_error_aborts(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            self.run_export(out)
            before = sorted(out.rglob("*"))
            mc.FAIL[f"{mc.V2}/firewall-policies"] = 500
            with self.assertRaises(ApiError):
                self.run_export(out)
            self.assertEqual(before, sorted(out.rglob("*")))

    def test_legacy_disabled(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            self.run_export(out, legacy=False)
            self.assertFalse((out / "default/legacy").exists())
            self.assertTrue((out / "default/firewall/zones").is_dir())


class CliTest(MockTestCase):
    def cli(self, out: Path, **env) -> int:
        base = {"UNIFI_HOST": self.host, "UNIFI_API_KEY": mc.API_KEY}
        base.update(env)
        clean = {k: v for k, v in os.environ.items() if not k.startswith("UNIFI_")}
        with mock.patch.dict(os.environ, {**clean, **base}, clear=True), redirect_stdout(StringIO()):
            return main(["export", "--out", str(out)])

    def test_env_legacy_default_on(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            self.assertEqual(self.cli(out), 0)
            self.assertTrue((out / V2_OUT / "firewall-policies").is_dir())

    def test_env_legacy_false(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "state"
            self.assertEqual(self.cli(out, UNIFI_LEGACY="false"), 0)
            self.assertFalse((out / "default/legacy").exists())

    def test_env_missing(self):
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(SystemExit):
            main(["export", "--out", "unused"])

    def test_api_error_exit_code(self):
        with tempfile.TemporaryDirectory() as d, mock.patch("sys.stderr", StringIO()):
            self.assertEqual(self.cli(Path(d) / "state", UNIFI_API_KEY="falsch"), 2)


if __name__ == "__main__":
    unittest.main()
