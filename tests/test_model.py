"""Tests für unifi_snapshot.model (v2-Daten für Invarianten-Checks)."""

import tempfile
import unittest
from pathlib import Path

import yaml

import mock_controller as mc
from unifi_snapshot.client import UnifiClient
from unifi_snapshot.export import export
from unifi_snapshot.model import Policy, V2Snapshot, load_v2, policy_from_v2

ZONES = {"z-lan": "lan", "z-iot": "iot"}


class PolicyFromV2Test(unittest.TestCase):
    def test_fields(self):
        obj = {"_id": "p1", "name": "lan to iot", "action": "allow", "enabled": True, "index": "10001",
               "predefined": False, "source": {"zone_id": "z-lan", "matching_target": "ANY"},
               "destination": {"zone_id": "z-iot", "matching_target": "IP", "ips": ["10.0.20.5"]}}
        p = policy_from_v2(obj, ZONES)
        self.assertIsInstance(p, Policy)
        self.assertEqual((p.id, p.name, p.action, p.enabled, p.index, p.predefined),
                         ("p1", "lan to iot", "ALLOW", True, 10001, False))
        self.assertEqual((p.source_zone, p.destination_zone), ("lan", "iot"))
        self.assertIs(p.source, obj["source"])
        self.assertEqual(p.destination["ips"], ["10.0.20.5"])
        self.assertIs(p.raw, obj)

    def test_unknown_and_missing_zone(self):
        p = policy_from_v2({"_id": "p2", "source": {"zone_id": "z-unbekannt"}}, ZONES)
        self.assertEqual(p.source_zone, "z-unbekannt")  # unbekannte ID bleibt sichtbar
        self.assertIsNone(p.destination_zone)
        self.assertEqual(p.destination, {})
        self.assertFalse(p.enabled)
        self.assertIsNone(p.index)


class LoadV2Test(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv, cls.host = mc.start()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "state"
        export(UnifiClient(cls.host, mc.API_KEY), cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()
        cls.tmp.cleanup()

    def test_load(self):
        snap = load_v2(self.out)
        self.assertIsInstance(snap, V2Snapshot)
        self.assertEqual(snap.zones, {
            mc.V2Z_LAN: "lan", mc.V2Z_IOT: "iot", mc.V2Z_GUEST: "guest",
            mc.V2Z_ISO: "isolated", mc.V2Z_EXT: "External",
        })
        by_id = {p.id: p for p in snap.policies}
        self.assertEqual(set(by_id), {mc.V2P_BLOCK, mc.V2P_ALLOW_A, mc.V2P_ALLOW_B, mc.V2P_SYS})
        block = by_id[mc.V2P_BLOCK]
        self.assertEqual((block.source_zone, block.destination_zone, block.action), ("isolated", "External", "BLOCK"))
        self.assertEqual(block.source["zone_id"], mc.V2Z_ISO)  # rohes Dict mit ID
        self.assertNotIn("hits", block.raw)
        self.assertTrue(by_id[mc.V2P_SYS].predefined)
        self.assertFalse(by_id[mc.V2P_ALLOW_B].enabled)
        # sortiert nach index, dann ID
        self.assertEqual([p.index for p in snap.policies], sorted(p.index for p in snap.policies))
        self.assertEqual([d["key"] for d in snap.dns], ["app.home.arpa", "device-1.home.arpa"])

    def test_missing_site_raises(self):
        with self.assertRaises(FileNotFoundError):
            load_v2(self.out, site="gibt-es-nicht")

    def test_dns_optional(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d) / "default" / "legacy" / "v2"
            (base / "firewall-zones").mkdir(parents=True)
            (base / "firewall-policies").mkdir()
            (base / "firewall-zones" / "lan.yaml").write_text(yaml.safe_dump({"_id": "z-lan", "name": "lan"}))
            (base / "firewall-policies" / "p.yaml").write_text(yaml.safe_dump(
                {"_id": "p1", "name": "x", "action": "BLOCK", "source": {"zone_id": "z-lan"},
                 "destination": {"zone_id": "z-weg"}}))
            snap = load_v2(d)
            self.assertEqual(snap.dns, [])
            self.assertEqual(snap.policies[0].source_zone, "lan")
            self.assertEqual(snap.policies[0].destination_zone, "z-weg")


if __name__ == "__main__":
    unittest.main()
