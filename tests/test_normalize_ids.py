import unittest

from unifi_snapshot.normalize import build_names, resolve_ids


class EmptyIdTest(unittest.TestCase):
    def test_object_without_id_does_not_claim_empty_string(self):
        names = build_names([{"id": "a1", "name": "one"}, {"name": "derived"}])
        self.assertNotIn("", names)
        self.assertEqual(names, {"a1": "one"})

    def test_empty_strings_stay_empty(self):
        idmap = {"a1": "zone:one", "": "zone:bogus"}
        out = resolve_ids({"description": "", "zoneId": "a1", "list": ["", "a1"]}, idmap)
        self.assertEqual(out, {"description": "", "zoneId": "zone:one", "list": ["", "zone:one"]})


if __name__ == "__main__":
    unittest.main()
