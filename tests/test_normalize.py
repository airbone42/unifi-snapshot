"""Tests für redact_text (Freitext-Redaction) und die v2-Hilfen in normalize."""

import base64
import unittest

from unifi_snapshot.normalize import REDACTED, V2_VOLATILE_KEYS, VOLATILE_KEYS, redact_text, strip_volatile

# Marker zusammengesetzt, damit kein vollständiger Private Key wörtlich im Quelltext steht
BEGIN, END, PK = "-----BEGIN ", "-----END ", "PRIVATE KEY-----"
BODY = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\nAbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/AbCd\n"


def pem(kind: str, body: str = BODY) -> str:
    return f"{BEGIN}{kind}\n{body}{END}{kind}"


class RedactTextTest(unittest.TestCase):
    def test_pem_block_masked_context_kept(self):
        text = f"vorher\n{pem(PK)}\nnachher"
        out = redact_text(text)
        self.assertEqual(out, f"vorher\n{REDACTED}\nnachher")

    def test_pem_variants(self):
        for kind in ("RSA " + PK, "EC " + PK, "OPENSSH " + PK, "ENCRYPTED " + PK):
            out = redact_text(f"a {pem(kind)} b")
            self.assertEqual(out, f"a {REDACTED} b", kind)

    def test_multiple_blocks(self):
        out = redact_text(f"{pem(PK)} mitte {pem('RSA ' + PK)}")
        self.assertEqual(out, f"{REDACTED} mitte {REDACTED}")

    def test_unterminated_block_masked_to_end(self):
        out = redact_text(f"log: {BEGIN}{PK}\nMIIEvQIBADAN")
        self.assertEqual(out, f"log: {REDACTED}")
        self.assertNotIn("MIIEvQIBADAN", out)

    def test_orphan_end_masks_preceding_lines(self):
        # Text vorne abgeschnitten, BEGIN fehlt. Die Kopfzeile ist kein base64 und bleibt.
        text = f"Log-Auszug:\nMIIEvQIBADANBgkq\nAbCdEfGh0123+/==\n{END}{PK}\nFuss"
        out = redact_text(text)
        self.assertNotIn("MIIEvQIBADAN", out)
        self.assertNotIn("AbCdEfGh", out)
        self.assertEqual(out, f"Log-Auszug:\n{REDACTED}\nFuss")

    def test_json_escaped_pem(self):
        escaped = f'{{"key": "{BEGIN}{PK}\\nMIIEvQIBADAN\\n{END}{PK}\\n"}}'
        out = redact_text(escaped)
        self.assertNotIn("MIIEvQIBADAN", out)
        self.assertIn('{"key": ', out)

    def test_base64_pem_masked(self):
        b64 = base64.b64encode(pem(PK).encode()).decode()
        self.assertTrue(b64.startswith("LS0tLS1CRUdJTi"))
        out = redact_text(f"blob={b64} ende")
        self.assertEqual(out, f"blob={REDACTED} ende")

    def test_base64_pem_truncated_masked(self):
        # Gleicher Fall wie im Export-Test: base64-PEM-Header, kein vollständiger Key
        out = redact_text("x LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQURB y")
        self.assertEqual(out, f"x {REDACTED} y")
        out = redact_text("x LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2Z0lCQUR y")  # Länge kein Vielfaches von 4
        self.assertEqual(out, f"x {REDACTED} y")

    def test_certificates_and_public_keys_kept(self):
        cert = f"{BEGIN}CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIE\n{END}CERTIFICATE-----"
        pub = f"{BEGIN}PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B\n{END}PUBLIC KEY-----"
        b64_cert = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"
        text = f"{cert}\n{pub}\n{b64_cert}\nwg public key: PUB"
        self.assertEqual(redact_text(text), text)

    def test_plain_text_unchanged(self):
        for text in ("", "nichts Geheimes hier", "private key rotated", "zone lan -> iot ALLOW"):
            self.assertEqual(redact_text(text), text)


class StripVolatileTest(unittest.TestCase):
    def test_default_keys_unchanged(self):
        obj = {"updatedAt": 1, "hits": 2, "name": "a", "nested": [{"last_seen": 3, "x": 4}]}
        self.assertEqual(strip_volatile(obj), {"hits": 2, "name": "a", "nested": [{"x": 4}]})

    def test_v2_keys(self):
        obj = {"hits": 2, "last_hit": 3, "updatedAt": 1, "name": "a"}
        self.assertEqual(strip_volatile(obj, VOLATILE_KEYS | V2_VOLATILE_KEYS), {"name": "a"})


if __name__ == "__main__":
    unittest.main()
