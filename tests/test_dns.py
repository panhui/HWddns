import unittest
from types import SimpleNamespace
from unittest.mock import patch

import dns


class FakeClient:
    def __init__(self, records):
        self.records = records
        self.created = None
        self.updated = None

    def list_public_zones(self, request):
        return SimpleNamespace(zones=[SimpleNamespace(id="zone-id", name="example.com.")])

    def list_record_sets_by_zone(self, request):
        return SimpleNamespace(recordsets=self.records)

    def create_record_set(self, request):
        self.created = request

    def update_record_set(self, request):
        self.updated = request


class DnsTests(unittest.TestCase):
    def test_create_ipv4(self):
        client = FakeClient([])
        with patch.object(dns, "client_for", return_value=client):
            old, action = dns.set_record("a", "s", "cn-north-4", "home.example.com", "203.0.113.10")
        self.assertEqual((old, action), ("—", "created"))
        self.assertEqual(client.created.body.type, "A")
        self.assertEqual(client.created.body.records, ["203.0.113.10"])

    def test_update_ipv6_preserves_ttl(self):
        record = SimpleNamespace(id="record-id", name="home.example.com.", type="AAAA", ttl=600,
                                 records=["2001:db8::1"])
        client = FakeClient([record])
        with patch.object(dns, "client_for", return_value=client):
            old, action = dns.set_record("a", "s", "cn-north-4", "home.example.com", "2001:db8::2")
        self.assertEqual((old, action), ("2001:db8::1", "updated"))
        self.assertEqual(client.updated.body.ttl, 600)
        self.assertEqual(client.updated.body.records, ["2001:db8::2"])

    def test_ambiguous_record_is_rejected(self):
        record = SimpleNamespace(id="1", name="home.example.com.", type="A", ttl=300,
                                 records=["203.0.113.1"])
        client = FakeClient([record, record])
        with patch.object(dns, "client_for", return_value=client):
            with self.assertRaisesRegex(ValueError, "多条"):
                dns.set_record("a", "s", "cn-north-4", "home.example.com", "203.0.113.2")


if __name__ == "__main__":
    unittest.main()
