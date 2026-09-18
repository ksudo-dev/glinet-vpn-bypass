import json
import unittest
from pathlib import Path

from generate import BROAD_PROVIDER_ROOTS, validate_subscription


ROOT = Path(__file__).resolve().parents[1]


class SubscriptionTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "sources.json").read_text())
        self.entries = {
            line.strip()
            for line in (ROOT / "flint3-vpn-bypass.txt").read_text().splitlines()
            if line.strip()
        }

    def test_output_is_valid_and_has_no_bare_provider_root(self):
        validate_subscription(self.entries, set(self.config["blocked_entries"]))
        self.assertFalse(self.entries & BROAD_PROVIDER_ROOTS)

    def test_only_manual_cidrs_are_present(self):
        cidrs = {entry for entry in self.entries if "/" in entry}
        self.assertEqual(
            cidrs,
            {
                "10.0.0.0/8",
                "100.64.0.0/10",
                "169.254.0.0/16",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "224.0.0.0/4",
            },
        )

    def test_generic_apple_feed_and_known_typos_are_absent(self):
        paths = {source["path"] for source in self.config["sources"]}
        self.assertNotIn("rule/Clash/Apple/Apple.list", paths)
        self.assertFalse({"a0pple.net", "100beatscheap.com", "airport.com"} & self.entries)
