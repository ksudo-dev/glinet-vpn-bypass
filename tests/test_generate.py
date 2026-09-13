import unittest

from generate import build, normalize_domain, normalize_ip, parse_rule_text, validate_subscription


class GeneratorTests(unittest.TestCase):
    def test_blackmatrix_classical_rules(self):
        entries, ignored, saw_rules = parse_rule_text("""
# NAME: Example
DOMAIN,api.example.com
DOMAIN-SUFFIX,example.net
IP-CIDR,203.0.113.7/24,no-resolve
DOMAIN-KEYWORD,example
PROCESS-NAME,com.example.app
""")
        self.assertTrue(saw_rules)
        self.assertEqual(entries, {"api.example.com", "example.net", "203.0.113.0/24"})
        self.assertEqual(ignored["DOMAIN-KEYWORD"], 1)
        self.assertEqual(ignored["PROCESS-NAME"], 1)

    def test_yaml_payload_rules(self):
        entries, _, saw_rules = parse_rule_text("""
payload:
  - DOMAIN-SUFFIX,Example.COM
  - IP-CIDR,198.51.100.9/24,no-resolve
""")
        self.assertTrue(saw_rules)
        self.assertEqual(entries, {"example.com", "198.51.100.0/24"})

    def test_normalization_and_validation(self):
        self.assertEqual(normalize_domain(".Example.COM."), "example.com")
        self.assertEqual(normalize_domain("apple.xn--czr694b"), "apple.xn--czr694b")
        self.assertEqual(normalize_ip("192.0.2.5/24"), "192.0.2.0/24")
        with self.assertRaises(ValueError):
            normalize_domain("bad_domain.example")
        with self.assertRaises(ValueError):
            normalize_ip("2001:db8::/32")

    def test_deduplication_and_blocking(self):
        config = {
            "blocked_entries": ["onetrust.com"],
            "manual_entries": {"manual": ["example.com", "10.0.0.0/8"]},
            "sources": [{"id": "example", "category": "test", "path": "example.list"}],
        }
        entries, summary = build(config, fetch=lambda _: "DOMAIN,example.com\nDOMAIN-SUFFIX,onetrust.com\n")
        self.assertEqual(entries, ["10.0.0.0/8", "example.com"])
        self.assertEqual(summary[-1]["blocked"], 1)

    def test_domain_only_source_policy_skips_ip_ranges(self):
        entries, ignored, saw_rules = parse_rule_text(
            "DOMAIN-SUFFIX,example.com\nIP-CIDR,203.0.113.0/24\n",
            {"DOMAIN", "DOMAIN-SUFFIX"},
        )
        self.assertTrue(saw_rules)
        self.assertEqual(entries, {"example.com"})
        self.assertEqual(ignored["IP-CIDR"], 1)

    def test_broad_provider_root_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_subscription({"cloudfront.net"}, set())


if __name__ == "__main__":
    unittest.main()
