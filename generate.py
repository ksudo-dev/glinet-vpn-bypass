#!/usr/bin/env python3
"""Build a GL.iNet domain/IP subscription from small, service-specific lists."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

UPSTREAM_RAW = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/"
SUPPORTED_RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR"}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
# These roots have no service boundary. A final subscription may contain an
# exact service host under one of them, but never the root itself.
BROAD_PROVIDER_ROOTS = {
    "akamai.net", "akamaihd.net", "akamaiedge.net", "akamaized.net",
    "amazonaws.com", "aws.amazon.com", "cloudflare.com", "cloudflare.net",
    "cloudfront.net", "edgesuite.net", "fastly.net", "google.com",
    "googleapis.com", "googleusercontent.com", "gstatic.com",
}


def normalize_domain(value: str) -> str:
    value = value.strip().lower().lstrip(".").rstrip(".")
    if not DOMAIN_RE.fullmatch(value):
        raise ValueError(f"invalid domain: {value!r}")
    return value


def normalize_ip(value: str) -> str:
    value = value.strip()
    if "/" not in value:
        address = ipaddress.ip_address(value)
        if address.version != 4:
            raise ValueError(f"IPv6 is not supported: {value!r}")
        return str(address)
    network = ipaddress.ip_network(value, strict=False)
    if network.version != 4:
        raise ValueError(f"IPv6 is not supported: {value!r}")
    return str(network)


def normalize_value(value: str) -> str:
    try:
        return normalize_ip(value)
    except ValueError:
        return normalize_domain(value)


def parse_rule_text(
    text: str, allowed_rule_types: set[str] | None = None
) -> tuple[set[str], Counter[str], bool]:
    """Parse Clash classical .list files and simple YAML payload files."""
    allowed_rule_types = allowed_rule_types or SUPPORTED_RULE_TYPES
    entries: set[str] = set()
    ignored: Counter[str] = Counter()
    saw_classical_rule = False

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line == "payload:":
            continue
        if line.startswith("- "):
            line = line[2:].strip().strip("'\"")

        fields = [field.strip() for field in line.split(",")]
        rule_type = fields[0].upper()
        if rule_type in SUPPORTED_RULE_TYPES:
            saw_classical_rule = True
            if len(fields) < 2 or not fields[1]:
                raise ValueError(f"missing value for {rule_type}: {raw_line!r}")
            value = fields[1]
            if rule_type in allowed_rule_types:
                if rule_type == "IP-CIDR":
                    entries.add(normalize_ip(value))
                else:
                    entries.add(normalize_domain(value))
            else:
                ignored[rule_type] += 1
        elif re.fullmatch(r"[A-Z][A-Z0-9-]*", rule_type):
            ignored[rule_type] += 1
        else:
            # A plain entry is useful for small hand-authored sources. The
            # Blackmatrix7 sources selected here are classical rules.
            entries.add(normalize_value(line))
    return entries, ignored, saw_classical_rule


def is_broad_provider_root(entry: str) -> bool:
    return entry in BROAD_PROVIDER_ROOTS


def validate_subscription(entries: set[str], blocked_entries: set[str]) -> None:
    for entry in entries:
        normalize_value(entry)
        if entry in blocked_entries:
            raise ValueError(f"blocked shared-service entry reached output: {entry}")
        if is_broad_provider_root(entry):
            raise ValueError(f"broad provider root reached output: {entry}")


def fetch_source(url: str) -> str:
    try:
        with urlopen(url, timeout=30) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP {response.status} for {url}")
            return response.read().decode("utf-8")
    except (URLError, UnicodeDecodeError) as exc:
        raise RuntimeError(f"failed to download {url}: {exc}") from exc


def source_url(source: dict[str, str]) -> str:
    return UPSTREAM_RAW + source["path"]


def build(config: dict, fetch=fetch_source) -> tuple[list[str], list[dict]]:
    blocked_entries = set(config.get("blocked_entries", []))
    all_entries: set[str] = set()
    summary: list[dict] = []

    for group, values in config.get("manual_entries", {}).items():
        normalized = {normalize_value(value) for value in values}
        all_entries.update(normalized)
        summary.append({"id": group, "category": "manual", "entries": len(normalized), "ignored": {}})

    for source in config["sources"]:
        url = source_url(source)
        entries, ignored, saw_rules = parse_rule_text(
            fetch(url), set(source.get("include_rule_types", ["DOMAIN", "DOMAIN-SUFFIX"]))
        )
        if not saw_rules:
            raise RuntimeError(f"{source['id']}: expected Clash classical rules at {url}")
        if not entries and source.get("required", True):
            raise RuntimeError(f"{source['id']}: no usable DOMAIN or IP-CIDR entries at {url}")
        before = len(entries)
        entries.difference_update(blocked_entries)
        all_entries.update(entries)
        summary.append({
            "id": source["id"],
            "category": source["category"],
            "entries": len(entries),
            "blocked": before - len(entries),
            "ignored": dict(sorted(ignored.items())),
        })

    validate_subscription(all_entries, blocked_entries)
    return sorted(all_entries), summary


def write_output(path: Path, entries: list[str]) -> bool:
    contents = "\n".join(entries) + "\n"
    previous = path.read_text() if path.exists() else None
    if previous == contents:
        return False
    path.write_text(contents)
    return True


def entry_kind(entry: str) -> str:
    try:
        if "/" in entry:
            ipaddress.IPv4Network(entry)
            return "cidr"
        ipaddress.IPv4Address(entry)
        return "ipv4"
    except ValueError:
        return "domain"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path("sources.json"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true", help="validate an existing subscription without downloading")
    args = parser.parse_args()

    config = json.loads(args.config.read_text())
    output = args.output or args.config.parent / config["output"]
    if args.check:
        entries = {line.strip() for line in output.read_text().splitlines() if line.strip()}
        validate_subscription(entries, set(config.get("blocked_entries", [])))
        print(f"validated {len(entries)} entries in {output}")
        return 0

    entries, summary = build(config)
    changed = write_output(output, entries)
    counts = Counter(entry_kind(entry) for entry in entries)
    for source in summary:
        details = f" ignored={source['ignored']}" if source["ignored"] else ""
        blocked = f" blocked={source.get('blocked', 0)}" if source.get("blocked") else ""
        print(f"{source['category']:<10} {source['id']:<22} entries={source['entries']}{blocked}{details}")
    print(f"total domains={counts['domain']} ipv4={counts['ipv4']} cidrs={counts['cidr']} output={output} changed={changed}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
