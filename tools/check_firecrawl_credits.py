#!/usr/bin/env python3
"""
Firecrawl Credit Checker
Reads discovered Firecrawl API keys from an NDJSON findings file and checks
the remaining credit balance for each key via the Firecrawl API.
"""

import argparse
import json
import re
import sys
from datetime import datetime

from curl_cffi import requests as curl_requests
from curl_cffi.requests import Session as CurlSession

CREDIT_URL = "https://api.firecrawl.dev/v2/team/credit-usage"
FC_KEY_RE = re.compile(r"fc-[a-f0-9]{32}")


def extract_keys_from_ndjson(path: str) -> list[dict]:
    """
    Read an NDJSON file of findings and extract unique Firecrawl keys.
    Returns a list of dicts: {key, repository, url, line_number}
    """
    seen = set()
    entries = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue

            # line_preview has the raw unredacted line; matched_pattern is redacted — always prefer line_preview
            raw = finding.get("line_preview", "")
            for match in FC_KEY_RE.finditer(raw):
                key = match.group(0)
                if key not in seen:
                    seen.add(key)
                    entries.append({
                        "key": key,
                        "repository": finding.get("repository", "unknown"),
                        "url": finding.get("url", ""),
                        "line_number": finding.get("line_number", 0),
                    })
    return entries


def check_credits(session: CurlSession, key: str) -> dict | None:
    """Call the Firecrawl credit-usage endpoint for a single key."""
    try:
        resp = session.get(
            CREDIT_URL,
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
        )
        if resp.status_code == 200:
            body = resp.json()
            if body.get("success"):
                return body.get("data", {})
        return {"error": f"HTTP {resp.status_code}", "body": resp.text[:200]}
    except Exception as exc:
        return {"error": str(exc)}


def redact(key: str) -> str:
    return key[:6] + "****" + key[-4:]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Firecrawl credit balances for keys found in a scan NDJSON file."
    )
    parser.add_argument(
        "--input", "-i",
        default="results_firecrawl/firecrawl.ndjson",
        help="Path to the firecrawl.ndjson findings file (default: results_firecrawl/firecrawl.ndjson)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional JSON file to save results to",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("FIRECRAWL CREDIT CHECKER")
    print("=" * 70)
    print(f"Input file : {args.input}")
    print(f"Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    entries = extract_keys_from_ndjson(args.input)
    if not entries:
        print("❌ No Firecrawl keys found in the input file.")
        return 1

    print(f"🔑 Found {len(entries)} unique key(s). Checking credits...\n")

    session = CurlSession(impersonate="chrome110")
    results = []

    for entry in entries:
        key = entry["key"]
        credits_data = check_credits(session, key)
        record = {
            "key_redacted": redact(key),
            "repository": entry["repository"],
            "url": entry["url"],
            **( credits_data if credits_data else {"error": "no response"}),
        }
        results.append(record)

        if "error" in record:
            print(f"  ❌ {redact(key)}  ({entry['repository']})  — Error: {record['error']}")
        else:
            remaining = credits_data.get("remainingCredits", "?")
            plan = credits_data.get("planCredits", "?")
            period_end = credits_data.get("billingPeriodEnd", "?")
            icon = "🟢" if isinstance(remaining, int) and remaining > 500 else "🟡" if isinstance(remaining, int) and remaining > 0 else "🔴"
            print(f"  {icon} {redact(key)}  ({entry['repository']})")
            print(f"      Credits: {remaining} / {plan}  |  Period ends: {period_end}")

    print()
    print("=" * 70)
    live_keys = [r for r in results if "remainingCredits" in r]
    print(f"Summary: {len(live_keys)} live key(s) with credits out of {len(results)} total")
    print("=" * 70)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump({
                "checked_at": datetime.now().isoformat(),
                "total_keys": len(results),
                "live_keys": len(live_keys),
                "results": results,
            }, fh, indent=2)
        print(f"\n📝 Results saved to: {args.output}")

    return 0 if live_keys else 1


if __name__ == "__main__":
    sys.exit(main())
