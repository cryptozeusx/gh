#!/usr/bin/env python3
"""
Cohere Credit Checker
Reads discovered Cohere API keys from an NDJSON findings file and checks
the validity of each key via the Cohere API. Does not provide credits.
"""

import argparse
import json
import re
import sys
from datetime import datetime

from curl_cffi import requests as curl_requests
from curl_cffi.requests import Session as CurlSession

CREDIT_URL = "https://api.cohere.com/v1/check-api-key"
COHERE_KEY_RE = re.compile(r"[A-Za-z0-9_-]{35,45}")

def extract_keys_from_ndjson(path: str) -> list[dict]:
    """
    Read an NDJSON file of findings and extract unique Cohere keys.
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

            raw = finding.get("line_preview", "")
            for match in COHERE_KEY_RE.finditer(raw):
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
    """
    Call the Cohere validation endpoint for a single key.
    Then call the chat endpoint to extract usage limit headers.
    """
    try:
        # 1. Base Validation
        resp = session.post(
            CREDIT_URL,
            headers={"Authorization": f"Bearer {key}"},
            timeout=15,
        )
        if resp.status_code != 200:
            return {"error": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            
        data = resp.json()
        if not data.get("valid"):
            return data

        # 2. Check Usage Limits
        chat_resp = session.post(
            "https://api.cohere.com/v2/chat",
            headers={
                "Authorization": f"Bearer {key}",
                "Content-Type": "application/json"
            },
            json={
                "model": "command-a-03-2025",
                "messages": [{"role": "user", "content": "hi"}]
            },
            timeout=15,
        )
        
        # Extract headers like x-trial-endpoint-call-limit
        headers = chat_resp.headers
        
        # Determine Plan
        plan = "Production"
        limit = headers.get("x-endpoint-monthly-call-limit", "?")
        remaining = "?"
        
        if "x-trial-endpoint-call-limit" in headers:
            plan = "Trial"
            limit = headers.get("x-trial-endpoint-call-limit", "?")
            remaining = headers.get("x-trial-endpoint-call-remaining", "?")
            
        data["plan"] = plan
        data["limit"] = limit
        data["remaining"] = remaining
        
        if chat_resp.status_code != 200:
            # Maybe the key works but the model is restricted, or it's out of credits
            data["chat_error"] = f"HTTP {chat_resp.status_code}: {chat_resp.text[:100]}"
            
        return data

    except Exception as exc:
        return {"error": str(exc)}


def redact(key: str) -> str:
    if len(key) < 10:
        return "***"
    return key[:6] + "****" + key[-4:]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Cohere key validity found in a scan NDJSON file."
    )
    parser.add_argument(
        "--input", "-i",
        default="results_cohere/cohere.ndjson",
        help="Path to the cohere.ndjson findings file",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional JSON file to save results to",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("COHERE VALIDATION CHECKER")
    print("=" * 70)
    print(f"Input file : {args.input}")
    print(f"Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    try:
        entries = extract_keys_from_ndjson(args.input)
    except FileNotFoundError:
        print(f"❌ Input file not found: {args.input}")
        return 1

    if not entries:
        print("❌ No Cohere keys found in the input file.")
        return 1

    print(f"🔑 Found {len(entries)} unique key(s). Checking validity...\n")

    session = CurlSession(impersonate="chrome110")
    results = []

    for entry in entries:
        key = entry["key"]
        credits_data = check_credits(session, key)
        record = {
            "key_redacted": redact(key),
            "repository": entry["repository"],
            "url": entry["url"],
            **(credits_data if credits_data and "error" not in credits_data else {"error": credits_data.get("error", "no response") if credits_data else "no response"}),
        }
        results.append(record)

        if "error" in record:
            print(f"  ❌ {redact(key)}  ({entry['repository']})  — Error: {record['error']}")
        else:
            is_valid = credits_data.get("valid", False)
            if is_valid:
                plan = credits_data.get("plan", "?")
                limit = credits_data.get("limit", "?")
                remaining = credits_data.get("remaining", "?")
                
                # Calculate usage if we have remaining and limit
                usage_str = "?"
                icon = "🔴"
                if str(limit).isdigit() and str(remaining).isdigit():
                    usage = int(limit) - int(remaining)
                    usage_str = f"{usage} / {limit}"
                    icon = "🟢" if usage < int(limit) else "🟡"
                elif plan == "Production":
                    icon = "🟢" # Assumed good if production and no trial headers
                    usage_str = "Unlimited / N/A"
                    
                print(f"  {icon} {redact(key)}  ({entry['repository']})")
                print(f"      Plan: {plan}  |  Usage: {usage_str}  |  Org ID: {credits_data.get('organization_id')}")
                if "chat_error" in credits_data:
                    print(f"      ⚠️ Chat Test Failed: {credits_data['chat_error']}")
            else:
                 print(f"  🔴 {redact(key)}  ({entry['repository']})")
                 print(f"      Status: Invalid  |  Response: {credits_data}")

    print()
    print("=" * 70)
    live_keys = [r for r in results if r.get("valid")]
    print(f"Summary: {len(live_keys)} live key(s) out of {len(results)} total")
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
