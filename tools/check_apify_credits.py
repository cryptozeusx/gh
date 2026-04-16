#!/usr/bin/env python3
"""
Apify API token checker
Reads Apify-classified findings from NDJSON and verifies each token via GET /v2/users/me.
"""

import argparse
import json
import re
import sys
from datetime import datetime

from curl_cffi.requests import Session as CurlSession

USER_ME_URL = "https://api.apify.com/v2/users/me"
APIFY_TOKEN_RE = re.compile(r"apify_api_[A-Za-z0-9_-]{10,}")


def extract_keys_from_ndjson(path: str) -> list[dict]:
    seen: set[str] = set()
    entries: list[dict] = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue

            if finding.get("service") != "apify":
                continue

            raw = finding.get("line_preview", "")
            for match in APIFY_TOKEN_RE.finditer(raw):
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


def check_user_me(session: CurlSession, token: str) -> dict:
    try:
        resp = session.get(
            USER_ME_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            },
            timeout=20,
        )
        try:
            body = resp.json()
        except json.JSONDecodeError:
            body = {"raw": resp.text[:500]}
        if resp.status_code == 200:
            return {"ok": True, "status": resp.status_code, "body": body}
        return {
            "ok": False,
            "status": resp.status_code,
            "body": body if isinstance(body, dict) else {"raw": str(body)[:200]},
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def redact(token: str) -> str:
    if len(token) <= 14:
        return token[:11] + "****"
    return token[:11] + "****" + token[-4:]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check Apify tokens from a scan NDJSON via GET /v2/users/me."
    )
    parser.add_argument(
        "--input", "-i",
        default="results_apify/apify.ndjson",
        help="Path to apify.ndjson (default: results_apify/apify.ndjson)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional JSON file to save results",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("APIFY USER CHECKER")
    print("=" * 70)
    print(f"Endpoint   : {USER_ME_URL}")
    print(f"Input file : {args.input}")
    print(f"Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    entries = extract_keys_from_ndjson(args.input)
    if not entries:
        print("❌ No apify_api_* tokens found in Apify service rows.")
        return 1

    print(f"🔑 Found {len(entries)} unique token(s). Calling users/me...\n")

    session = CurlSession(impersonate="chrome110")
    results: list[dict] = []

    for entry in entries:
        key = entry["key"]
        info = check_user_me(session, key)
        record = {
            "key_redacted": redact(key),
            "repository": entry["repository"],
            "url": entry["url"],
            "line_number": entry["line_number"],
            **info,
        }
        results.append(record)

        if info.get("ok"):
            body = info.get("body") or {}
            username = body.get("username") if isinstance(body, dict) else None
            extra = f" @{username}" if username else ""
            print(f"  🟢 {redact(key)}  ({entry['repository']}){extra}")
        else:
            err = info.get("error") or info.get("body") or info.get("status")
            print(f"  ❌ {redact(key)}  ({entry['repository']})  — {err}")

    print()
    print("=" * 70)
    live = [r for r in results if r.get("ok")]
    print(f"Summary: {len(live)} valid token(s) (HTTP 200) out of {len(results)} total")
    print("=" * 70)

    if args.output:
        out = {
            "checked_at": datetime.now().isoformat(),
            "endpoint": USER_ME_URL,
            "total_keys": len(results),
            "live_keys": len(live),
            "results": results,
        }
        with open(args.output, "w") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)
        print(f"\n📝 Results saved to: {args.output}")

    return 0 if live else 1


if __name__ == "__main__":
    sys.exit(main())
