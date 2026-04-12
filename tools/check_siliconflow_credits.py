#!/usr/bin/env python3
"""
SiliconFlow API key checker
Reads SiliconFlow-classified findings from an NDJSON file and calls the
user info endpoint for each unique key (same auth style as OpenAI-compatible APIs).
"""

import argparse
import json
import re
import sys
from datetime import datetime

from curl_cffi.requests import Session as CurlSession

USER_INFO_URL = "https://api.siliconflow.cn/v1/user/info"
# Keys in findings are SiliconFlow-scoped; value shape matches SiliconFlow / sk-* API keys.
SF_SK_RE = re.compile(r"sk-[a-zA-Z0-9]{20,}")


def extract_keys_from_ndjson(path: str) -> list[dict]:
    """
    Read NDJSON findings and extract unique API keys from SiliconFlow service rows only.
    """
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

            if finding.get("service") != "siliconflow":
                continue

            raw = finding.get("line_preview", "")
            for match in SF_SK_RE.finditer(raw):
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


def check_user_info(session: CurlSession, key: str) -> dict:
    """GET /v1/user/info with Bearer token."""
    try:
        resp = session.get(
            USER_INFO_URL,
            headers={
                "Authorization": f"Bearer {key}",
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


def redact(key: str) -> str:
    if len(key) <= 10:
        return key[:3] + "****"
    return key[:6] + "****" + key[-4:]


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check SiliconFlow keys from a scan NDJSON via GET /v1/user/info."
    )
    parser.add_argument(
        "--input", "-i",
        default="results_siliconflow/siliconflow.ndjson",
        help="Path to siliconflow.ndjson (default: results_siliconflow/siliconflow.ndjson)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional JSON file to save results",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("SILICONFLOW USER INFO CHECKER")
    print("=" * 70)
    print(f"Endpoint   : {USER_INFO_URL}")
    print(f"Input file : {args.input}")
    print(f"Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    entries = extract_keys_from_ndjson(args.input)
    if not entries:
        print("❌ No SiliconFlow sk-* keys found in the input file.")
        return 1

    print(f"🔑 Found {len(entries)} unique key(s). Calling user/info...\n")

    session = CurlSession(impersonate="chrome110")
    results: list[dict] = []

    for entry in entries:
        key = entry["key"]
        info = check_user_info(session, key)
        record = {
            "key_redacted": redact(key),
            "repository": entry["repository"],
            "url": entry["url"],
            "line_number": entry["line_number"],
            **info,
        }
        results.append(record)

        if info.get("ok"):
            print(f"  🟢 {redact(key)}  ({entry['repository']})  — HTTP {info.get('status')}")
            body = info.get("body")
            if isinstance(body, dict):
                # Common shapes: wrap in data, or flat user fields
                preview = {k: body[k] for k in list(body)[:8]}
                print(f"      {json.dumps(preview, ensure_ascii=False)[:200]}")
        else:
            err = info.get("error") or info.get("body") or info.get("status")
            print(f"  ❌ {redact(key)}  ({entry['repository']})  — {err}")

    print()
    print("=" * 70)
    live = [r for r in results if r.get("ok")]
    print(f"Summary: {len(live)} valid key(s) (HTTP 200) out of {len(results)} total")
    print("=" * 70)

    if args.output:
        out = {
            "checked_at": datetime.now().isoformat(),
            "endpoint": USER_INFO_URL,
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
