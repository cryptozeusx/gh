#!/usr/bin/env python3
"""
Apify API token checker
Reads Apify-classified findings from NDJSON (or interactive paste), verifies tokens,
fetches plan + monthly usage + limits, and optionally appends live keys and usage rows.
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from typing import Any, Optional

import requests

USER_ME_URL = "https://api.apify.com/v2/users/me"
USAGE_MONTHLY_URL = "https://api.apify.com/v2/users/me/usage/monthly"
LIMITS_URL = "https://api.apify.com/v2/users/me/limits"

DEFAULT_LIVE_KEYS_FILE = "apify_live_keys.txt"
DEFAULT_USAGE_LOG = "apify_live_usage.jsonl"

APIFY_TOKEN_RE = re.compile(r"apify_api_[A-Za-z0-9_-]{10,}")


def apify_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def load_existing_keys(path: str) -> set[str]:
    """Return full API keys already stored (one per line)."""
    if not os.path.exists(path):
        return set()
    with open(path, "r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def save_key(path: str, api_key: str) -> None:
    """Append a verified key to the live-keys file."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"{api_key}\n")


def append_usage_log(path: str, record: dict[str, Any]) -> None:
    """Append one JSON object per line (no raw secrets)."""
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def _unwrap_data(payload: dict[str, Any]) -> dict[str, Any]:
    inner = payload.get("data")
    if isinstance(inner, dict):
        return inner
    return payload


def fetch_usage_snapshot(
    token: str,
    user_json: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Plan + monthly spend + limit (USD). Shape matches Apify API v2 docs;
    uses .get() so minor schema drift does not crash the checker.
    If user_json is set, skips a duplicate GET /users/me.
    """
    out: dict[str, Any] = {"usage_error": None}

    try:
        if user_json is not None:
            user_body = user_json
        else:
            user_res = requests.get(
                USER_ME_URL, headers=apify_headers(token), timeout=20
            )
            if user_res.status_code != 200:
                out["usage_error"] = f"users/me HTTP {user_res.status_code}"
                return out
            user_body = user_res.json()
        user_data = _unwrap_data(user_body if isinstance(user_body, dict) else {})
        plan = user_data.get("plan") if isinstance(user_data.get("plan"), dict) else {}
        out["plan_id"] = plan.get("id", "N/A")
        out["username"] = user_data.get("username")

        usage_res = requests.get(
            USAGE_MONTHLY_URL, headers=apify_headers(token), timeout=20
        )
        limits_res = requests.get(
            LIMITS_URL, headers=apify_headers(token), timeout=20
        )

        spent: Optional[float] = None
        limit: Optional[float] = None

        if usage_res.status_code == 200:
            uj = usage_res.json()
            ud = _unwrap_data(uj if isinstance(uj, dict) else {})
            spent = ud.get("totalUsageCreditsUsdAfterVolumeDiscount")
            if spent is not None:
                spent = float(spent)

        if limits_res.status_code == 200:
            lj = limits_res.json()
            ld = _unwrap_data(lj if isinstance(lj, dict) else {})
            lim_block = ld.get("limits")
            if isinstance(lim_block, dict):
                raw_lim = lim_block.get("maxMonthlyUsageUsd")
                if raw_lim is not None:
                    limit = float(raw_lim)

        out["spent_usd"] = spent
        out["limit_usd"] = limit
        if spent is not None and limit is not None:
            out["remaining_usd"] = limit - spent
        else:
            out["remaining_usd"] = None

        out["usage_http"] = {
            "monthly": usage_res.status_code,
            "limits": limits_res.status_code,
        }
    except Exception as exc:
        out["usage_error"] = str(exc)

    return out


def check_user_me(token: str) -> dict[str, Any]:
    try:
        resp = requests.get(
            USER_ME_URL,
            headers=apify_headers(token),
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


def extract_keys_from_ndjson(path: str) -> list[dict[str, Any]]:
    seen: set[str] = set()
    entries: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
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


def redact(token: str) -> str:
    if len(token) <= 14:
        return token[:11] + "****"
    return token[:11] + "****" + token[-4:]


def interactive_main(
    live_keys_path: str,
    usage_log_path: str,
    *,
    save_files: bool,
) -> int:
    existing_keys = load_existing_keys(live_keys_path)

    print("=" * 50)
    print("   APIFY KEY CHECKER & SAVER (Ctrl+C to exit)")
    print(f"   Logged keys: {len(existing_keys)}  →  {live_keys_path}")
    if save_files:
        print(f"   Usage log: {usage_log_path}")
    print("=" * 50)

    while True:
        try:
            api_key = input("\nPaste API Key: ").strip()
            if not api_key:
                continue

            if api_key in existing_keys:
                print(f"⏩ SKIP: Key already exists in {live_keys_path}")
                continue

            info = check_user_me(api_key)
            if not info.get("ok"):
                st = info.get("status", "?")
                print(f"❌ INVALID: Key is not live (Status {st})")
                continue

            body = info.get("body") if isinstance(info.get("body"), dict) else None
            usage = fetch_usage_snapshot(api_key, user_json=body)
            plan_id = usage.get("plan_id", "N/A")
            rem = usage.get("remaining_usd")
            rem_s = f"${rem:.4f}" if isinstance(rem, (int, float)) else "N/A"
            print(f"✅ LIVE | Plan: {plan_id} | Balance: {rem_s}")

            if save_files:
                save_key(live_keys_path, api_key)
                existing_keys.add(api_key)
                append_usage_log(
                    usage_log_path,
                    {
                        "saved_at": datetime.now().isoformat(),
                        "mode": "interactive",
                        "key_redacted": redact(api_key),
                        "plan_id": plan_id,
                        "spent_usd": usage.get("spent_usd"),
                        "limit_usd": usage.get("limit_usd"),
                        "remaining_usd": usage.get("remaining_usd"),
                        "username": usage.get("username"),
                        "usage_error": usage.get("usage_error"),
                    },
                )
                print(f"📝 SAVED: key → {live_keys_path}; usage → {usage_log_path}")
            else:
                print("📝 (--no-save: not written to disk)")

        except KeyboardInterrupt:
            print("\n\nExiting... Goodbye!")
            return 0
        except Exception as e:
            print(f"⚠️ Error: {e}")


def ndjson_main(args: argparse.Namespace) -> int:
    save_files = not args.no_save

    print("=" * 70)
    print("APIFY USER CHECKER")
    print("=" * 70)
    print(f"Endpoint   : {USER_ME_URL}")
    print(f"Input file : {args.input}")
    print(f"Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    if save_files:
        print(f"Live keys  : {args.live_keys_file}")
        print(f"Usage log  : {args.usage_log}")
    print()

    entries = extract_keys_from_ndjson(args.input)
    if not entries:
        print("❌ No apify_api_* tokens found in Apify service rows.")
        return 1

    existing_keys = load_existing_keys(args.live_keys_file) if save_files else set()

    print(f"🔑 Found {len(entries)} unique token(s). Calling users/me...\n")

    results: list[dict[str, Any]] = []

    for entry in entries:
        key = entry["key"]
        info = check_user_me(key)
        record: dict[str, Any] = {
            "key_redacted": redact(key),
            "repository": entry["repository"],
            "url": entry["url"],
            "line_number": entry["line_number"],
            **info,
        }

        if info.get("ok"):
            body_ok = info.get("body") if isinstance(info.get("body"), dict) else None
            usage = fetch_usage_snapshot(key, user_json=body_ok)
            record["plan_id"] = usage.get("plan_id")
            record["username"] = usage.get("username")
            record["spent_usd"] = usage.get("spent_usd")
            record["limit_usd"] = usage.get("limit_usd")
            record["remaining_usd"] = usage.get("remaining_usd")
            record["usage_error"] = usage.get("usage_error")

            body = info.get("body") or {}
            if isinstance(body, dict):
                inner = _unwrap_data(body)
                if record.get("username") is None:
                    record["username"] = inner.get("username")

            username = record.get("username")
            extra = f" @{username}" if username else ""
            rem = record.get("remaining_usd")
            bal = f" | Balance: ${rem:.4f}" if isinstance(rem, (int, float)) else ""
            print(f"  🟢 {redact(key)}  ({entry['repository']}){extra}{bal}")

            if save_files:
                if key not in existing_keys:
                    save_key(args.live_keys_file, key)
                    existing_keys.add(key)
                    print(f"      📝 New live key appended to {args.live_keys_file}")
                append_usage_log(
                    args.usage_log,
                    {
                        "saved_at": datetime.now().isoformat(),
                        "mode": "ndjson",
                        "key_redacted": redact(key),
                        "repository": entry["repository"],
                        "url": entry["url"],
                        "line_number": entry["line_number"],
                        "plan_id": record.get("plan_id"),
                        "spent_usd": record.get("spent_usd"),
                        "limit_usd": record.get("limit_usd"),
                        "remaining_usd": record.get("remaining_usd"),
                        "username": record.get("username"),
                        "usage_error": record.get("usage_error"),
                    },
                )
                print(f"      📝 Usage row appended to {args.usage_log}")
        else:
            err = info.get("error") or info.get("body") or info.get("status")
            print(f"  ❌ {redact(key)}  ({entry['repository']})  — {err}")

        results.append(record)

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
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(out, fh, indent=2, ensure_ascii=False)
        print(f"\n📝 Results saved to: {args.output}")

    return 0 if live else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Check Apify tokens (users/me + usage/monthly + limits); "
        "optionally append live keys and JSONL usage."
    )
    p.add_argument(
        "--interactive",
        action="store_true",
        help="Interactive paste loop (Ctrl+C to exit). Ignores --input.",
    )
    p.add_argument(
        "--input", "-i",
        default="results_apify/apify.ndjson",
        help="Path to apify.ndjson (NDJSON mode only).",
    )
    p.add_argument(
        "--output", "-o",
        default=None,
        help="Optional JSON report path (NDJSON mode only).",
    )
    p.add_argument(
        "--live-keys-file",
        default=DEFAULT_LIVE_KEYS_FILE,
        help=f"Append verified full keys here (default: {DEFAULT_LIVE_KEYS_FILE}).",
    )
    p.add_argument(
        "--usage-log",
        default=DEFAULT_USAGE_LOG,
        help=f"Append one JSON usage object per line (default: {DEFAULT_USAGE_LOG}).",
    )
    p.add_argument(
        "--no-save",
        action="store_true",
        help="Do not write live-keys file or usage JSONL.",
    )
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    save_files = not args.no_save

    if args.interactive:
        return interactive_main(
            args.live_keys_file,
            args.usage_log,
            save_files=save_files,
        )

    return ndjson_main(args)


if __name__ == "__main__":
    sys.exit(main())
