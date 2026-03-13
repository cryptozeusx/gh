#!/usr/bin/env python3
"""
NeonDB Connection Checker
Reads discovered NeonDB connection strings from an NDJSON findings file,
attempts to connect to each database, and lists the tables in the public schema.
"""

import argparse
import concurrent.futures
import json
import re
import sys
from datetime import datetime
from urllib.parse import urlsplit

import psycopg2
import psycopg2.extras

# Matches postgres(ql):// connection strings containing neon.tech
NEON_URL_RE = re.compile(
    r"(?:postgres(?:ql)?)://[^\s\"']+@[^\s\"']*\.neon\.tech[^\s\"']*",
    re.IGNORECASE,
)

# Also match named variable assignments so we capture full URL values from scan fields
NAMED_URL_RE = re.compile(
    r"(?:postgres(?:ql)?)://\S+",
    re.IGNORECASE,
)

VALID_SSLMODES = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}


def extract_urls_from_ndjson(path: str) -> list[dict]:
    """
    Read an NDJSON file of findings and extract unique NeonDB connection URLs.
    Returns a list of dicts: {url, repository, file_url, line_number}
    """
    seen: set[str] = set()
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

            raw = finding.get("candidate_url") or finding.get("line_preview", "")
            # Try specific neon.tech pattern first, then fall back to any postgres URL
            matches = NEON_URL_RE.findall(raw) or NAMED_URL_RE.findall(raw)

            for url in matches:
                # Strip trailing quotes or whitespace
                url = url.strip("\"' \t\r\n")
                # Only keep URLs that reference neon.tech (after stripping)
                if "neon.tech" not in url.lower():
                    continue
                if url not in seen:
                    seen.add(url)
                    entries.append({
                        "url": url,
                        "repository": finding.get("repository", "unknown"),
                        "file_url": finding.get("url", ""),
                        "line_number": finding.get("line_number", 0),
                    })
    return entries


def redact_url(url: str) -> str:
    """Replace the password portion of a postgres URL with ****."""
    return re.sub(
        r"((?:postgres(?:ql)?)://[^:]+:)([^@]+)(@)",
        lambda m: m.group(1) + "****" + m.group(3),
        url,
        flags=re.IGNORECASE,
    )


def classify_unusable_url(url: str) -> str | None:
    """Return a skip reason for malformed/truncated URLs, otherwise None."""
    lowered = url.lower()

    # Common placeholder/truncation markers from examples or redacted docs.
    if "..." in url or any(ch in url for ch in "<>[]{}"):
        return "placeholder or redacted URL"

    if not lowered.startswith(("postgres://", "postgresql://")):
        return "not a postgres URL"

    try:
        parsed = urlsplit(url)
    except Exception:
        return "unparseable URL"

    if not parsed.hostname:
        return "missing hostname"

    # A trailing '?' or '&' yields an empty query token once sslmode is appended.
    if ("?" in url and parsed.query == "") or url.endswith("&"):
        return "empty query parameter"

    if parsed.query:
        for token in parsed.query.split("&"):
            if token == "":
                return "empty query parameter"
            if "=" not in token:
                return f"incomplete query parameter '{token}'"

            key, value = token.split("=", 1)
            if not key:
                return "missing query parameter key"
            if key == "sslmode" and value not in VALID_SSLMODES:
                return f"invalid sslmode '{value}'"

    return None


def check_connection(url: str) -> dict:
    """
    Connect to the database and list tables in the public schema.
    Returns a dict with 'tables' on success, or 'error' on failure.
    """
    # Ensure SSL is required (NeonDB requires it)
    connect_url = url
    if "sslmode" not in connect_url:
        connect_url += ("&" if "?" in connect_url else "?") + "sslmode=require"

    try:
        conn = psycopg2.connect(connect_url, connect_timeout=10)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_type = 'BASE TABLE'
            ORDER BY table_name;
            """
        )
        tables = [row[0] for row in cur.fetchall()]

        # Also grab row counts for non-empty databases (best-effort)
        table_info = []
        for table in tables:
            try:
                cur.execute(f'SELECT COUNT(*) FROM "{table}"')  # noqa: S608
                count = cur.fetchone()[0]
                table_info.append({"table": table, "rows": count})
            except Exception:
                table_info.append({"table": table, "rows": "?"})

        cur.close()
        conn.close()
        return {"tables": table_info, "table_count": len(tables)}

    except psycopg2.OperationalError as exc:
        return {"error": f"OperationalError: {exc}"}
    except psycopg2.Error as exc:
        return {"error": f"psycopg2 error: {exc}"}
    except Exception as exc:
        return {"error": str(exc)}


def check_entry(entry: dict) -> dict:
    """Run a single connection check and return normalized output record."""
    url = entry["url"]
    redacted = redact_url(url)
    result = check_connection(url)
    return {
        "url_redacted": redacted,
        "repository": entry["repository"],
        "file_url": entry["file_url"],
        **result,
    }


def build_skipped_record(entry: dict, reason: str) -> dict:
    """Return a normalized record for entries we intentionally do not test."""
    return {
        "url_redacted": redact_url(entry["url"]),
        "repository": entry["repository"],
        "file_url": entry["file_url"],
        "skipped": True,
        "skip_reason": reason,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test NeonDB connections and list tables for keys found in a scan NDJSON file."
    )
    parser.add_argument(
        "--input", "-i",
        default="results_neondb/neondb.ndjson",
        help="Path to the neondb.ndjson findings file (default: results_neondb/neondb.ndjson)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional JSON file to save results to",
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=20,
        help="Number of concurrent DB checks (default: 20)",
    )
    args = parser.parse_args()

    workers = max(1, args.workers)

    print("=" * 70)
    print("NEONDB CONNECTION CHECKER")
    print("=" * 70)
    print(f"Input file : {args.input}")
    print(f"Timestamp  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print()

    entries = extract_urls_from_ndjson(args.input)
    if not entries:
        print("❌ No NeonDB connection strings found in the input file.")
        return 1

    testable_entries = []
    skipped_results = []
    for entry in entries:
        skip_reason = classify_unusable_url(entry["url"])
        if skip_reason:
            skipped_results.append(build_skipped_record(entry, skip_reason))
        else:
            testable_entries.append(entry)

    print(f"🔑 Found {len(entries)} unique connection string(s).")
    print(f"   • testable: {len(testable_entries)}")
    print(f"   • skipped : {len(skipped_results)} (malformed/truncated)\n")

    results = []
    processed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(check_entry, entry): entry for entry in testable_entries}
        for future in concurrent.futures.as_completed(future_map):
            entry = future_map[future]
            processed += 1
            try:
                record = future.result()
            except Exception as exc:
                redacted = redact_url(entry["url"])
                record = {
                    "url_redacted": redacted,
                    "repository": entry["repository"],
                    "file_url": entry["file_url"],
                    "error": f"Unhandled worker exception: {exc}",
                }

            results.append(record)

            print(f"[{processed}/{len(testable_entries)}] 🔗 {record['url_redacted']}")
            print(f"     Repo: {record['repository']}")

            if "error" in record:
                print(f"     ❌ Connection failed: {record['error']}")
            else:
                table_count = record.get("table_count", 0)
                tables = record.get("tables", [])
                icon = "🟢" if table_count > 0 else "🟡"
                print(f"     {icon} Connected! {table_count} table(s) in public schema:")
                if tables:
                    for t in tables:
                        rows = t.get("rows", "?")
                        print(f"         • {t['table']}  ({rows} rows)")
                else:
                    print("         (no tables found in public schema)")
            print()

    print("=" * 70)
    live = [r for r in results if "tables" in r]
    print(f"Summary: {len(live)} accessible database(s) out of {len(results)} tested")
    if skipped_results:
        print(f"         {len(skipped_results)} skipped malformed/truncated URL(s)")
    print("=" * 70)

    if args.output:
        all_results = results + skipped_results
        with open(args.output, "w") as fh:
            json.dump({
                "checked_at": datetime.now().isoformat(),
                "total_connections": len(all_results),
                "tested_connections": len(results),
                "skipped_connections": len(skipped_results),
                "accessible": len(live),
                "results": all_results,
            }, fh, indent=2)
        print(f"\n📝 Results saved to: {args.output}")

    return 0 if live else 1


if __name__ == "__main__":
    sys.exit(main())
