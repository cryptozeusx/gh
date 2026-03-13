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

import psycopg2
import psycopg2.extras

# Matches postgres(ql):// connection strings containing neon.tech
NEON_URL_RE = re.compile(
    r"(?:postgres(?:ql)?)://[^\s\"']+@[^\s\"']*\.neon\.tech[^\s\"']*",
    re.IGNORECASE,
)

# Also match named variable assignments in line_preview so we capture the full URL
NAMED_URL_RE = re.compile(
    r"(?:postgres(?:ql)?)://\S+",
    re.IGNORECASE,
)


def extract_urls_from_ndjson(path: str) -> tuple[list[dict], dict]:
    """
    Read an NDJSON file of findings and extract unique NeonDB connection URLs.
    Returns (entries, stats) where entries is a list of dicts:
    {url, repository, file_url, line_number}
    """
    seen: set[str] = set()
    entries = []
    stats = {
        "total_lines": 0,
        "json_lines": 0,
        "matched_urls": 0,
        "unique_urls": 0,
    }
    with open(path) as fh:
        for line in fh:
            stats["total_lines"] += 1
            line = line.strip()
            if not line:
                continue
            try:
                finding = json.loads(line)
            except json.JSONDecodeError:
                continue

            stats["json_lines"] += 1

            raw = finding.get("line_preview", "")
            # Try specific neon.tech pattern first, then fall back to any postgres URL
            matches = NEON_URL_RE.findall(raw) or NAMED_URL_RE.findall(raw)

            for url in matches:
                stats["matched_urls"] += 1
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
    stats["unique_urls"] = len(entries)
    return entries, stats


def redact_url(url: str) -> str:
    """Replace the password portion of a postgres URL with ****."""
    return re.sub(
        r"((?:postgres(?:ql)?)://[^:]+:)([^@]+)(@)",
        lambda m: m.group(1) + "****" + m.group(3),
        url,
        flags=re.IGNORECASE,
    )


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

    entries, extraction_stats = extract_urls_from_ndjson(args.input)
    if not entries:
        print("❌ No NeonDB connection strings found in the input file.")
        return 1

    print("Extraction stats:")
    print(f"  NDJSON lines read      : {extraction_stats['total_lines']}")
    print(f"  JSON lines parsed      : {extraction_stats['json_lines']}")
    print(f"  URL matches (raw)      : {extraction_stats['matched_urls']}")
    print(f"  Unique URLs to test    : {extraction_stats['unique_urls']}")
    print()

    print(f"🔑 Found {len(entries)} unique connection string(s). Testing with {workers} workers...\n")

    results = []
    processed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(check_entry, entry): entry for entry in entries}
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

            print(f"[{processed}/{len(entries)}] 🔗 {record['url_redacted']}")
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
    print(f"Summary: {len(live)} accessible database(s) out of {len(results)} total")
    print("=" * 70)

    if args.output:
        with open(args.output, "w") as fh:
            json.dump({
                "checked_at": datetime.now().isoformat(),
                "extraction_stats": extraction_stats,
                "total_connections": len(results),
                "accessible": len(live),
                "results": results,
            }, fh, indent=2)
        print(f"\n📝 Results saved to: {args.output}")

    return 0 if live else 1


if __name__ == "__main__":
    sys.exit(main())
