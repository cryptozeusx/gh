#!/usr/bin/env python3
"""
[U]nlock Gate — Token Verification Tool
Run this BEFORE any scan to confirm GitHub auth is working.
Gate: exits 0 on success, 1 on failure.
"""

import os
import sys
from datetime import datetime, timezone

from curl_cffi.requests import Session

TOKEN = os.getenv('GITHUB_TOKEN')

if not TOKEN:
    print("❌ GITHUB_TOKEN not set. Copy .env.example to .env and fill in your PAT.")
    sys.exit(1)

session = Session(impersonate="chrome110")
session.headers.update({
    'Authorization': f'token {TOKEN}',
    'Accept': 'application/vnd.github.v3+json',
    'User-Agent': 'CMU-Security-Research-Scanner/2.0',
})

print("=" * 60)
print("[U]nlock Gate — GitHub Token Verification")
print("=" * 60)

# --- Check authenticated user ---
resp = session.get('https://api.github.com/user', timeout=10)
if resp.status_code != 200:
    print(f"❌ /user returned {resp.status_code}: {resp.text[:200]}")
    sys.exit(1)

user = resp.json()
print(f"✅ Authenticated as : {user['login']} ({user.get('name', 'no name set')})")
print(f"   Account type     : {user.get('type', 'unknown')}")

# --- Check rate limits ---
resp = session.get('https://api.github.com/rate_limit', timeout=10)
if resp.status_code != 200:
    print(f"❌ /rate_limit returned {resp.status_code}")
    sys.exit(1)

limits = resp.json()['resources']
core   = limits['core']
search = limits['search']

reset_core   = datetime.fromtimestamp(core['reset'],   tz=timezone.utc).strftime('%H:%M:%S UTC')
reset_search = datetime.fromtimestamp(search['reset'], tz=timezone.utc).strftime('%H:%M:%S UTC')

print()
print(f"📊 Rate limits:")
print(f"   Core   : {core['remaining']}/{core['limit']} remaining (resets {reset_core})")
print(f"   Search : {search['remaining']}/{search['limit']} remaining (resets {reset_search})")

if core['remaining'] == 0 or search['remaining'] == 0:
    print("\n⚠️  WARNING: One or more rate limit buckets are exhausted.")
    print("    Wait for reset time before scanning.")
    sys.exit(1)

print()
print("✅ Gate PASSED — ready to scan.")
print("=" * 60)
sys.exit(0)
