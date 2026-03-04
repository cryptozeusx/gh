# Learning Log — gh-api Scanner

> Entries are added by the **Healing Patch Protocol** whenever a failure occurs.
> Format per entry: **Symptom → Root Cause → Rule Learned**

---

## Entry 001 — Rate Limit Naive Sleep
**Date:** 2026-03-04  
**Symptom:** Scanner would sleep 60 seconds even when the rate-limit reset was only 5 seconds away (or would wake up too early if reset was 90 seconds away).  
**Root Cause:** Tooling Config — `_check_rate_limit()` used `time.sleep(60)` unconditionally instead of computing `reset - time.time()`.  
**Patch Applied:** Replaced with `_wait_for_rate_limit()` that reads `X-RateLimit-Reset` from response headers and sleeps `max(0, reset - time.time()) + 2`.  
**Rule Learned:** *When sleeping on GitHub rate limits, always use the actual `X-RateLimit-Reset` UNIX timestamp from the response header, never a fixed sleep. Add +2s buffer to absorb clock skew.*  
**Regression Guard:** `test_patterns.py` → assert `_wait_for_rate_limit()` does not sleep when `remaining > 5`.

---

## Entry 002 — Stale `import time` placement
**Date:** 2026-03-04  
**Symptom:** `import time` was inside `_check_rate_limit()` — hidden from readers, not discoverable by linters, and executed on every rate-limit check.  
**Root Cause:** Ambiguity — original author likely added it as a quick fix without knowing it would be buried.  
**Patch Applied:** Moved `import time` to top-level imports block.  
**Rule Learned:** *All imports must live at the top of the file. Never use inline imports as a workaround.*

---

## Entry 003 — `total_files_scanned` counted API URLs, not file paths
**Date:** 2026-03-04  
**Symptom:** Metadata field `total_files_scanned` used `len(set(f['url'] for f in findings))` — this counted internal GitHub API URLs, which are unique per file AND per encoding, not per logical file.  
**Root Cause:** Schema Mismatch — the field intent (number of unique files) did not match the implementation (count of API endpoint strings).  
**Patch Applied:** Changed to `len(set((f['repository'], f['file']) for f in findings))`.  
**Rule Learned:** *When counting "unique files," always key on `(repository, file_path)` tuples, not API URL strings.*

---

## Entry 004 — Single-Worker Architecture: No Service Clustering
**Date:** 2026-03-04  
**Symptom:** The v1.1 flat scanner treated all services equally — a Stripe key discovery and an OpenAI key discovery were fed into the same undifferentiated thread pool. There was no mechanism to do targeted deep-searches per service, and newly discovered pattern variants had nowhere to propagate.  
**Root Cause:** Architecture — `GitHubEnvScanner._scan_files()` used a homogeneous thread pool with no concept of service identity or per-service query strategies.  
**Patch Applied:** Replaced with Kimi's recursive multi-worker design (v2.0): `MainExplorer` does BFS to identify service types, then spawns a `ServiceWorker` per service for DFS deep-search. Workers share a `PatternDatabase` so new pattern variants found by one worker are available to all others.  
**Rule Learned:** *When scanning GitHub for credentials, cluster by service domain first (BFS), then go deep within each cluster (DFS). A flat undifferentiated search misses rare key variants that only appear in narrowly-scoped service-specific repos.*  
**Regression Guard:** `gemini.md` data shapes for `visited_services` and `scanned_repos` are now locked as the source of truth. Any future refactor must preserve those shapes.

---
