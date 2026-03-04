# Prompt Patches — gh-api Scanner

> Rules distilled from the Healing Log. These are permanent coding constraints.
> Added chronologically; never deleted.

---

## PP-001 — Rate Limit Sleep Rule
**Source:** Learning Log Entry 001  
**Rule:** When sleeping on GitHub rate limits, always compute `wait = max(0, reset - time.time()) + 2` from the `X-RateLimit-Reset` header. Never use `time.sleep(60)`.

---

## PP-002 — Import Placement Rule
**Source:** Learning Log Entry 002  
**Rule:** All imports must be at the top of the file. No inline `import` statements anywhere in the codebase.

---

## PP-003 — Unique File Counting Rule
**Source:** Learning Log Entry 003  
**Rule:** When counting unique files from findings, always use `(repository, file_path)` tuples as the dedup key — never API URL strings.

---

## PP-004 — Schema Guard Rule
**Source:** gemini.md behavioral rules  
**Rule:** If a GitHub API response contains an unexpected shape (new field, missing field, unexpected encoding), STOP and ask the user before proceeding. Never guess.

---

## PP-005 — Redaction Rule
**Source:** gemini.md behavioral rules  
**Rule:** Any string that matches a key pattern must be passed through `_redact_key()` before it appears in ANY output: console, JSON, or text report. No exceptions.

---

## PP-006 — Key Fingerprint Format Rule
**Source:** Kimi design doc + Learning Log Entry 004  
**Rule:** The deduplication fingerprint for any discovered key must be `{service}:{repo}:{path}:{sha256[:16]}`. Never use raw line numbers, URL strings, or partial matches as dedup keys — they are not stable across scans.

---

## PP-007 — Repo Rescan Rule
**Source:** Kimi design doc (`ResilientVisitedTracker.should_process_repo`)  
**Rule:** A repo must only be rescanned if `github_updated_at` from the current API response is strictly newer (string-sortable ISO 8601 comparison) than our stored `last_scanned.github_updated_at`. Never rescan purely on wall-clock time.

---

## PP-008 — Service Worker Routing Rule
**Source:** Kimi design doc + v2.0 `MainExplorer` implementation  
**Rule:** When a new service type is discovered during BFS, check `visited_services` before spawning. If a worker for that service already exists, enqueue to the existing worker. Only spawn a new worker if: (a) the service is new AND (b) the active worker count is below `--max-workers`. Never spawn duplicate service workers.
