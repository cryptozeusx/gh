# Task List — Recursive Multi-Worker GitHub .env Scanner (v2.0)

> Tracks every task chunk, its Green Gate evidence, and current status.
> **Format:** `[ ]` todo · `[/]` in-progress · `[x]` done · `[🩹]` healing in progress

---

## [U]nlock Phase

- [ ] **U-1** Create `tools/verify_token.py` — hits `/user` and `/rate_limit`, prints result
  - Gate evidence: _not recorded yet_

---

## [I]mplement Phase — v1.1 Core (Superseded)

- [x] **I-1 through I-13** — see historical record in git history (v1.1 single-worker)

---

## [I]mplement Phase — v2.0 Recursive Multi-Worker

- [x] **I-14** `redact_key()` utility + `key_fingerprint()` utility (module-level functions)
- [x] **I-15** `PatternDatabase` — 19 builtin patterns, `SERVICE_MAP`, thread-safe `add_pattern()`, versioned
- [x] **I-16** `ResilientVisitedTracker` — L1 visited_services, L2 scanned_repos, L3/4 global_visited_keys
  - [x] `should_process_repo()` — timestamp comparison (new/newer → True, same/older → False)
  - [x] `is_key_new()` / `mark_key_visited()` — O(1) fingerprint lookup
  - [x] `load_from_report()` — warm-start from prior JSON output
- [x] **I-17** `ResultAggregator` — fingerprint dedup via tracker, `save()` emits v2.0 JSON schema, `generate_text_report()`
- [x] **I-18** `ServiceWorker` — DFS queue-based, local visited cache, rate-limit aware `_get()`, `_search_files()`, `_fetch_content()`
- [x] **I-19** `MainExplorer` — BFS broad pass, `_classify_file()` service detection, `_spawn_worker()`, `_route_to_worker()` with max-workers cap
- [x] **I-20** `main()` CLI — `--resume`, `--max-workers`, `--verbose`, `--threads` removed (now per-worker)
- [x] **I-21** Shared HTTP session with retry adapter (5 retries, 1.5x backoff, 5xx status list)

---

## [L]ock Phase

- [ ] **L-1** Import smoke test: `python -c "import main; print('OK')"`
  - Gate evidence: _not recorded yet_
- [ ] **L-2** CLI help test: `python main.py --help`
  - Gate evidence: _not recorded yet_
- [ ] **L-3** `PatternDatabase` inline unit test (no network)
  - Gate evidence: _not recorded yet_
- [ ] **L-4** `ResilientVisitedTracker` timestamp logic inline test (no network)
  - Gate evidence: _not recorded yet_
- [ ] **L-5** `redact_key()` inline test — assert no full key in output
  - Gate evidence: _not recorded yet_
- [ ] **L-6** `tools/verify_token.py` live gate (requires real `GITHUB_TOKEN`)
  - Gate evidence: _not recorded yet_

---

## [D]eploy Phase

- [ ] **D-1** Write `README.md` — install, `.env` setup, all CLI flags, `--resume` walkthrough
- [ ] **D-2** Confirm `.env.example` and `.gitignore` are committed
- [ ] **D-3** Tag v2.0 release

---

## 🟢 Green Gate Log

| Task | Date | Result | Evidence |
|------|------|--------|----------|
| I-1 through I-13 | 2026-03-04 | ✅ Written | `main.py` v1.1 |
| I-14 through I-21 | 2026-03-04 | ✅ Written | `main.py` v2.0 — 5 classes, ~500 lines |
