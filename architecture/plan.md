# Architecture Plan — Recursive Multi-Worker GitHub .env Scanner

## Milestones & Acceptance Criteria

---

### Milestone 1: [U]nlock — Connectivity Verified
**Goal:** Prove GitHub API auth works before writing any scanning logic.

**Acceptance Criteria:**
- [ ] `tools/verify_token.py` returns 200 OK with authenticated user info
- [ ] Rate limit endpoint returns `> 0` remaining calls
- [ ] Token stored safely in `.env` (not hardcoded)

**Status:** ⬜ Not started

---

### Milestone 2: [I]mplement — Single-Worker Core (v1.1)
> ⚠️ Superseded by Milestone 2b. Kept for historical record.

**Status:** ✅ Complete and superseded

---

### Milestone 2b: [I]mplement — Recursive Multi-Worker Architecture (v2.0)
**Goal:** Replace flat scanner with BFS/DFS multi-worker system per Kimi design doc.

**Acceptance Criteria:**
- [x] `PatternDatabase` — thread-safe, versioned, 19+ patterns, `add_pattern()` API
- [x] `ResilientVisitedTracker` — L1/L2/L3-4 visited state, `should_process_repo()` with timestamp comparison
- [x] `ResultAggregator` — global fingerprint dedup, `save()` writes v2.0 JSON schema
- [x] `ServiceWorker` — DFS per service, local visited cache, per-worker queue, rate-limit aware
- [x] `MainExplorer` — BFS broad pass, classifies service types, spawns workers up to `--max-workers` cap
- [x] `--resume` flag warms visited sets from a prior scan JSON
- [x] `--max-workers` flag caps simultaneous service workers
- [x] Key fingerprint format: `{service}:{repo}:{path}:{sha256[:16]}`
- [x] Rate-limit sleep uses `X-RateLimit-Reset` header timestamp

**Status:** ✅ Complete (v2.0)

---

### Milestone 3: [L]ock — Green Gate
**Goal:** Smoke tests pass; no regressions on core logic.

**Acceptance Criteria:**
- [ ] `python -c "import main"` exits 0
- [ ] `python main.py --help` renders all flags
- [ ] `PatternDatabase` inline test: `add_pattern()` → `get_patterns()` roundtrip
- [ ] `ResilientVisitedTracker` inline test: repo timestamp logic (new → rescan, same → skip, newer → rescan)
- [ ] `redact_key()` inline test: no full key leaks
- [ ] `tools/verify_token.py` passes with a valid `GITHUB_TOKEN`

**Status:** ⬜ Not started

---

### Milestone 4: [D]eploy — Runbook Ready
**Goal:** Any engineer can run this tool from a fresh clone.

**Acceptance Criteria:**
- [ ] `README.md` covers install, `.env` setup, all CLI flags, and `--resume` usage
- [ ] `.env.example` and `.gitignore` committed
- [ ] Output JSON passes schema validation against `gemini.md` contract
- [ ] Tag v2.0 release

**Status:** ⬜ Not started
