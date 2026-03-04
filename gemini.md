# 🧠 Project Map — Recursive Multi-Worker GitHub .env Scanner
> **Source of Truth.** All agents must read this file before starting any work.

---

## North Star
Scan GitHub public repositories for accidentally committed `.env` files containing live API keys. Use a **recursive multi-worker BFS/DFS architecture** to maximize coverage: a MainExplorer discovers service types breadth-first, then spawns dedicated ServiceWorkers that explore each service domain depth-first. Produce redacted, severity-ranked reports for security research purposes.

## Integrations
| Service | Key/Auth | Status |
|---|---|---|
| GitHub REST API v3 | `GITHUB_TOKEN` (PAT) | ⬜ Unverified |

## Architecture (per Kimi design doc)
```
MainExplorer (BFS) → Discovers service types → Spawns ServiceWorkers
ServiceWorker (DFS) → Deep searches one service → Updates PatternDatabase
PatternDatabase → Shared regex KB, versioned, thread-safe
ResilientVisitedTracker → Dedup at every level (L1 services, L2 repos, L3/4 keys)
ResultAggregator → Global dedup, JSON report, text report
```

## Source of Truth
- Raw input: GitHub Code Search API JSON responses.
- Canonical stored shape: `findings[]` array in the output JSON (see Data Shapes below).
- Delivery payload: JSON report file + human-readable text report to stdout.

## Data Shapes

### Raw Input (GitHub Contents API)
```json
{
  "name": ".env",
  "path": "config/.env",
  "repository": { "full_name": "owner/repo", "updated_at": "2024-01-14T08:00:00Z" },
  "html_url": "https://github.com/owner/repo/blob/main/config/.env",
  "url": "https://api.github.com/repos/owner/repo/contents/config/.env",
  "content": "<base64>",
  "encoding": "base64"
}
```

### Canonical Stored Shape (Finding)
```json
{
  "service": "stripe",
  "file": "config/.env",
  "repository": "owner/repo",
  "url": "https://github.com/owner/repo/blob/main/config/.env",
  "line_number": 12,
  "line_preview": "STRIPE_SECRET_KEY=sk_live_****...",
  "key_type": "stripe_key",
  "description": "Stripe Live Secret Key",
  "severity": "critical",
  "matched_pattern": "sk_l****...ive_",
  "timestamp": "2026-03-04T16:36:00"
}
```

### Output Shape (JSON Report)
```json
{
  "scan_metadata": {
    "timestamp": "...",
    "total_repositories": 3,
    "total_files_scanned": 12,
    "total_findings": 7,
    "scanner_version": "2.0",
    "scanned_repos": { "owner/repo": { "last_scanned": "...", "github_updated_at": "...", "keys_found": 2 } },
    "visited_services": { "stripe": { "worker_id": "worker_001_stripe", "spawned_at": "...", "status": "done" } }
  },
  "findings": [ ... ]
}
```

### Visited State Shapes (Internal)
```python
# L1 — visited_services
visited_services = {
    "stripe": {"worker_id": "worker_001_stripe", "spawned_at": "...", "status": "active"}
}
# L2 — scanned_repos
scanned_repos = {
    "owner/repo": {"last_scanned": "...", "github_updated_at": "...", "keys_found": 2}
}
# L3/4 — global_visited_keys (set of fingerprint strings)
# Fingerprint format: {service}:{repo}:{path}:{sha256_prefix_of_raw_key}
visited_keys = {"stripe:owner/repo:config/.env:a3f2b1c4d5e6f7a8"}
```

## Behavioral Rules
- **Do not** display unredacted API keys in any output.
- **Do not** make write operations to any GitHub repository.
- **Do not** guess schema shapes — stop and ask if a new API response format appears.
- Rate-limit sleep must use actual reset timestamp from `X-RateLimit-Reset` header, never a fixed sleep.
- Repo rescanning: only rescan if `github_updated_at` is newer than our `last_scanned` timestamp.
- Key fingerprint format must be `{service}:{repo}:{path}:{sha256[:16]}` — never deviate.

## File Map
| File | Purpose |
|---|---|
| `main.py` | Core scanner — entry point, all 5 architecture classes |
| `architecture/plan.md` | Milestones + acceptance criteria |
| `architecture/todo.md` | Task list + Green Gate evidence |
| `architecture/learning_log.md` | Lessons learned (Healing outputs) |
| `architecture/prompt_patches.md` | Prompt improvements |
| `.agent/workflows/kickoff.md` | How to start a new feature |
| `.agent/rules/` | Permanent coding rules |
| `tools/verify_token.py` | [U]nlock gate — run before scanning |
| `tools/` | Deterministic helper scripts |
| `Recursive Multi-Worker GitHub Scanner.md` | Kimi's architecture design doc (source of v2.0) |
