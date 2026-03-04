# Recursive Multi-Worker GitHub Scanner

## Architecture Overview

```plain
┌─────────────────────────────────────────────────────────────┐
│                     MAIN EXPLORER                           │
│              (Discovers new service types)                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Visited Services Set: {serper.dev, openai.com}    │   │
│  │  Active Workers Registry                            │   │
│  └─────────────────────────────────────────────────────┘   │
└────────────────────┬────────────────────────────────────────┘
                     │
                     │ Discovers: serper.dev API key
                     │ Check: Is serper.dev in visited?
                     │ Result: No → Spawn Worker
                     ▼
        ┌────────────────────────────┐
        │      SERPER.DEV WORKER     │
        │  (Deep search: serper.dev) │
        │  ┌──────────────────────┐  │
        │  │ Visited Keys Store   │  │
        │  │ {repo:path:line_hash}│  │
        │  └──────────────────────┘  │
        └────────────────────────────┘
                     │
                     │ Discovers: new pattern variant
                     │ Check: Is this key fingerprint visited?
                     │ Result: No → Process & Update
                     ▼
        ┌────────────────────────────┐
        │    PATTERN EVOLUTION       │
        │  (Worker feeds back learnings)│
        │  - New regex patterns      │
        │  - Key format variants     │
        │  - Repository clusters     │
        └────────────────────────────┘
                     │
                     │ Updates Global Pattern DB
                     │ Broadcasts to all workers
                     ▼
        ┌────────────────────────────┐
        │   GLOBAL PATTERN DATABASE  │
        │   (Shared across workers)  │
        └────────────────────────────┘

                     │
                     │ Discovers: openai.com key
                     │ Check: Is openai.com in visited?
                     │ Result: No → Spawn Worker
                     ▼
        ┌────────────────────────────┐
        │     OPENAI.COM WORKER      │
        │  (Deep search: openai.com) │
        │  ┌──────────────────────┐  │
        │  │ Visited Keys Store   │  │
        │  │ {repo:path:line_hash}│  │
        │  └──────────────────────┘  │
        └────────────────────────────┘
```

## Key Components

### 1. **Main Explorer**

- Broad search for any API keys
- Identifies service types from findings
- Maintains **Visited Services Set** to avoid duplicate worker spawning
- Routes new discoveries to appropriate workers or spawns new ones

### 2. **Service Workers** (One per service type)

- Dedicated deep-search for a specific service (e.g., serper.dev)
- Maintains **Visited Keys Store** (fingerprint-based deduplication)
- Updates Pattern Database with new findings
- Terminates when queue empty or no new patterns found

### 3. **Visited State Management**

#### Global Visited Services (Main Explorer)

```python
visited_services = {
    "serper.dev": {
        "worker_id": "worker_001",
        "spawned_at": "2024-01-15T10:30:00Z",
        "status": "active"
    },
    "openai.com": {
        "worker_id": "worker_002", 
        "spawned_at": "2024-01-15T10:35:00Z",
        "status": "active"
    }
}
```

#### Per-Worker Visited Keys (Service Workers)

```python
# Fingerprint format: {service}:{repo}:{path}:{key_hash}
visited_keys = {
    "serper.dev:facebook/react:src/.env:a3f2b1...",
    "serper.dev:torvalds/linux:config.env:9c8d2a...",
    "openai.com:microsoft/vscode:.env.local:7e4f5c..."
}
```

#### Scanned Repositories (Timestamp-based)

```python
scanned_repos = {
    "facebook/react": {
        "last_scanned": "2024-01-15T10:30:00Z",
        "github_updated_at": "2024-01-14T08:00:00Z",
        "keys_found": 3
    }
}
```

### 4. **Pattern Database**

- Shared knowledge base that all workers read/update
- Stores regex patterns, key formats, repository clusters
- Versioned to track pattern evolution

### 5. **Work Queue**

- **Main Queue**: New service discoveries from Main Explorer
- **Service Queues**: One per service worker for deep-search tasks
- **Priority**: New services > Pattern updates > Deep search

### 6. **Result Aggregator**

- Deduplicates findings across all workers
- Maintains global visited set
- Generates research reports

## Worker Lifecycle with Visited Tracking

```plain
Main Explorer scans → Finds "serper.dev" key in "facebook/react"
                          ↓
                   Create fingerprint: "serper.dev:facebook/react:.env:L42:hash"
                          ↓
                   Check Global Visited Keys
                          ↓
                   Already exists? → Skip (already reported)
                   New finding? → Continue
                          ↓
                   Check: Is serper.dev in visited_services?
                          ↓
                   Yes → Add repo to serper.dev worker's queue
                   No  → Spawn new serper.dev worker
                          ↓
                   Spawn serper.dev worker:
                   - Initialize with seed pattern
                   - Create worker-specific visited set
                   - Add to visited_services registry
                          ↓
                   serper.dev worker runs:
                   ├─ Search for serper.dev patterns
                   ├─ For each finding:
                   │  ├─ Create fingerprint
                   │  ├─ Check worker's visited set
                   │  ├─ If new: Process → Add to visited → Report
                   │  └─ If seen: Skip
                   ├─ Discover new pattern variant
                   ├─ Update global Pattern Database
                   └─ Broadcast to other workers
                          ↓
                   Main Explorer continues scanning...
                   (Won't respawn serper.dev worker)
```

## BFS/DFS Analogy with Visited Tracking

This is a **hybrid approach with cycle detection**:

### Graph Structure

```plain
Level 0 (Root): GitHub Universe
    │
    ├── Level 1 (Service Nodes): serper.dev, openai.com, stripe.com...
    │   │
    │   ├── Level 2 (Repo Nodes): Each service's repos
    │   │   │
    │   │   ├── Level 3 (File Nodes): .env files in repos
    │   │   │   │
    │   │   │   └── Level 4 (Key Nodes): Individual keys in files
    │   │   │
    │   │   └── [VISITED: Skip if already processed]
    │   │
    │   └── [VISITED: Skip if worker already active]
    │
    └── [Main Explorer continues BFS]
```

### Traversal Strategy

- **Main Explorer**: BFS Level 0→1 (breadth-first discovery of service types)
  - Uses **Visited Services Set** to avoid respawning workers
  - Explores horizontally across all services

- **Service Workers**: DFS Level 1→4 (depth-first exploration of each service)
  - Uses **Visited Keys Set** to avoid reprocessing same keys
  - Explores vertically within their service domain
  - Updates global knowledge for other workers

### Visited Set Semantics

| Level             | Visited Set        | Purpose                       | Scope                  |
| :---------------- | :----------------- | :---------------------------- | :--------------------- |
| L1 (Services)     | `visited_services` | Don't spawn duplicate workers | Global (Main Explorer) |
| L2-4 (Keys)       | `visited_keys`     | Don't report same key twice   | Global (Aggregator)    |
| L2 (Repos)        | `scanned_repos`    | Skip if no new commits        | Per-worker + Global    |
| L3-4 (Files/Keys) | `worker_visited`   | Worker-local cache            | Per-worker             |

## Deduplication Flow

```plain
┌─────────────────┐
│  Find API Key   │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────┐
│ Create Fingerprint          │
│ {service}:{repo}:{path}:{hash}
└────────┬────────────────────┘
         │
         ▼
┌─────────────────────────────┐     Yes    ┌─────────────┐
│ Check Global Visited Keys   │───────────→│    Skip     │
│ (All workers share this)    │            │  (Duplicate)│
└────────┬────────────────────┘            └─────────────┘
         │ No
         ▼
┌─────────────────────────────┐     Yes    ┌─────────────┐
│ Check Service Worker Exists?│───────────→│ Add to Queue│
│ (visited_services check)    │            │ (Existing)  │
└────────┬────────────────────┘            └─────────────┘
         │ No
         ▼
┌─────────────────────────────┐
│ Spawn New Service Worker    │
│ Add to visited_services     │
└─────────────────────────────┘
```

## Handling GitHub's Non-Deterministic Ordering

Since GitHub search **does NOT guarantee chronological order**:

```python
class ResilientVisitedTracker:
    """
    Handles out-of-order results from GitHub API.
    """
    
    def should_process_repo(self, repo: str, github_updated_at: str) -> bool:
        """
        Check if we should scan this repo.
        
        Strategy:
        1. If never seen → Scan it
        2. If seen but GitHub shows newer update → Rescan
        3. If seen and GitHub shows same/older → Skip
        """
        if repo not in self.scanned_repos:
            return True  # New repo
        
        last_scan = self.scanned_repos[repo]
        
        # GitHub's updated_at vs our last scan
        if github_updated_at > last_scan['github_updated_at']:
            # Repo has new activity since we last saw it
            return True
        
        return False
    
    def is_key_new(self, fingerprint: str) -> bool:
        """
        Check if we've seen this exact key before.
        Uses fingerprint for O(1) lookup.
        """
        return fingerprint not in self.global_visited_keys
```

## Storage Options for Visited Sets

| Scale           | Visited Services     | Visited Keys      | Scanned Repos  |
| :-------------- | :------------------- | :---------------- | :------------- |
| Small (<10K)    | Python `set`         | Python `set`      | SQLite         |
| Medium (10K-1M) | Redis Set            | Redis Set         | PostgreSQL     |
| Large (>1M)     | Redis + Bloom Filter | Distributed Cache | Time-series DB |

## Key Benefits of This Architecture

1. **No Duplicate Work**: Visited sets prevent reprocessing
2. **Scalable**: Workers operate independently
3. **Resilient**: Can resume from crash using persisted visited sets
4. **Efficient**: DFS within service, BFS across services
5. **Evolving**: Pattern database improves all workers over time
