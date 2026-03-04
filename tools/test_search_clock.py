#!/usr/bin/env python3
"""Unit tests for GlobalSearchClock — validates gap enforcement, header-awareness, and thread safety."""
import sys
import time
import threading
sys.path.insert(0, ".")

from main import GlobalSearchClock

PASS = "\033[32m✅ PASS\033[0m"
FAIL = "\033[31m❌ FAIL\033[0m"

results = []

def check(name: str, condition: bool, detail: str = ""):
    icon = PASS if condition else FAIL
    print(f"  {icon}  {name}" + (f"  ({detail})" if detail else ""))
    results.append(condition)

# ---------------------------------------------------------------------------
# Test 1: gap enforcement — 3 sequential acquires should take ≥ 2 gaps × 7s = 14s
# (We use a tiny min_gap for speed)
# ---------------------------------------------------------------------------
print("\nTest 1: gap enforcement")
clock = GlobalSearchClock()
clock._MIN_GAP = 0.1  # 100ms for testing speed
t0 = time.monotonic()
for _ in range(3):
    clock.acquire()
elapsed = time.monotonic() - t0
check("3 acquires take ≥ 2 gaps (0.2s)", elapsed >= 0.18, f"elapsed={elapsed:.3f}s")

# ---------------------------------------------------------------------------
# Test 2: stale reset clears immediately (reset_at in the past)
# ---------------------------------------------------------------------------
print("\nTest 2: stale state clears immediately")
clock = GlobalSearchClock()
clock._MIN_GAP = 0.0
clock._remaining = 0
clock._reset_at = time.time() - 30  # 30s in the past
t0 = time.monotonic()
clock.acquire()
elapsed = time.monotonic() - t0
check("stale reset doesn't sleep", elapsed < 0.5, f"elapsed={elapsed:.3f}s")
check("remaining reset to 9 after stale clear", clock._remaining == 9)

# ---------------------------------------------------------------------------
# Test 3: future reset sleeps correct duration
# ---------------------------------------------------------------------------
print("\nTest 3: future reset sleeps until window")
clock = GlobalSearchClock()
clock._MIN_GAP = 0.0
clock._remaining = 0
future = time.time() + 0.3  # 300ms window
clock._reset_at = future
t0 = time.time()
clock.acquire()
elapsed = time.time() - t0
check("slept ≥ 0.3s for future reset", elapsed >= 0.28, f"elapsed={elapsed:.3f}s")
check("slept ≤ 1.5s (not too long)", elapsed < 1.5, f"elapsed={elapsed:.3f}s")
check("remaining reset after window", clock._remaining == 9)

# ---------------------------------------------------------------------------
# Test 4: record_response updates state from headers
# ---------------------------------------------------------------------------
print("\nTest 4: record_response updates from headers")
clock = GlobalSearchClock()
clock._MIN_GAP = 0.0

class FakeResp:
    def __init__(self, remaining, reset):
        self.headers = {}
        if remaining is not None:
            self.headers["X-RateLimit-Remaining"] = str(remaining)
        if reset is not None:
            self.headers["X-RateLimit-Reset"] = str(reset)

ts = time.time() + 60
clock.record_response(FakeResp(3, ts))
check("remaining updated from header", clock._remaining == 3)
check("reset_at updated from header", abs(clock._reset_at - ts) < 0.01)

# No-op when headers missing
clock.record_response(FakeResp(None, None))
check("no-op when headers missing", clock._remaining == 3)

# ---------------------------------------------------------------------------
# Test 5: thread safety — 5 threads, gaps must all be ≥ min_gap
# ---------------------------------------------------------------------------
print("\nTest 5: thread safety (5 concurrent acquires)")
clock = GlobalSearchClock()
clock._MIN_GAP = 0.05  # 50ms
timestamps = []
lock = threading.Lock()

def worker():
    clock.acquire()
    with lock:
        timestamps.append(time.monotonic())

threads = [threading.Thread(target=worker) for _ in range(5)]
for t in threads: t.start()
for t in threads: t.join()

timestamps.sort()
gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
min_gap = min(gaps)
check("all gaps ≥ 50ms", min_gap >= 0.045, f"min_gap={min_gap*1000:.1f}ms")
check("calls serialised (no overlap)", len(gaps) == 4)

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print(f"\n{'=' * 50}")
passed = sum(results)
total = len(results)
print(f"  {passed}/{total} tests passed")
sys.exit(0 if passed == total else 1)
