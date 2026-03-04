---
description: How to kick off a new feature or milestone on this project
---

# Kickoff Workflow

Use this at the start of every new feature or B.U.I.L.D. phase.

## Steps

1. **Read `gemini.md`** — confirm you understand the North Star, data shapes, and behavioral rules before touching any code.

2. **Read `architecture/plan.md`** — identify which milestone you are in and confirm the current phase gate status.

3. **Read `architecture/todo.md`** — find the next `[ ]` task. Do not skip ahead.

4. **Read `architecture/prompt_patches.md`** — apply all permanent rules before writing any code.

5. **Read `architecture/learning_log.md`** — check if the work you're about to do has a known failure mode.

6. **Unlock check (if new integration):** Run `tools/verify_token.py` and confirm 200 OK before proceeding.

7. **Do the work** — implement the task chunk, following the 3-layer architecture.

8. **Run the Green Gate:**
   - `python tools/test_patterns.py`
   - `python tools/test_redact.py`
   - `python tools/test_report.py`
   - Record evidence in `architecture/todo.md`.

9. **If any gate fails** → Enter Healing Patch Protocol. Update `learning_log.md` and `prompt_patches.md`. Re-run gate.

10. **Mark task `[x]` in `todo.md`** and move to next task.
