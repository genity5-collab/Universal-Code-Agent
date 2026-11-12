---
name: debugging
description: Systematic debugging with the Universal-Code-Agent tools. Reproduce, isolate, hypothesize, fix, verify.
---
# Debugging
1. **Reproduce first.** Run the failing command (`run_tests`, or `run_command`) and capture the exact error. If you cannot reproduce, say so and gather more evidence instead of guessing.
2. **Read the whole error.** Use `read_command_log` / `job_output` with offsets for long output. Note the first error, not the last cascade.
3. **Locate.** Use `find_symbol` and `search_content` on names in the stack trace. Read the failing function and its callers with `read_file_range`.
4. **Form 1-3 hypotheses**, ranked. Test the cheapest one first with a targeted run or a temporary log line (remove it afterwards).
5. **Fix the cause**, not the symptom. Change as little as possible.
6. **Verify**: the original failure is gone, the full related test suite still passes, and add a regression test when practical.
7. **Report**: root cause, fix, evidence (command and result). If still failing, report what you ruled out.
Avoid: blind retries, disabling tests, broad try/catch that hides errors, and rewriting unrelated code.
