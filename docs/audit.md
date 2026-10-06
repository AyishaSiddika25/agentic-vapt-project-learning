# Repository audit

Audit date: 2026-10-06

## Baseline

The repository began as a sequence of learning exercises rather than an installable application. Days 1–5
cover Git change scoping and Python AST exploration. Day 6 introduced a Semgrep subprocess adapter, SARIF
normalization, and 17 directly runnable tests. Day 7 added a first fingerprint, exact deduplication, and a
severity gate. Untracked Days 8–12 added heuristic risk/context enrichment, prompt construction, simulated LLM
analysis, response validation, and a confidence-based decision prototype.

Before implementation:

- `Day-06/test_semgrep_adapter.py`: 17/17 passed when invoked directly.
- Repository-wide `unittest discover`: discovered zero tests because `Day-06` is not an importable package name.
- Python byte compilation: passed.
- Ruff: reported 25 issues in the learning prototypes.
- Dependency manifests, package metadata, CI, suppression, explicit reachability, centralized policy,
  reporting, and an end-to-end entry point were absent.
- `Day-10/config.py` contained a demonstration hardcoded password.
- The repository's `.venv` is a `uv` trampoline whose backing runtime was not accessible in the initial
  sandbox. Validation used the Codex bundled Python 3.12 runtime instead.

## Architecture decision

The day-by-day prototypes are preserved as learning history. Production-quality integration lives in the
standard-library-only `agentic_vapt` package. Existing Semgrep/SARIF behavior informed the scanner and
normalization interfaces; existing fingerprint, triage, and LLM response ideas were extended rather than
deleted. The new package provides stable imports, conservative failure semantics, test discovery, a CLI, and
CI without coupling downstream logic to Semgrep.

## Security review notes

- Scanner commands use argument arrays with `shell=False`; target and rule paths must remain under the
  configured workspace.
- SARIF input is size-limited and malformed runs/results are isolated.
- External LLM endpoints require HTTPS, except localhost HTTP for local models. Credentials come only from
  `AGENTIC_VAPT_LLM_API_KEY`.
- Finding/source content is marked untrusted in the model instruction and context is bounded.
- AI runs after the deterministic gate and cannot update its decisions.
- Suppressed and unreachable findings remain in both report formats.
- The system performs static/local processing only. It does not fetch finding URLs or attack targets.

