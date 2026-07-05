#!/usr/bin/env python3

# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: BUSL-1.1

"""
tests/newman/scripts/validate-cases.py — MANDATORY case-uniqueness + catalog validation.

Run in CI **before** the newman step (pure-Python, no network). Hard-fails when:

  1. The same case-id appears more than once across all modules that gen.py
     produces (within a file, between files, in helper blocks). Duplicate
     case-ids are forbidden.

  2. A case-id is not catalogued: every case-id must either
       (a) be covered in `docs/CASES-INDEX.md` — either as the literal id or
           as a suffix pattern `*-<SUFFIX>` (suffix after the first '-').
       (b) be tagged with `# index: <ref>` on (or 1-2 lines above) the
           `id="..."` line, meaning "instance of an already-catalogued pattern".

Helper-generated cases (e.g. `http_method_not_allowed_block`) cannot be
tagged at the case-file level because their ids are constructed inside gen.py;
they pass (2) via CASES-INDEX.md catalogue entries only.

Usage:
    python3 tests/newman/scripts/validate-cases.py
    # or equivalently:
    python3 tests/newman/scripts/gen.py --validate
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"
CASES_DIR = ROOT / "cases"
INDEX_FILE = ROOT / "docs" / "CASES-INDEX.md"

_ID_RE = re.compile(r"""id\s*=\s*["']([A-Z0-9][A-Z0-9_-]+)["']""")
_INDEX_TAG_RE = re.compile(r"#\s*index:\s*(\S+)")

sys.path.insert(0, str(SCRIPTS_DIR))


def _suffix(case_id: str) -> str:
    """`NLB-CR-CRUD-OK` -> `CR-CRUD-OK` (strip domain prefix before first '-')."""
    parts = case_id.split("-")
    return "-".join(parts[1:]) if len(parts) > 1 else case_id


def _text_tags() -> dict[str, set[str]]:
    """Scan case modules for `# index:` tags near `id=` lines."""
    tagged: dict[str, set[str]] = {}
    for f in sorted(CASES_DIR.glob("*.py")):
        if f.name.startswith("_"):
            continue
        lines = f.read_text().splitlines()
        for i, line in enumerate(lines):
            m = _ID_RE.search(line)
            if not m:
                continue
            case_id = m.group(1)
            window = "\n".join(lines[max(0, i - 2): i + 1])
            if _INDEX_TAG_RE.search(window):
                tagged.setdefault(case_id, set()).add(f.name)
    return tagged


def _all_cases() -> list[tuple[str, str]]:
    """Import case modules the same way gen.py does → ordered [(case_id, file), ...]."""
    import gen  # noqa: E402

    out: list[tuple[str, str]] = []
    for f in sorted(CASES_DIR.glob("*.py")):
        if f.name.startswith("_"):
            continue
        mod = gen.load_cases_module(f)
        for c in getattr(mod, "CASES", []):
            out.append((c.id, f.name))
    return out


def main() -> int:
    errors: list[str] = []

    try:
        cases = _all_cases()
    except Exception as exc:  # noqa: BLE001 — surface as validation failure
        sys.stderr.write(f"validate-cases: FAIL — cannot load case modules: {exc}\n")
        return 1
    if not cases:
        sys.stderr.write("validate-cases: FAIL — no cases\n")
        return 1

    # ---- (1) duplicate case-ids ----
    seen: dict[str, str] = {}
    for case_id, fname in cases:
        if case_id in seen:
            errors.append(
                f"duplicate case-id {case_id!r}: appears in {seen[case_id]} and {fname} "
                f"(case-ids must be unique)"
            )
        else:
            seen[case_id] = fname

    # ---- (2) each case-id catalogued in CASES-INDEX.md or tagged `# index:` ----
    index_text = INDEX_FILE.read_text() if INDEX_FILE.exists() else ""
    if not index_text:
        errors.append(f"missing {INDEX_FILE}")
    tagged = _text_tags()
    checked: set[str] = set()
    for case_id, fname in cases:
        if case_id in checked:
            continue
        checked.add(case_id)
        if case_id in tagged:
            continue
        suf = _suffix(case_id)
        if f"*-{suf}" in index_text or case_id in index_text:
            continue
        errors.append(
            f"case {case_id!r} (from {fname}) not catalogued in docs/CASES-INDEX.md.\n"
            f"    → NEW unique pattern: add `*-{suf}` (or `{case_id}`) entry to "
            f"docs/CASES-INDEX.md (and a REQ-* in PRODUCT-REQUIREMENTS.md if appropriate);\n"
            f"    → INSTANCE of an existing pattern: tag the `id=` line with "
            f"`# index: <pattern-ref>`."
        )

    if errors:
        sys.stderr.write("validate-cases: FAIL\n")
        for e in errors:
            sys.stderr.write("  - " + e + "\n")
        return 1
    print(
        f"validate-cases: OK — {len(seen)} unique case-ids, no duplicates, "
        f"all catalogued (CASES-INDEX / # index:)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
