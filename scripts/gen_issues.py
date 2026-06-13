#!/usr/bin/env python3
"""
Generate .agents/issue-drafts/NNN-port-<slug>.md for every unported Java class
found by sync_check.py.  Classes already checked off in todo.md are skipped.

Usage:
    python scripts/gen_issues.py
"""

import json
import os
import re
import subprocess
import sys
from collections import Counter

REPO_ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ISSUES_DIR  = os.path.join(REPO_ROOT, ".agents", "issue-drafts")
TODO_FILE   = os.path.join(REPO_ROOT, "todo.md")
ORIG_SRC    = os.path.join(REPO_ROOT, "orig_src")
SYNC_SCRIPT = os.path.join(REPO_ROOT, "scripts", "sync_check.py")

START_NUM   = 16   # existing issues are 001-015


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ported_classnames(todo_path: str) -> set[str]:
    """Return the set of simple class names that are checked off in todo.md."""
    names: set[str] = set()
    with open(todo_path, encoding="utf-8") as fh:
        for line in fh:
            stripped = line.strip()
            if not stripped.startswith("- [x]"):
                continue
            # Backtick-quoted identifiers, e.g. `AddressFactory`
            names.update(re.findall(r"`([A-Za-z][A-Za-z0-9_]*)`", stripped))
    return names


def risk_tier(dep_count: int) -> str:
    if dep_count <= 2:
        return "low"
    if dep_count <= 10:
        return "medium"
    return "high"


def module_root(java_path: str) -> str:
    """Return the Ghidra sub-project path, e.g. 'Ghidra/Framework/DB'."""
    parts = java_path.split("/")
    # Standard layout: Ghidra/<type>/<module>/src/...
    for i, p in enumerate(parts):
        if p == "src" and i >= 2:
            return "/".join(parts[:i])
    return os.path.dirname(java_path)


def unique_slug(java_path: str, seen: Counter) -> str:
    """
    Build a filesystem-safe slug from the Java path.
    Disambiguates duplicate simple names by prepending the immediate parent package.
    """
    classname = os.path.splitext(os.path.basename(java_path))[0].lower()
    if seen[classname] == 0:
        slug = classname
    else:
        # Use last two path components before the filename for disambiguation
        parts = java_path.replace("\\", "/").split("/")
        # Drop .java extension part; take up to 2 parent dirs
        dirs = [p for p in parts[:-1] if p not in ("src", "main", "java", "test")]
        prefix = "-".join(dirs[-2:]).lower() if len(dirs) >= 2 else dirs[-1].lower() if dirs else "x"
        prefix = re.sub(r"[^a-z0-9]+", "-", prefix).strip("-")
        slug = f"{prefix}-{classname}"
    seen[classname] += 1
    return slug


def dep_lines(dependencies: list[str]) -> str:
    if not dependencies:
        return "_None_"
    lines = []
    for d in dependencies:
        cls = os.path.splitext(os.path.basename(d))[0]
        lines.append(f"- `{cls}` — `{d}`")
    return "\n".join(lines)


def render_issue(num: int, java_path: str, package: str,
                 dep_count: int, dependencies: list[str]) -> str:
    classname   = os.path.splitext(os.path.basename(java_path))[0]
    mod_root    = module_root(java_path)
    tier        = risk_tier(dep_count)
    dep_section = dep_lines(dependencies)

    return f"""\
# Port `{classname}`

**Risk tier:** {tier}

## Context
Java class `{package or classname}` lives in `{java_path}` (sub-project: `{mod_root}`).
It has **{dep_count}** direct intra-project dependenc{"y" if dep_count == 1 else "ies"}.

## Goal
Port `{classname}` to idiomatic Rust, preserving the public API and observable
behaviour of the Java original documented in `orig_src/{java_path}`.

## Acceptance criteria
- Rust implementation covers the full public API of the Java class.
- Unit tests exercise primary behaviour, edge cases, and error paths present in
  the Java source.
- `cargo test --workspace` passes with no regressions.
- All public items carry Rustdoc comments.
- `todo.md` is updated to reflect completion only after implementation, tests,
  and Java-parity review are all done.

## Constraints
- `orig_src/{java_path}` is the source of truth (per AGENTS.md).
- No placeholder or stub implementations without explicit user approval.
- Use already-ported Rust types for any dependency classes where available;
  port prerequisites first if they are missing.
- Do not introduce `unwrap()` calls in production code (see issue 010).

## Out of scope
- Porting dependency classes not yet ported — those are tracked as separate issues.
- UI integration unless this class is itself a UI component.

## References
- `orig_src/{java_path}` — Java source of truth.
- **Direct dependencies ({dep_count}):**
{dep_section}
"""


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    os.makedirs(ISSUES_DIR, exist_ok=True)

    # 1. Determine already-ported class names
    ported = ported_classnames(TODO_FILE)
    print(f"[gen_issues] {len(ported)} class names marked ported in todo.md")

    # 2. Run sync_check.py to get dependency data for all Java files
    print("[gen_issues] Running sync_check.py (this may take ~30 s)…")
    proc = subprocess.run(
        [sys.executable, SYNC_SCRIPT, "--root", ORIG_SRC, "--json"],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )
    if proc.returncode != 0:
        print("sync_check.py failed:", proc.stderr[:400], file=sys.stderr)
        sys.exit(1)

    # First line is "Scanning … for Java files…"; skip it
    raw = proc.stdout
    json_start = raw.index("[")
    data: list[dict] = json.loads(raw[json_start:])
    print(f"[gen_issues] {len(data)} Java files found")

    # 3. Sort: fewest deps first (easiest to port), then alphabetically
    data.sort(key=lambda x: (x["dep_count"], x["file"]))

    # 4. First pass: build slug uniqueness counter across ALL items we will emit
    seen: Counter = Counter()
    slug_map: dict[str, str] = {}  # java_path -> slug
    for item in data:
        classname = os.path.splitext(os.path.basename(item["file"]))[0]
        if classname in ported:
            continue
        slug = unique_slug(item["file"], seen)
        slug_map[item["file"]] = slug

    # 5. Second pass: write files
    skipped = 0
    created = 0

    for item in data:
        java_path   = item["file"]
        classname   = os.path.splitext(os.path.basename(java_path))[0]
        package     = item.get("package", "")
        dep_count   = item["dep_count"]
        dependencies = item["dependencies"]

        if classname in ported:
            skipped += 1
            continue

        num      = START_NUM + created
        slug     = slug_map[java_path]
        filename = f"{num:05d}-port-{slug}.md"
        filepath = os.path.join(ISSUES_DIR, filename)

        content = render_issue(num, java_path, package, dep_count, dependencies)

        with open(filepath, "w", encoding="utf-8") as fh:
            fh.write(content)

        created += 1

        if created % 1000 == 0:
            print(f"[gen_issues] … {created} files written")

    print(f"[gen_issues] Done. Skipped (ported): {skipped}  Created: {created}")
    print(f"[gen_issues] Issues numbered {START_NUM:05d}–{START_NUM + created - 1:05d}")


if __name__ == "__main__":
    main()
