#!/usr/bin/env python3
"""
GitHub issue reconciliation + per-class issue tracking for the porting harness.

Background
----------
The existing open issues are corrupt: ~1,284 of them share one identical
per-package title (`Port package `...btree` (9 classes)`), while the manifest is
per *class*. This tool replaces that scheme with one issue per manifest class,
matched reliably through a local join map instead of flaky title search.

Identity
--------
Class names are NOT unique across packages (196 collide), so the join key is the
full manifest path (`orig_src/.../Foo.java`), recorded in:

    .agents/issue-map.tsv     <relpath>\t<issue#>

`ensure` is idempotent: it returns the existing number if mapped, otherwise
creates the issue, records it, and returns the new number. That makes issue
creation lazy -- the harness only creates an issue for a class when it actually
works on it, so we never fire 15k creations at once (which would trip GitHub's
secondary rate limits).

Subcommands
-----------
    cleanup            Close every open issue whose title starts with
                       "Port package `" (the corrupt per-package dupes).
    ensure  <relpath>  Print the issue number for a class, creating it if needed.
    close   <relpath>  Close the class's issue with a completion comment.
    park    <relpath>  Label the class's issue needs-attention with a reason.

All GitHub mutations are throttled and retried on secondary-rate-limit errors.
Set GH=0 in the environment to make every subcommand a no-op (prints/echoes only)
-- useful for manifest-only runs.
"""

import argparse
import os
import re
import subprocess
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GH_REPO = os.environ.get("GH_REPO", "cyrex562/ghidra-rs")
MAP_PATH = os.path.join(REPO_ROOT, ".agents", "issue-map.tsv")
GH_ENABLED = os.environ.get("GH", "1") != "0"

# Throttle between mutating gh calls; bumped automatically on rate-limit backoff.
BASE_SLEEP = float(os.environ.get("GH_SLEEP", "1.0"))


def log(msg: str) -> None:
    print(f"[issuelib] {msg}", file=sys.stderr)


def gh(args, check=True, capture=True, retries=5):
    """Run a gh command with secondary-rate-limit backoff."""
    delay = 2.0
    for attempt in range(retries):
        proc = subprocess.run(
            ["gh", *args],
            capture_output=capture,
            text=True,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        if proc.returncode == 0:
            return proc.stdout.strip() if capture else ""
        if re.search(r"rate limit|too quickly|secondary", out, re.I):
            log(f"rate-limited, backing off {delay:.0f}s ({attempt + 1}/{retries})")
            time.sleep(delay)
            delay *= 2
            continue
        if check:
            log(f"gh {' '.join(args)} failed: {out.strip()[:200]}")
            raise RuntimeError(out.strip()[:200])
        return None
    if check:
        raise RuntimeError("gh exhausted retries")
    return None


# --- local join map -------------------------------------------------------

def load_map() -> dict:
    m = {}
    if os.path.exists(MAP_PATH):
        with open(MAP_PATH, encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) == 2 and parts[1].isdigit():
                    m[parts[0]] = int(parts[1])
    return m


def map_set(relpath: str, number: int) -> None:
    os.makedirs(os.path.dirname(MAP_PATH), exist_ok=True)
    m = load_map()
    m[relpath] = number
    tmp = MAP_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for k in sorted(m):
            fh.write(f"{k}\t{m[k]}\n")
    os.replace(tmp, MAP_PATH)


# --- helpers --------------------------------------------------------------

def classname(relpath: str) -> str:
    return os.path.splitext(os.path.basename(relpath))[0]


def module_root(relpath: str) -> str:
    parts = relpath.split("/")
    for i, p in enumerate(parts):
        if p == "src" and i >= 1:
            return "/".join(parts[:i])
    return os.path.dirname(relpath)


# --- subcommands ----------------------------------------------------------

def cmd_cleanup(_args) -> int:
    if not GH_ENABLED:
        log("GH disabled; cleanup is a no-op")
        return 0
    log("listing corrupt per-package issues (title starts with 'Port package `') ...")
    raw = gh([
        "issue", "list", "--repo", GH_REPO, "--state", "open",
        "--limit", "5000", "--json", "number,title",
        "--jq", '.[] | select(.title | startswith("Port package `")) | .number',
    ])
    nums = [n for n in (raw or "").splitlines() if n.strip().isdigit()]
    log(f"{len(nums)} corrupt issues to close")
    for i, n in enumerate(nums, 1):
        gh(["issue", "close", n, "--repo", GH_REPO,
            "--comment", "Superseded by per-class porting issues; closing corrupt per-package duplicate."],
           check=False)
        if i % 25 == 0:
            log(f"closed {i}/{len(nums)}")
        time.sleep(BASE_SLEEP)
    log(f"done: closed {len(nums)} corrupt issues")
    return 0


def cmd_ensure(args) -> int:
    relpath = args.relpath
    m = load_map()
    if relpath in m:
        print(m[relpath])
        return 0
    if not GH_ENABLED:
        # Manifest-only mode: no real issue, emit sentinel.
        print("0")
        return 0
    cls = classname(relpath)
    mod = module_root(relpath)
    title = f"Port `{cls}` ({mod})"
    body = (
        f"Port the Java class `{cls}` to idiomatic Rust.\n\n"
        f"- **Source of truth:** `{relpath}`\n"
        f"- **Module:** `{mod}`\n\n"
        f"Acceptance: full public API covered, focused unit tests, `cargo build --lib` "
        f"green, manifest row flipped TODO->DONE.\n\n"
        f"<!-- port-relpath: {relpath} -->\n"
    )
    url = gh([
        "issue", "create", "--repo", GH_REPO,
        "--title", title, "--body", body, "--label", "ready",
    ])
    num = int(url.rstrip("/").split("/")[-1])
    map_set(relpath, num)
    time.sleep(BASE_SLEEP)
    print(num)
    return 0


def cmd_close(args) -> int:
    relpath = args.relpath
    m = load_map()
    num = m.get(relpath)
    if not num:
        log(f"no mapped issue for {relpath}; nothing to close")
        return 0
    if not GH_ENABLED:
        log(f"GH disabled; would close #{num}")
        return 0
    comment = args.comment or "Ported and merged into `integration`."
    gh(["issue", "edit", str(num), "--repo", GH_REPO,
        "--remove-label", "ready", "--remove-label", "implementing"], check=False)
    gh(["issue", "close", str(num), "--repo", GH_REPO, "--comment", comment], check=False)
    time.sleep(BASE_SLEEP)
    log(f"closed #{num} for {relpath}")
    return 0


def cmd_park(args) -> int:
    relpath = args.relpath
    num = load_map().get(relpath)
    if not num:
        log(f"no mapped issue for {relpath}; nothing to park")
        return 0
    if not GH_ENABLED:
        log(f"GH disabled; would park #{num}")
        return 0
    reason = args.comment or "Parked by harness: could not port cleanly within the rules."
    gh(["issue", "edit", str(num), "--repo", GH_REPO, "--add-label", "needs-attention"], check=False)
    gh(["issue", "comment", str(num), "--repo", GH_REPO, "--body", reason], check=False)
    time.sleep(BASE_SLEEP)
    log(f"parked #{num} for {relpath}")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Per-class GitHub issue tracking for the porting harness")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("cleanup", help="close corrupt per-package duplicate issues")

    pe = sub.add_parser("ensure", help="print issue number for a class, creating if needed")
    pe.add_argument("relpath")

    pc = sub.add_parser("close", help="close a class's issue")
    pc.add_argument("relpath")
    pc.add_argument("--comment", default="")

    pp = sub.add_parser("park", help="label a class's issue needs-attention")
    pp.add_argument("relpath")
    pp.add_argument("--comment", default="")

    args = p.parse_args()
    return {
        "cleanup": cmd_cleanup,
        "ensure": cmd_ensure,
        "close": cmd_close,
        "park": cmd_park,
    }[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
