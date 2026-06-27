import csv
import json
import os
import re
import sys
from collections import deque, defaultdict


class JavaDependencyAnalyzer:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.file_to_package = {}        # rel_path -> package.ClassName
        self.package_to_file = {}        # package.ClassName -> rel_path
        self.package_members = defaultdict(list)  # package -> [rel_path] (for wildcard imports)
        self.package_classmap = defaultdict(dict)  # package -> {ClassName: rel_path} (same-package refs)
        self._package_regex = {}         # package -> compiled \b(Class1|Class2|...)\b (cached)
        self.dependencies = {}           # rel_path -> set(rel_path)  (all in-repo direct deps)
        self.done = set()                # rel_paths that are already ported (status DONE)
        self.all_files = []

    def scan_files(self):
        print(f"Scanning {self.root_dir} for Java files...", file=sys.stderr)
        for root, dirs, files in os.walk(self.root_dir):
            for file in files:
                if file.endswith(".java"):
                    rel_path = os.path.relpath(os.path.join(root, file), self.root_dir)
                    rel_path = rel_path.replace(os.sep, "/")
                    self.all_files.append(rel_path)

                    package_name = self._extract_package_from_file(
                        os.path.join(root, file)
                    )
                    if package_name:
                        class_name = os.path.splitext(file)[0]
                        full_name = f"{package_name}.{class_name}"
                        self.package_to_file[full_name] = rel_path
                        self.file_to_package[rel_path] = full_name
                        self.package_members[package_name].append(rel_path)
                        self.package_classmap[package_name][class_name] = rel_path

    def _extract_package_from_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("package "):
                        return line.replace("package ", "").replace(";", "").strip()
                    if (
                        line.startswith("import ")
                        or line.startswith("public ")
                        or line.startswith("class ")
                    ):
                        break  # package declaration is always at the top
        except Exception:
            pass
        return None

    def load_manifest(self, manifest_path):
        """Mark files whose manifest status is DONE so they drop out of dep counts.

        Manifest rows are TAB-separated: <path>\t<status>\t<package...>
        Paths include the root prefix (e.g. 'orig_src/...'), so strip it to match
        our root-relative rel_paths.
        """
        if not manifest_path or not os.path.exists(manifest_path):
            return 0
        root_prefix = os.path.basename(self.root_dir.rstrip("/")) + "/"
        n = 0
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 2:
                    continue
                path, status = parts[0], parts[1].strip().upper()
                if status == "DONE":
                    rel = path[len(root_prefix):] if path.startswith(root_prefix) else path
                    self.done.add(rel)
                    n += 1
        return n

    def _same_package_regex(self, package_name):
        """Cached \\b(Class1|Class2|...)\\b for a package's in-repo classes.

        Longest names first so e.g. `Sequence` can't pre-empt `SequenceItem`
        (word boundaries already prevent substring hits, but ordering is cheap
        insurance). Returns None for packages with no members.
        """
        if package_name not in self._package_regex:
            names = sorted(self.package_classmap.get(package_name, {}), key=len, reverse=True)
            self._package_regex[package_name] = (
                re.compile(r"\b(" + "|".join(map(re.escape, names)) + r")\b") if names else None
            )
        return self._package_regex[package_name]

    def get_dependencies(self, rel_path):
        """All in-repo direct dependencies: explicit imports, wildcard expansion,
        AND same-package references (Java needs no import for those, so they were
        previously missed -- the main cause of spurious "0 remaining dep" frontier
        entries that the porter then parks on a missing prerequisite)."""
        if rel_path in self.dependencies:
            return self.dependencies[rel_path]

        file_path = os.path.join(self.root_dir, rel_path)
        deps = set()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Explicit single-class imports: import a.b.C;
            for imp in re.findall(r"^import\s+(?:static\s+)?([\w\.]+);", content, re.MULTILINE):
                if imp.endswith(".*"):
                    continue  # handled below
                if imp in self.package_to_file:
                    deps.add(self.package_to_file[imp])

            # Wildcard imports: import a.b.*;  -> every in-repo class in package a.b
            for pkg in re.findall(r"^import\s+(?:static\s+)?([\w\.]+)\.\*;", content, re.MULTILINE):
                for member in self.package_members.get(pkg, ()):
                    deps.add(member)

            # Same-package references: sibling class names used in the body, no import.
            full = self.file_to_package.get(rel_path)
            if full:
                package_name = full.rsplit(".", 1)[0]
                rgx = self._same_package_regex(package_name)
                if rgx is not None:
                    classmap = self.package_classmap[package_name]
                    for name in set(rgx.findall(content)):
                        sib = classmap.get(name)
                        if sib:
                            deps.add(sib)
        except Exception:
            pass

        deps.discard(rel_path)  # never depend on self
        self.dependencies[rel_path] = deps
        return deps

    def get_remaining_dependencies(self, rel_path):
        """Direct deps that are NOT yet ported -- the dynamic, status-aware count."""
        return self.get_dependencies(rel_path) - self.done

    def get_recursive_dependencies(self, rel_path):
        visited = set()
        to_visit = deque([rel_path])
        while to_visit:
            current = to_visit.popleft()
            if current not in visited:
                visited.add(current)
                for dep in self.get_dependencies(current):
                    if dep not in visited:
                        to_visit.append(dep)
        visited.discard(rel_path)
        return visited

    def get_all_stats(self):
        stats = []
        for f in self.all_files:
            deps = self.get_dependencies(f)
            remaining = deps - self.done
            stats.append(
                {
                    "file": f,
                    "package": self.file_to_package.get(f, ""),
                    "dep_count": len(deps),
                    "remaining_dep_count": len(remaining),
                    "done": f in self.done,
                    "dependencies": sorted(deps),
                }
            )
        return stats


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Ghidra-rs Parity & Dependency Checker")
    parser.add_argument("--root", default="orig_src", help="Root directory of original source")
    parser.add_argument("--manifest", default="PORT_MANIFEST.tsv",
                        help="Manifest TSV used to determine which files are already DONE")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    parser.add_argument("--csv", action="store_true", help="Output results in CSV format")
    parser.add_argument("--check-deps", help="Check recursive dependencies for a specific file")
    parser.add_argument("--utility-only", action="store_true",
                        help="Only analyze files in Ghidra/Framework/Utility")
    parser.add_argument("--port-order", action="store_true",
                        help="Emit TODO files ordered by remaining (unported) dependency count "
                             "-- the frontier the daemon should port next. Output: '<n>\\t<file>'.")
    args = parser.parse_args()

    if not os.path.exists(args.root):
        print(f"Error: {args.root} directory not found.")
        sys.exit(1)

    analyzer = JavaDependencyAnalyzer(args.root)
    analyzer.scan_files()
    done_n = analyzer.load_manifest(args.manifest)
    if done_n:
        print(f"Loaded {done_n} DONE entries from {args.manifest}", file=sys.stderr)

    if args.utility_only:
        analyzer.all_files = [f for f in analyzer.all_files if "Ghidra/Framework/Utility" in f]

    if args.check_deps:
        target = args.check_deps
        if target not in analyzer.all_files:
            matches = [f for f in analyzer.all_files if target in f]
            if len(matches) == 1:
                target = matches[0]
            elif len(matches) > 1:
                print(f"Ambiguous file name. Matches: {matches[:5]}")
                sys.exit(1)
            else:
                print(f"File not found: {target}")
                sys.exit(1)
        deps = analyzer.get_recursive_dependencies(target)
        print(f"Recursive dependencies for {target}:")
        for d in sorted(deps):
            print(f"  {d}")
        print(f"\nTotal recursive dependencies: {len(deps)}")
        return

    if args.port_order:
        # Frontier first: lowest remaining (unported) deps, then lowest total deps, then path.
        # Files already DONE are excluded. Count 0 == ready to port now with no stubbing.
        todo = [f for f in analyzer.all_files if f not in analyzer.done]
        ordered = sorted(
            todo,
            key=lambda f: (
                len(analyzer.get_remaining_dependencies(f)),
                len(analyzer.get_dependencies(f)),
                f,
            ),
        )
        for f in ordered:
            print(f"{len(analyzer.get_remaining_dependencies(f))}\t{f}")
        return

    stats = analyzer.get_all_stats()

    if args.json:
        print(json.dumps(stats, separators=(",", ":")))
    elif args.csv:
        writer = csv.DictWriter(
            sys.stdout, fieldnames=["file", "package", "dep_count", "remaining_dep_count", "done"]
        )
        writer.writeheader()
        for s in stats:
            writer.writerow({k: s[k] for k in ["file", "package", "dep_count", "remaining_dep_count", "done"]})
    else:
        print("\nTop 20 unported files with fewest remaining dependencies:")
        todo = [s for s in stats if not s["done"]]
        for s in sorted(todo, key=lambda x: (x["remaining_dep_count"], x["dep_count"]))[:20]:
            print(f"{s['remaining_dep_count']:3} rem ({s['dep_count']:3} total) | {s['file']}")


if __name__ == "__main__":
    main()