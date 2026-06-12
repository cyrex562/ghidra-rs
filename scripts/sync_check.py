import csv
import json
import os
import re
import sys
from collections import deque


class JavaDependencyAnalyzer:
    def __init__(self, root_dir):
        self.root_dir = root_dir
        self.file_to_package = {}  # rel_path -> package.ClassName
        self.package_to_file = {}  # package.ClassName -> rel_path
        self.dependencies = {}  # rel_path -> set(rel_path)
        self.all_files = []

    def scan_files(self):
        print(f"Scanning {self.root_dir} for Java files...")
        for root, dirs, files in os.walk(self.root_dir):
            for file in files:
                if file.endswith(".java"):
                    rel_path = os.path.relpath(os.path.join(root, file), self.root_dir)
                    rel_path = rel_path.replace(os.sep, "/")
                    self.all_files.append(rel_path)

                    # Try to determine package from path
                    # Standard structure: .../src/main/java/package/path/File.java
                    # Some scripts are in .../ghidra_scripts/File.java
                    package_name = self._extract_package_from_file(
                        os.path.join(root, file)
                    )
                    if package_name:
                        class_name = os.path.splitext(file)[0]
                        full_name = f"{package_name}.{class_name}"
                        self.package_to_file[full_name] = rel_path
                        self.file_to_package[rel_path] = full_name

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
                        break  # Optimization: package should be at the top
        except Exception:
            pass
        return None

    def get_dependencies(self, rel_path):
        if rel_path in self.dependencies:
            return self.dependencies[rel_path]

        file_path = os.path.join(self.root_dir, rel_path)
        deps = set()
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                # Simple regex for imports
                imports = re.findall(r"^import\s+([\w\.]+);", content, re.MULTILINE)
                for imp in imports:
                    if imp in self.package_to_file:
                        deps.add(self.package_to_file[imp])
                    else:
                        # Handle wildcard imports? (e.g. import ghidra.util.*;)
                        # For now, let's keep it simple and only match exact classes
                        pass
        except Exception:
            pass

        self.dependencies[rel_path] = deps
        return deps

    def get_recursive_dependencies(self, rel_path):
        visited = set()
        to_visit = deque([rel_path])

        while to_visit:
            current = to_visit.popleft()
            if current not in visited:
                visited.add(current)
                deps = self.get_dependencies(current)
                for dep in deps:
                    if dep not in visited:
                        to_visit.append(dep)

        visited.remove(rel_path)
        return visited

    def get_all_stats(self):
        stats = []
        for f in self.all_files:
            deps = self.get_dependencies(f)
            stats.append(
                {
                    "file": f,
                    "package": self.file_to_package.get(f, ""),
                    "dep_count": len(deps),
                    "dependencies": sorted(list(deps)),
                }
            )
        return stats


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Ghidra-rs Parity & Dependency Checker"
    )
    parser.add_argument(
        "--root", default="orig_src", help="Root directory of original source"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output results in JSON format"
    )
    parser.add_argument(
        "--csv", action="store_true", help="Output results in CSV format"
    )
    parser.add_argument(
        "--check-deps", help="Check recursive dependencies for a specific file"
    )
    parser.add_argument(
        "--utility-only",
        action="store_true",
        help="Only analyze files in Ghidra/Framework/Utility",
    )

    args = parser.parse_args()

    if not os.path.exists(args.root):
        print(f"Error: {args.root} directory not found.")
        sys.exit(1)

    analyzer = JavaDependencyAnalyzer(args.root)
    analyzer.scan_files()

    if args.utility_only:
        analyzer.all_files = [
            f for f in analyzer.all_files if "Ghidra/Framework/Utility" in f
        ]

    if args.check_deps:
        # Find file by partial match if needed
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
        for d in sorted(list(deps)):
            print(f"  {d}")
        print(f"\nTotal recursive dependencies: {len(deps)}")
        return

    stats = analyzer.get_all_stats()

    if args.json:
        # For token efficiency, use compact JSON
        print(json.dumps(stats, separators=(",", ":")))
    elif args.csv:
        writer = csv.DictWriter(sys.stdout, fieldnames=["file", "package", "dep_count"])
        writer.writeheader()
        for s in stats:
            writer.writerow({k: s[k] for k in ["file", "package", "dep_count"]})
    else:
        # Default: Print top 20 files with lowest dependencies
        print("\nTop 20 files with lowest direct dependencies:")
        sorted_stats = sorted(stats, key=lambda x: x["dep_count"])
        for s in sorted_stats[:20]:
            print(f"{s['dep_count']:3} | {s['file']}")


if __name__ == "__main__":
    main()
