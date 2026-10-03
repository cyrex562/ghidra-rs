#!/usr/bin/env python3
"""Vendor Ghidra's theme files and the icons they reference into
ghidra-ui-model/resources/ghidra-theme, mirroring Ghidra's module layout so
generic::theme::ThemeIconResolver::from_ghidra_root works on it unchanged.

Also writes ICON_LICENSES.tsv (one row per image, from each module's
certification.manifest) and copies the licence texts those rows name.

usage: scripts/vendor_ghidra_theme.py [ORIG_SRC] [DEST]
  ORIG_SRC defaults to orig_src (the Ghidra checkout root), DEST to
  ghidra-ui-model/resources/ghidra-theme. Re-running replaces DEST.
"""
import glob
import os
import re
import shutil
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
orig = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "orig_src"))
dest = os.path.abspath(sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, "ghidra-ui-model/resources/ghidra-theme"))
ghidra = os.path.join(orig, "Ghidra")

IMAGE = re.compile(r"[\w.+/-]+\.(?:png|gif|svg|jpg|ico)")

props = sorted(glob.glob(os.path.join(ghidra, "**/data/*.theme.properties"), recursive=True))
# component-wise, as Rust's PathBuf ordering (Foo/ before Foo-Bar/)
roots = sorted(glob.glob(os.path.join(ghidra, "**/src/main/resources"), recursive=True), key=lambda p: p.split(os.sep))


def referenced_images(path):
    names = set()
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.split("//", 1)[0]  # trailing comments name missing icons
        m = re.match(r"\s*icon\.[^=]*=\s*(.+)", line)
        if m:
            names.update(n for n in IMAGE.findall(m.group(1)) if not n.startswith("laf."))
    return names


def locate(name):
    # ResourceManager order (as IconResourceLocator ports it): a bare name as
    # images/<name> across roots, then the path itself across roots.
    for rel in ([f"images/{name}"] if "/" not in name else []) + [name]:
        for r in roots:
            p = os.path.join(r, rel)
            if os.path.isfile(p):
                return p
    return None


def module_of(path):
    rel = os.path.relpath(path, ghidra)
    head = rel.split(os.sep + "src" + os.sep, 1)[0] if os.sep + "src" + os.sep in rel else rel.split(os.sep + "data" + os.sep, 1)[0]
    return head


def manifest_licenses(module):
    out = {}
    m = os.path.join(ghidra, module, "certification.manifest")
    if os.path.isfile(m):
        for line in open(m, encoding="utf-8", errors="replace"):
            parts = line.rstrip("\n").split("||")
            if len(parts) >= 2 and parts[0]:
                # path||LICENSE|||note|END|  → keep only the note text
                note = " ".join(x for x in "|".join(parts[2:]).split("|") if x and x != "END")
                out[parts[0]] = (parts[1], note)
    return out


if os.path.isdir(dest):
    shutil.rmtree(dest)
names = set()
for p in props:
    rel = os.path.relpath(p, ghidra)
    os.makedirs(os.path.join(dest, os.path.dirname(rel)), exist_ok=True)
    shutil.copyfile(p, os.path.join(dest, rel))
    names |= referenced_images(p)

rows, missing, licences = [], [], set()
manifests = {}
for n in sorted(names):
    src = locate(n)
    if not src:
        missing.append(n)
        continue
    rel = os.path.relpath(src, ghidra)
    os.makedirs(os.path.join(dest, os.path.dirname(rel)), exist_ok=True)
    shutil.copyfile(src, os.path.join(dest, rel))
    module = module_of(src)
    lic = manifests.setdefault(module, manifest_licenses(module)).get(os.path.relpath(src, os.path.join(ghidra, module)), ("UNKNOWN", ""))
    rows.append((rel, lic[0], lic[1]))
    licences.add(lic[0])

with open(os.path.join(dest, "ICON_LICENSES.tsv"), "w") as f:
    f.write("path\tlicense\tnote\n")
    for r in sorted(set(rows)):
        f.write("\t".join(r) + "\n")

lic_dir = os.path.join(dest, "licenses")
os.makedirs(lic_dir)
for name in ("LICENSE", "NOTICE"):
    shutil.copyfile(os.path.join(orig, name), os.path.join(lic_dir, f"GHIDRA_{name}"))
unmatched = []
lic_dirs = [os.path.join(orig, "licenses"), os.path.join(orig, "GPL", "licenses")]


def lic_files(stem):
    return [p for d in lic_dirs for p in glob.glob(os.path.join(d, stem + ".*"))]


for lic in sorted(licences - {"GHIDRA"}):
    found = lic_files(lic.replace(" ", "_"))
    # the icon-set notices only point at the licence; ship the full texts
    if lic.startswith("FAMFAMFAM Icons - CC"):
        found += lic_files("Creative_Commons_Attribution_2.5")
    if lic.endswith("LGPL 2.1"):
        found += lic_files("LGPL_2.1")
    if lic.endswith("LGPL 3.0"):
        found += lic_files("LGPL_3.0") + lic_files("GPL_3")  # LGPLv3 §4(b): both texts
    for p in found:
        shutil.copyfile(p, os.path.join(lic_dir, os.path.basename(p)))
    if not found:
        unmatched.append(lic)

# Modified LGPL icons ship with their sources (their notice points here).
if "Modified Nuvola Icons - LGPL 2.1" in licences:
    src = os.path.join(orig, "GPL", "Icons", "ModifiedNuvola")
    out = os.path.join(dest, "GPL", "Icons", "ModifiedNuvola")
    shutil.copytree(src, out)
    shutil.copyfile(os.path.join(orig, "GPL", "Icons", "certification.manifest"), os.path.join(dest, "GPL", "Icons", "certification.manifest"))

# Which Ghidra source the files came from.
props_file = dict(
    line.strip().split("=", 1) for line in open(os.path.join(ghidra, "application.properties")) if "=" in line and not line.startswith("#")
)
with open(os.path.join(dest, "SOURCE_VERSION"), "w") as f:
    f.write(f"Ghidra {props_file.get('application.version', '?')} {props_file.get('application.release.name', '')}".strip() + "\n")

print(f"{len(props)} theme files, {len(rows)} images, {len(missing)} unresolved {missing}")
print("licences:", sorted(licences), "unmatched:", unmatched)
