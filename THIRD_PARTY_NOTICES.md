# Third-party notices

## Qt 6 (https://www.qt.io)
The `ghidra-qt` binary links the Qt 6 libraries dynamically under the GNU LGPL v3.
Qt is not distributed in this repository.

## Qt Advanced Docking System (https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System)
Vendored as a git submodule at `ghidra-qt/third_party/ads` (commit 4f4f602c3f7b02ee041793e9bc5833bab1bdb4ab)
and compiled into `ghidra-qt`. Licensed under the GNU LGPL v2.1; its complete source is
the submodule, so users can modify and relink it.

## Ghidra theme files and icons (https://github.com/NationalSecurityAgency/ghidra)
`ghidra-ui-model/resources/ghidra-theme` holds Ghidra's `*.theme.properties` files and the
icon images they reference, copied from Ghidra 12.1.2 by `scripts/vendor_ghidra_theme.py`
with Ghidra's module layout preserved. Ghidra itself is licensed under the Apache License 2.0
(`licenses/GHIDRA_LICENSE`, `licenses/GHIDRA_NOTICE`). Several icon sets carry their own
licences, recorded per file in `ICON_LICENSES.tsv` (taken from Ghidra's
`certification.manifest` files) with the licence texts in `licenses/`:
GHIDRA (Apache 2.0), FAMFAMFAM Icons (CC BY 2.5, attribution: Mark James, famfamfam.com),
FAMFAMFAM Mini Icons (public domain), Oxygen Icons (LGPL 3.0), Nuvola and Modified Nuvola
Icons (LGPL 2.1), Crystal Clear Icons (LGPL 2.1), Tango Icons (public domain), plus single
files under MIT and LGPL 3.0.
