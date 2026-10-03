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
icon images they reference, copied from a Ghidra source checkout (version recorded in
`SOURCE_VERSION`, currently Ghidra 12.2 DEV) by `scripts/vendor_ghidra_theme.py`, with
Ghidra's module layout preserved. Ghidra itself is licensed under the Apache License 2.0
(`licenses/GHIDRA_LICENSE`, `licenses/GHIDRA_NOTICE`). Several icon sets carry their own
licences, recorded per file in `ICON_LICENSES.tsv` (taken from Ghidra's
`certification.manifest` files), with the full licence texts in `licenses/`:
- GHIDRA icons: Apache 2.0.
- FAMFAMFAM Icons: CC BY 2.5, attribution Mark James (famfamfam.com).
- FAMFAMFAM Mini Icons, Tango Icons: public domain.
- Oxygen Icons and one other file: LGPL 3.0 (`LGPL_3.0.html` with `GPL_3.html`, as LGPLv3 requires).
- Nuvola, Modified Nuvola and Crystal Clear Icons: LGPL 2.1 (`LGPL_2.1.txt`). The sources of the
  Modified Nuvola icons are in `GPL/Icons/ModifiedNuvola`.
- One file under MIT.
