#!/usr/bin/env python3
"""Build data/oui.tsv (the vendor list built into Proton IP Scanner).

Accepted input (either one):
  * the IEEE MA-L registry as CSV, e.g. /usr/share/ieee-data/oui.csv
    (Debian package "ieee-data") or https://standards-oui.ieee.org/oui/oui.csv
  * the "oui-data" JSON (npm package oui-data, BSD licence), which merges
    all three IEEE registries: MA-L (6 hex digits), MA-M (7) and MA-S (9).

Output: one line per prefix, sorted:  PREFIX<TAB>Vendor name
The app matches the longest prefix first (9, then 7, then 6 digits).

Usage:
  python3 tools/make-oui.py /usr/share/ieee-data/oui.csv > data/oui.tsv
  python3 tools/make-oui.py node_modules/oui-data/index.json > data/oui.tsv
"""
import csv, json, re, sys

def clean(name):
    # First line only (JSON values include the postal address), single
    # spaces, printable, max 48 characters.
    name = re.sub(r"\s+", " ", name.split("\n")[0]).strip().strip('"')
    return name[:48] if name and name.isprintable() else None

rows = {}
src = sys.argv[1]
if src.endswith(".json"):
    with open(src, encoding="utf-8") as f:
        for prefix, value in json.load(f).items():
            prefix = prefix.upper()
            name = clean(value)
            if re.fullmatch(r"[0-9A-F]{6}|[0-9A-F]{7}|[0-9A-F]{9}", prefix) and name:
                rows[prefix] = name
else:
    with open(src, newline="", encoding="utf-8", errors="replace") as f:
        for row in csv.DictReader(f):
            prefix = row.get("Assignment", "").strip().upper()
            name = clean(row.get("Organization Name", ""))
            if re.fullmatch(r"[0-9A-F]{6}", prefix) and name:
                rows[prefix] = name

for prefix in sorted(rows):
    print(f"{prefix}\t{rows[prefix]}")
