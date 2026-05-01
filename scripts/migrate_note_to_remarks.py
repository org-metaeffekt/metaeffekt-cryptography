#!/usr/bin/env python3
"""
One-shot migration: rename top-level `note:` (algorithm-entry level) to
`remarks: [...]` (single-element list) in the algorithm-registry YAMLs.

Authority-nested `note:` fields (under bsi:, nist:, cnsa:, ietf:, etc.) are
preserved unchanged.

Detection rule: a `note:` line is "top-level" if it sits at exactly 4 spaces
of indent (the same level as `id:`, `oid:`, `prefix:` etc. on a top-level
entry). Authority-nested `note:` is at 6+ spaces or appears inline inside
`{ ... }` flow mappings — both forms are skipped.
"""

import re
import sys
from pathlib import Path

REGISTRY = Path(__file__).resolve().parent.parent / "ae-pattern-validator" / "src" / "main" / "resources" / "registry"
TARGETS = [
    "cr-asymmetric.yaml", "cr-pqc.yaml", "cr-symmetric-ciphers.yaml",
    "cr-hash-functions.yaml", "cr-kdfs.yaml", "cr-macs.yaml",
    "cr-rngs.yaml", "cr-cdx.yaml", "cr-spdx.yaml", "cr-x509.yaml",
]

# Match a top-level `note:` line: exactly 4 spaces, then `note: "..."`.
# Allow either double-quoted or single-quoted strings.
NOTE_LINE_RE = re.compile(r'^    note: ("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\')\s*$')


def migrate_file(path: Path) -> int:
    """Rewrite path in place. Returns the number of lines changed."""
    lines = path.read_text().splitlines(keepends=False)
    out = []
    changes = 0
    for line in lines:
        m = NOTE_LINE_RE.match(line)
        if m:
            # Convert: `    note: "value"` → `    remarks:\n      - "value"`
            value = m.group(1)
            out.append("    remarks:")
            out.append(f"      - {value}")
            changes += 1
        else:
            out.append(line)
    path.write_text("\n".join(out) + "\n")
    return changes


def main():
    total = 0
    for name in TARGETS:
        path = REGISTRY / name
        if not path.exists():
            print(f"  SKIP  {name} (file not found)")
            continue
        changed = migrate_file(path)
        total += changed
        print(f"  {name}: {changed} top-level note: → remarks: conversions")
    print(f"\nTotal lines migrated: {total}")


if __name__ == "__main__":
    main()
