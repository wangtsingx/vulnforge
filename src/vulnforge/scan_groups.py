"""Generic scan-group generation for any registered project.

Groups are derived automatically from the source tree structure:
directory -> filename-prefix clustering, sized for ~30-minute audit
sessions. Projects may override groups in config/scan_groups.yaml.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vulnforge.config import load_yaml

SLUG_RE = re.compile(r"[^a-z0-9]+")
DEFAULT_TARGET_FILES = 15
DEFAULT_MIN_FILES = 5


def _slug(text: str) -> str:
    return SLUG_RE.sub("-", text.strip("/").lower()).strip("-") or "misc"


def _prefix(stem: str, depth: int = 2) -> str:
    """Return the first `depth` underscore-separated tokens of a filename stem."""
    parts = stem.split("_")
    return "_".join(parts[:depth]) if len(parts) >= depth else stem


def _merge_small_prefixes(
    by_prefix: dict[str, list[Path]],
    target_files: int,
    min_files: int,
) -> tuple[list[tuple[str, list[Path]]], list[Path]]:
    """Split prefix buckets into (large_enough, leftovers).

    Buckets below min_files are iteratively merged into alphabetically
    adjacent buckets until they meet the threshold, then re-checked against
    target_files. Returns (ready_buckets, still_small_files).
    """
    keys = sorted(by_prefix)
    merged: dict[str, list[Path]] = {}
    i = 0
    while i < len(keys):
        current = list(by_prefix[keys[i]])
        while len(current) < min_files and i + 1 < len(keys):
            i += 1
            current.extend(by_prefix[keys[i]])
        if len(current) >= min_files:
            merged[keys[i]] = current
        else:
            merged.setdefault(keys[i], current)
        i += 1
    # Second pass: merge any remaining small bucket into previous
    ready: list[tuple[str, list[Path]]] = []
    carry: list[Path] = []
    for key in sorted(merged):
        items = merged[key]
        if carry:
            items = carry + items
            carry = []
        if len(items) < min_files:
            carry = items
        elif len(items) <= target_files:
            ready.append((key, items))
        else:
            ready.append((key, items))
    if carry:
        ready.append(("__carry__", carry))
    return ready, []


IGNORE_DIRS = {".git", ".svn", "node_modules", "__pycache__", ".venv", "build", "dist", "test"}


def collect_source_files(root: Path, allowed: set[str]) -> list[Path]:
    return sorted(
        p for p in root.rglob("*")
        if p.is_file() and not p.is_symlink() and p.suffix in allowed
        and not any(part in IGNORE_DIRS for part in p.relative_to(root).parts)
    )


def generate_scan_groups(
    root: Path,
    allowed: set[str],
    target_files: int = DEFAULT_TARGET_FILES,
    min_files: int = DEFAULT_MIN_FILES,
) -> list[dict[str, Any]]:
    """Auto-partition source files into audit groups.

    Algorithm:
    1. Bucket files by parent directory.
    2. Directories larger than target_files are split by filename prefix.
    3. Buckets smaller than min_files are merged into their nearest
       sibling bucket (or a top-level _misc group).
    """
    files = collect_source_files(root, allowed)
    if not files:
        return []

    # Step 1: bucket by directory
    by_dir: dict[str, list[Path]] = {}
    for f in files:
        rel_dir = f.parent.relative_to(root).as_posix()
        by_dir.setdefault(rel_dir if rel_dir != "." else "", []).append(f)

    buckets: list[tuple[str, list[Path]]] = []  # (bucket_key, files)

    for dir_path in sorted(by_dir):
        dir_files = by_dir[dir_path]
        if len(dir_files) <= target_files:
            buckets.append((dir_path, dir_files))
            continue
        # Step 2: split large directory by filename prefix, merging small prefixes
        by_prefix: dict[str, list[Path]] = {}
        for f in dir_files:
            by_prefix.setdefault(_prefix(f.stem), []).append(f)
        ready, leftover = _merge_small_prefixes(by_prefix, target_files, min_files)
        for prefix, pf in ready:
            if prefix == "__carry__":
                key = f"{dir_path}/misc" if dir_path else "misc"
            else:
                key = f"{dir_path}/{prefix}" if dir_path else prefix
            buckets.append((key, pf))
        for f in leftover:
            key = f"{dir_path}/misc" if dir_path else "misc"
            # Append to existing misc bucket or create new
            found = False
            for idx, (bk, bf) in enumerate(buckets):
                if bk == key:
                    bf.append(f)
                    found = True
                    break
            if not found:
                buckets.append((key, [f]))

    # Step 3: merge tiny buckets into nearest sibling
    final: list[tuple[str, list[Path]]] = []
    pending: list[tuple[str, list[Path]]] = []
    for key, group_files in buckets:
        if len(group_files) < min_files:
            pending.append((key, group_files))
        else:
            final.append((key, group_files))
    misc: list[Path] = []
    for key, group_files in pending:
        parent = str(Path(key).parent)
        target = next(
            (b for b in final if b[0] == parent or b[0].startswith(parent + "/")),
            None,
        )
        if target:
            target[1].extend(group_files)
            target[1].sort()
        else:
            misc.extend(group_files)
    if misc:
        final.append(("_misc", sorted(misc)))

    # Step 4: if too many groups, merge adjacent alphabetical pairs
    MAX_GROUPS = 20
    while len(final) > MAX_GROUPS:
        final.sort(key=lambda x: x[0])
        merged_pairs: list[tuple[str, list[Path]]] = []
        i = 0
        while i < len(final):
            if i + 1 < len(final) and len(final[i][1]) + len(final[i + 1][1]) <= target_files * 2:
                key = final[i][0]
                merged_pairs.append((key, sorted(final[i][1] + final[i + 1][1])))
                i += 2
            else:
                merged_pairs.append(final[i])
                i += 1
        if len(merged_pairs) >= len(final):
            break
        final = merged_pairs

    groups: list[dict[str, Any]] = []
    for key, group_files in sorted(final):
        rel_files = sorted(f.relative_to(root).as_posix() for f in group_files)
        dirs = sorted({str(Path(f).parent) for f in rel_files})
        groups.append({
            "group_id": _slug(key),
            "description": f"Auto-generated: {len(rel_files)} files in {', '.join(dirs[:3])}"
                           + ("..." if len(dirs) > 3 else ""),
            "paths": rel_files,
        })
    return groups


def load_group_overrides(settings_path: str | Path) -> dict[str, list[dict[str, Any]]]:
    """Load manual scan-group overrides from config/scan_groups.yaml."""
    path = Path(settings_path)
    if not path.is_file():
        return {}
    cfg = load_yaml(path)
    return cfg.get("scan_groups", {})


def resolve_scan_groups(
    project: str,
    root: Path,
    allowed: set[str],
    scan_groups_config: str | Path,
) -> tuple[list[dict[str, Any]], bool]:
    """Return (groups, is_override). Overrides win; otherwise auto-generate."""
    overrides = load_group_overrides(scan_groups_config)
    if project in overrides:
        return overrides[project], True
    return generate_scan_groups(root, allowed), False
