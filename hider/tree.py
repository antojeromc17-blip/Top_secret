"""
Tree node definition and rename walk functions.

The tree mirrors the directory structure.  Each node stores:
  original_name   — the item's own filename (no path)
  random_name     — a random UUID-based name (no path, no extension)
  node_type       — "file" | "dir"
  original_attrs  — Windows attribute DWORD captured before any change
  children        — child nodes (always empty for files)

The root node represents the folder being hidden.  Its random_name equals
the vault GUID.  The root is NEVER renamed during step 8; it is moved by
os.rename(src, vault_root/GUID) in step 10.  Only the root's children are
processed by rename_hide / rename_unhide.

Processing order
────────────────
hide   (rename to random)  : post-order  — children renamed before their parent dir
unhide (rename to original): pre-order   — parent dir renamed before its children
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator


def _w(path: Path) -> str:
    """Return a \\?\\-prefixed absolute path string for Win32 / os.rename calls."""
    return "\\\\?\\" + str(path.resolve())


@dataclass
class Node:
    original_name:  str
    random_name:    str           # single UUID string, no slashes, no extension
    node_type:      str           # "file" | "dir"
    original_attrs: int           # raw Windows DWORD
    children:       list["Node"] = field(default_factory=list)

    @property
    def is_dir(self) -> bool:
        return self.node_type == "dir"

    def to_dict(self) -> dict:
        return {
            "original_name":  self.original_name,
            "random_name":    self.random_name,
            "node_type":      self.node_type,
            "original_attrs": self.original_attrs,
            "children":       [c.to_dict() for c in self.children],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Node":
        return cls(
            original_name  = d["original_name"],
            random_name    = d["random_name"],
            node_type      = d["node_type"],
            original_attrs = d["original_attrs"],
            children       = [cls.from_dict(c) for c in d.get("children", [])],
        )


# ── Tree construction ─────────────────────────────────────────────────────────

def build_tree(
    src: Path,
    vault_guid: str,
    name_gen,               # callable() -> str, returns a fresh random name
    get_attrs,              # callable(Path) -> int
    exclude_names: set[str] | None = None,
) -> Node:
    """
    Walk *src* and build the full in-memory tree.
    *exclude_names* — filenames to skip (e.g. {"manifest.dat"}).
    The root node gets random_name = vault_guid.
    """
    exclude = exclude_names or set()

    def _build(path: Path, random_name: str) -> Node:
        attrs = get_attrs(path)
        node  = Node(
            original_name  = path.name,
            random_name    = random_name,
            node_type      = "dir" if path.is_dir() else "file",
            original_attrs = attrs,
        )
        if path.is_dir():
            for child in sorted(path.iterdir()):   # deterministic order
                if child.name in exclude:
                    continue
                node.children.append(_build(child, name_gen()))
        return node

    return _build(src, vault_guid)


# ── Flat iteration (for idempotent recovery) ──────────────────────────────────

def iter_post_order(root: Node) -> Iterator[Node]:
    """
    Yield every node in the tree (excluding root) in post-order
    (deepest children first).
    """
    def _visit(node: Node) -> Iterator[Node]:
        for child in node.children:
            yield from _visit(child)
            yield child
    yield from _visit(root)


def iter_pre_order(root: Node) -> Iterator[Node]:
    """
    Yield every node (excluding root) in pre-order
    (parent before its children).
    """
    def _visit(node: Node) -> Iterator[Node]:
        for child in node.children:
            yield child
            yield from _visit(child)
    yield from _visit(root)


# ── Rename walks ──────────────────────────────────────────────────────────────

def rename_hide(root: Node, src: Path) -> None:
    """
    Rename all children of *root* from original names to random names.
    *src* is the current absolute path of the root folder (not yet moved).
    Post-order: children renamed before their parent directory.

    FIX C1: root itself is NOT renamed here.  os.rename(src, vault_root/GUID) handles the root.
    """
    for child in root.children:
        _rename_node_hide(child, src)


def _rename_node_hide(node: Node, parent: Path) -> None:
    cur_path  = parent / node.original_name
    rand_path = parent / node.random_name
    # First: recurse into children (post-order)
    if node.is_dir:
        for child in node.children:
            _rename_node_hide(child, cur_path)
    # Then: rename this node (idempotent: if rand_path exists, original is gone — skip)
    if rand_path.exists():
        return   # already renamed (crash recovery)
    if cur_path.exists():
        os.rename(_w(cur_path), _w(rand_path))


def rename_unhide(root: Node, dest: Path) -> None:
    """
    Rename all children of *root* from random names back to original names.
    *dest* is the current absolute path of the root folder (already moved back).
    Pre-order: parent dir renamed before its children.

    FIX C1: root itself is NOT renamed here.  os.rename moved it already.
    """
    for child in root.children:
        _rename_node_unhide(child, dest)


def _rename_node_unhide(node: Node, parent: Path) -> None:
    rand_path = parent / node.random_name
    orig_path = parent / node.original_name
    # Rename this node first (pre-order); idempotent
    if orig_path.exists():
        pass   # already restored
    elif rand_path.exists():
        os.rename(_w(rand_path), _w(orig_path))
    # Then recurse into children (now inside orig_path)
    if node.is_dir:
        for child in node.children:
            _rename_node_unhide(child, orig_path)


# ── Rollback ──────────────────────────────────────────────────────────────────

def rollback_hide_renames(root: Node, src: Path) -> None:
    """
    Reverse any completed renames.  Safe to call even if only some renames happened
    (idempotent probe: if random_name exists, rename it back; if original_name
    exists, nothing to do).
    """
    for child in root.children:
        _rollback_node(child, src)


def _rollback_node(node: Node, parent: Path) -> None:
    rand_path = parent / node.random_name
    orig_path = parent / node.original_name
    # Pre-order rollback: rename this node back first, then recurse
    if rand_path.exists() and not orig_path.exists():
        os.rename(_w(rand_path), _w(orig_path))
        if node.is_dir:
            for child in node.children:
                _rollback_node(child, orig_path)
    elif orig_path.exists():
        # Already original; recurse in case some children were renamed
        if node.is_dir:
            for child in node.children:
                _rollback_node(child, orig_path)

