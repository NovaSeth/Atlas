#!/usr/bin/env python3
"""Guard against weakened tests (audit plan GC6): compare the test files at a git ref with the working tree.

Usage: inventory.py --base <ref>
Exit 0 when clean, 1 with one line per violation: "<path>::<qualname>: removed|weakened".

Rule, for every function, class and method in test files (`*/tests/*.py`, `tests/*.py`) present at <ref>:
  * missing now                                           -> removed
  * AST changed AND the diff removes >= 1 line inside the
    old line range of the definition (a class counts only
    its own lines, not those of its methods)              -> weakened
Entries in allowed-test-edits.txt (`path::qualname  # P-id`) are skipped. Exit 2 (message on stderr) on a usage, git or parse error.
"""
import argparse
import ast
import fnmatch
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@")


def git(root, *args):
    r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit("inventory: git %s failed: %s" % (" ".join(args), r.stderr.strip()))
    return r.stdout


def is_test_file(path):
    return path.endswith(".py") and (fnmatch.fnmatch(path, "tests/*.py") or fnmatch.fnmatch(path, "*/tests/*.py"))


def definitions(source, path):
    """{qualname: (ast_dump, [(first_line, last_line), ...])} for functions, classes and their methods."""
    out = {}

    def walk(body, prefix):
        for node in body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            qual = prefix + node.name
            first = min([node.lineno] + [d.lineno for d in node.decorator_list])
            if isinstance(node, ast.ClassDef):
                children = [c for c in node.body if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
                own = ast.dump(ast.Module([c for c in node.body if c not in children], []))
                own += ast.dump(ast.Tuple(node.bases + node.decorator_list, ast.Load()))
                spans, cur = [], first
                for c in children:
                    cfirst = min([c.lineno] + [d.lineno for d in c.decorator_list])
                    if cfirst > cur:
                        spans.append((cur, cfirst - 1))
                    cur = c.end_lineno + 1
                if cur <= node.end_lineno:
                    spans.append((cur, node.end_lineno))
                out[qual] = (own, spans)
                walk(node.body, qual + ".")
            else:
                out[qual] = (ast.dump(node), [(first, node.end_lineno)])

    try:
        tree = ast.parse(source, path)
    except SyntaxError as exc:
        raise SystemExit("inventory: %s does not parse: %s" % (path, exc))
    walk(tree.body, "")
    return out


def removed_lines(root, ref, path):
    """Old-file line numbers the diff against <ref> removes (git diff -U0 compares with the working tree)."""
    lines = set()
    for line in git(root, "diff", "-U0", ref, "--", path).splitlines():
        m = HUNK.match(line)
        if m:
            start, count = int(m.group(1)), int(m.group(2) if m.group(2) is not None else 1)
            lines.update(range(start, start + count))
    return lines


def allowed(path):
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base", required=True, help="git ref to compare with")
    ap.add_argument("--root", default=str(HERE.parents[1]), help="repository root (default: this checkout)")
    ap.add_argument("--allowed", default=str(HERE / "allowed-test-edits.txt"))
    args = ap.parse_args(argv)
    root = Path(args.root)
    skip = allowed(Path(args.allowed)) if Path(args.allowed).exists() else set()
    violations = []
    for path in git(root, "ls-tree", "-r", "--name-only", args.base).splitlines():
        if not is_test_file(path):
            continue
        old = definitions(git(root, "show", "%s:%s" % (args.base, path)), path)
        now_file = root / path
        new = definitions(now_file.read_text(encoding="utf-8"), path) if now_file.exists() else {}
        removed = None
        for qual, (dump, spans) in sorted(old.items()):
            key = "%s::%s" % (path, qual)
            if key in skip:
                continue
            if qual not in new:
                violations.append("%s: removed" % key)
                continue
            if new[qual][0] == dump:
                continue
            if removed is None:
                removed = removed_lines(root, args.base, path)
            if any(n in removed for a, b in spans for n in range(a, b + 1)):
                violations.append("%s: weakened" % key)
    for v in violations:
        print(v)
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
