"""Remove the plain-language explanation comments added for learning.

Every such comment is a whole line that carries the marker "[explain]":
    # [explain] ...            (Python, shell, YAML, config)
    // [explain] ...           (TypeScript / JavaScript, also inside <script>)
    <!-- [explain] ... -->     (Vue / HTML templates)
Only those lines are removed; no other comment and no code is touched.

Dry run by default.   python scripts/strip_explanations.py            (counts only)
                      python scripts/strip_explanations.py --apply    (remove them)
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", "venv", "node_modules", "dist", "__pycache__", ".claude", "alembic/versions"}
EXTENSIONS = {".py", ".sh", ".ts", ".js", ".vue", ".yml", ".yaml", ".txt", ".ini", ".md"}
MARKER = re.compile(r"^\s*(#|//|<!--)\s*\[explain\]")


def files():
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix not in EXTENSIONS:
            continue
        parts = set(path.relative_to(ROOT).parts)
        if parts & SKIP_DIRS or path.resolve() == Path(__file__).resolve():
            continue
        yield path


def main(apply: bool) -> None:
    total, touched = 0, 0
    for path in files():
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines(keepends=True)
        kept = [line for line in lines if not MARKER.match(line)]
        removed = len(lines) - len(kept)
        if removed:
            total += removed
            touched += 1
            print(f"{removed:4d}  {path.relative_to(ROOT)}")
            if apply:
                path.write_text("".join(kept), encoding="utf-8")
    verb = "removed" if apply else "would remove"
    print(f"{verb} {total} explanation line(s) in {touched} file(s)" + ("" if apply else "  (dry run; use --apply)"))


if __name__ == "__main__":
    main("--apply" in sys.argv)
