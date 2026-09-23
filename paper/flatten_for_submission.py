#!/usr/bin/env python3
r"""Rewrites a copied manuscript so its tables and figures resolve inside the bundle.

The working tree keeps generated tables in ``results/tables/`` and reaches them
with ``\input{../results/tables/...}``, so the generator owns them and the
manuscript cannot drift from the measurements. That path does not survive
submission: Springer and arXiv unpack the source into a single directory, where the
parent reference resolves to nothing and the build fails once per table.

EMSE's guidelines go further: "Please do not use subfolders for your LaTeX
submission, e.g. for figures or bibliographic files." So the bundle is flat, and
this rewrites both kinds of reference to match it:

- the ``\resulttable`` definition in the preamble loses its
  ``../results/tables/`` prefix, so each table is read from the bundle root;
- every ``\paperfigure{figures/...}`` call loses its ``figures/`` prefix, because
  ``\paperfigure`` tests the path with ``\IfFileExists``, which ignores
  ``\graphicspath``, and would otherwise degrade to a placeholder box.

It edits the copy inside the bundle, never the tracked source.

Kept as a script rather than inlined into the Makefile because the replacement
text is made of backslashes, braces and a ``#`` parameter marker, each of which is
consumed by make or by the shell before reaching the file.

    python3 flatten_for_submission.py dist/iacsecbench.tex
"""

from __future__ import annotations

import pathlib
import sys

MARKER = "% ---- injected by `make dist`: flattened table and figure paths ----"
TABLE_PREFIX = "../results/tables/"
FIGURE_PREFIX = "\\paperfigure{figures/"


def flatten(path: pathlib.Path) -> str:
    source = path.read_text(encoding="utf-8")

    if MARKER in source:
        return f"{path}: already flattened, left alone"

    anchor = "\\begin{document}"
    at = source.find(anchor)
    if at < 0:
        raise SystemExit(f"error: {path} has no {anchor}; not a manuscript source")

    preamble, body = source[:at], source[at:]
    if "\\resulttable" not in preamble or TABLE_PREFIX not in preamble:
        raise SystemExit(
            f"error: {path} does not define \\resulttable over {TABLE_PREFIX} in its\n"
            "       preamble. The table-input mechanism has changed and this script is\n"
            "       stale; fix it rather than shipping a bundle whose tables vanish."
        )

    # Rewritten in place rather than overridden with \renewcommand, so the bundle
    # a reviewer opens holds no parent-directory path at all.
    preamble = preamble.replace(TABLE_PREFIX, "")
    figures = body.count(FIGURE_PREFIX)
    body = body.replace(FIGURE_PREFIX, "\\paperfigure{")
    path.write_text(f"{MARKER}\n{preamble}{body}", encoding="utf-8")
    return (
        f"{path}: \\resulttable redirected to the bundle root, {figures} figure path(s) flattened"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip().splitlines()[-1].strip(), file=sys.stderr)
        return 2
    target = pathlib.Path(argv[1])
    if not target.is_file():
        raise SystemExit(f"error: {target} not found")
    print(flatten(target))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
