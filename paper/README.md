# IaCSecBench Manuscript (`paper/`)

LaTeX source, bibliography, figures, and build automation for the **IaCSecBench**
paper. **Target venue: Empirical Software Engineering (Springer).**

## 📄 Contents

| Path                        | Role                                                                                          |
| --------------------------- | --------------------------------------------------------------------------------------------- |
| `iacsecbench.tex`           | The manuscript.                                                                               |
| `refs.bib`                  | Bibliography, 53 entries. Every DOI resolves in Crossref or DataCite; none was typed by hand. |
| `Makefile`                  | Build automation. Prefers `tectonic`, falls back to `pdflatex` + `bibtex`.                    |
| `figures/`                  | Two generated diagrams plus their sources. See `figures/README.md`.                           |
| `flatten_for_submission.py` | Rewrites table and figure paths in the bundle copy so everything resolves from one flat directory. Invoked by `make dist`. |

**No result table lives here.** All ten are generated into `results/tables/` by
`evaluation/analyze.py` and `evaluation/corpus.py`, and pulled in with
`\resulttable`. `make` refuses to typeset if any is missing, so the manuscript
cannot contain a hand-written number.

## ⚠️ The class file you must fetch before submitting

EMSE's guidelines offer Springer's **`svjour3`** macro package
([direct zip](https://media.springer.com/full/springer-instructions-for-authors-assets/zip/468198_LaTeX_DL_468198_01072021.zip))
and also recommend the newer Springer Nature LaTeX template. This manuscript
targets `svjour3`. Springer distributes it only in its own template archive: it is
**not on CTAN** and not in any TeX distribution's package set, so no build can
fetch it automatically.

```bash
# once per checkout, before `make dist`
curl -sSLo /tmp/svjour3.zip \
  https://media.springer.com/full/springer-instructions-for-authors-assets/zip/468198_LaTeX_DL_468198_01072021.zip
unzip -j /tmp/svjour3.zip '*/svjour3.cls' '*/svglov3.clo' '*/spbasic.bst' -d .
```

The three files are "(c) Springer" with no redistribution grant, so they are
gitignored rather than committed under this repository's MIT licence. `make dist`
copies them into the bundle, which is what Springer asks for.

The manuscript detects them and switches automatically:

```latex
\newif\ifhassvjour
\IfFileExists{svjour3.cls}{\hassvjourtrue}{\hassvjourfalse}
\ifhassvjour \documentclass[smallextended]{svjour3}
\else        \documentclass[11pt,a4paper]{article} \fi
```

Without them the paper builds under `article` at a text measure of **117 mm**,
deliberately narrower than Springer's `smallextended`. That is the conservative
direction: **anything that fits in the fallback fits in the real class.** Every
table is additionally set with `tabularx` against `\linewidth`, so no table can
overrun whatever measure the class sets. `make` prints a NOTE on every fallback
build so you cannot ship the wrong one by accident, and `make dist` copies the
Springer files into the bundle when they are present.

The bibliography style switches the same way: `spbasic` when present, `plainnat`
otherwise. Both are author–year, so citations render in EMSE's form either way.

## 🛠️ Building

```bash
cd paper
make          # regenerate tables from recorded output, then typeset
make paper    # typeset only, no re-measurement
make check    # report anything that would embarrass a submission
make clean    # remove intermediates
```

`make check` covers unresolved `TODO(author)` markers, bare `\cite` (ambiguous
under natbib author–year), ampersands loose in prose, Markdown bold left in the
source, citations absent from `refs.bib`, and `refs.bib` entries never cited.

No `TODO(author)` markers remain. The AI-use declaration names the assistant
products (Claude Code and Gemini); their model versions and parameters were not
recorded, and the manuscript says so. The second labeller in the consistency audit
(Section 4.3) was a large language model whose identity, parameters and
instruction were not recorded. The manuscript says so in the methods, the threats
to validity and the AI-use declaration, and treats the resulting κ as an
observation: it can be recomputed from the recorded labels, but the labelling
cannot be repeated. AI coding assistance in building the harness, policies and
cases is disclosed in the methods (Section 4.5) and the declarations. Do not fill these in from memory: a
reconstructed disclosure is worse than a stated omission.

## ✅ EMSE format compliance

Checked against Springer's [EMSE submission
guidelines](https://link.springer.com/journal/10664/submission-guidelines):

| Requirement                                            | Status                                            |
| ------------------------------------------------------ | ------------------------------------------------- |
| Abstract 150–250 words                                 | 229 words, structured (Context…Conclusion)        |
| 4–6 keywords                                           | 6                                                 |
| Single-blind review                                    | no anonymisation needed; author details stay      |
| Declarations section before the references            | Funding, Ethical approval, Informed consent, Author Contributions, Data Availability Statement, Conflict of Interest, AI use |
| Affiliation as institution, city, country              | present (London, United Kingdom)                  |
| ORCID                                                  | present (`0009-0003-9709-5842`)                   |
| `svjour3` class files                                  | fetched locally (gitignored), shipped in bundle   |
| Title page with clinical trial number | `make titlepage` ("Clinical trial number: not applicable") |
| Running head                                           | `\titlerunning` and `\authorrunning` set          |
| DOIs as full links in references                       | 43 of 53, rendered as https://doi.org links; the rest are books and standards |
| LaTeX source without subfolders                        | `make dist` emits a flat bundle and fails if not  |
| Data availability statement                            | in Declarations; cites the v3.0.0 DOI             |

The abstract is 229 words. **Re-run `make check` after any edit to it**: the ceiling
is 250, and an added clause can cross it.

## 📦 Submission bundle

```bash
cd paper
make dist     # -> iacsecbench-submission.tar.gz
```

The working tree keeps result tables in `../results/tables/` so the generator owns
them. That path does not survive submission: publishers unpack the source into a
single directory, where `\input{../results/tables/...}` resolves to nothing and the
build fails once per table. `make dist` flattens the tables and figures into
`dist/`, rewrites the table and figure paths in the copy, copies Springer's class
files if present, **compiles the bundle standalone to prove it builds**, and only
then tars it. `dist/` and the tarball are gitignored; they are pure derived output.

The bundle is **flat**. EMSE's guidelines say: "Please do not use subfolders for
your LaTeX submission, e.g. for figures or bibliographic files." Tables and
figures therefore sit beside `iacsecbench.tex`, and `make dist` fails if `dist/`
contains a directory or the flattened source still references a path with a `/`.
The tarball holds sources only (`.tex`, `.bib`, `.bbl`, figure PDFs and any
Springer class files). The `.bbl` is included in case Springer's system does not
run BibTeX. Intermediates and the compiled PDF stay in `dist/`; upload the PDF
separately if the submission system asks for one.

## 🖼️ Figures

Two diagrams are generated, not hand-drawn: `experiments/generate_figures.py`
writes their Mermaid sources from `results/evaluation.json` and
`results/run_manifest.json`, so a figure cannot assert a corpus size or tool
version that disagrees with a table. The third figure, the replication-package
layout, is a `verbatim` listing inside the manuscript rather than a drawing.

Regenerate and re-render after any re-measurement:

```bash
python -m experiments.generate_figures      # refresh figures/*.mmd
# then the mmdc commands in figures/README.md
```

`generate_figures.py --check` exits non-zero if the committed sources no longer
match the recorded results, and runs in CI for that reason. It passes when the only
difference is the pipeline figure's two measured latency labels, because those
describe the measuring host and CI's host is not the one the paper reports; add
`--strict` when re-measuring on that machine.

## ✍️ Conventions worth knowing before editing

- **Numeric table columns are `r`, never `c`.** Each emitter formats a column to a
  fixed number of decimal places, so right alignment lines the decimal points up.
  Centring does not, once a value crosses from one integer digit to two. `siunitx`
  is deliberately absent: the fixed decimal places make it unnecessary, and its
  option names differ between versions 2 and 3.
- **`\citep` and `\citet`, never bare `\cite`.** natbib gives `\cite` different
  meanings in author–year and numeric modes; the explicit forms are unambiguous in
  both. `make check` now flags bare `\cite`, because when the manuscript moved to
  author–year the old check silently passed on every citation.
- **Long file paths use `\path{...}`, not `\texttt{...}`.** A path in `\texttt` is
  one unbreakable token and overflows a one-column measure. `\path` breaks after
  `/` without inserting a hyphen, and needs no `_` escaping. It is **fragile**:
  inside a `\caption` it fails with "`\url` used in a moving argument", so use
  `\texttt` there.
- **Em-dashes are rare and spaced (` --- `).** A previous revision deleted 24 of them
  without restructuring the surrounding sentences, leaving 24 ungrammatical
  sentences including one in the abstract. Prefer commas, parentheses or a sentence
  break; where a dash stays, rewrite the sentence around it rather than delete it.
- **A missing figure prints a visible placeholder box** rather than failing the
  build, so an incomplete figure set cannot pass silently as finished work.
