# IaCSecBench manuscript build.
#
# `make` rebuilds the result tables from recorded tool output before typesetting,
# so the PDF cannot silently contain stale numbers. Use `make paper` to typeset
# without re-measuring.

SHELL   := /bin/bash
TEX     := iacsecbench
LATEX   := pdflatex -interaction=nonstopmode -halt-on-error
BIBTEX  := bibtex
TABLES  := ../results/tables

# Engine selection. tectonic resolves packages and runs BibTeX itself, so it
# needs no explicit multi-pass sequence; a TeX Live installation does. Preferring
# whichever is present keeps the build working on machines with either, rather
# than failing on a hardcoded binary that happens to be absent.
HAVE_TECTONIC := $(shell command -v tectonic 2>/dev/null)
HAVE_PDFLATEX := $(shell command -v pdflatex 2>/dev/null)

DIST    := dist

.PHONY: all paper tables clean distclean check dist titlepage

all: tables paper

## Regenerate every table from recorded raw tool output.
tables:
	cd .. && bash experiments/run_baselines.sh

## Typeset only. Fails if a result table is missing.
paper: $(TEX).pdf

# The generated tables are prerequisites, not just inputs. Listing only the .tex
# and .bib let a regenerated table sit on disk while `make paper' reported
# "Nothing to be done" and left the old numbers in the PDF -- the precise drift
# this build is supposed to prevent.
$(TEX).pdf: $(TEX).tex refs.bib $(wildcard $(TABLES)/*.tex) $(wildcard figures/*.pdf)
	@for t in performance rates strictness mcnemar allpairs latency layers corpus external external_agreement; do \
	  test -f $(TABLES)/$$t.tex || { \
	    echo "error: $(TABLES)/$$t.tex missing."; \
	    echo "       Run 'make tables' -- do not hand-write result tables."; \
	    exit 1; }; \
	done
	@# EMSE requires Springer's svjour3, which is not on CTAN and cannot be
	@# fetched by a build. Say so once per build rather than let the author
	@# discover at submission that the PDF was set in the fallback class.
	@test -f svjour3.cls || echo "NOTE: svjour3.cls absent; building in the article fallback. See the header of $(TEX).tex."
ifneq ($(HAVE_TECTONIC),)
	tectonic -X compile --keep-intermediates $(TEX).tex
else ifneq ($(HAVE_PDFLATEX),)
	$(LATEX) $(TEX)
	$(BIBTEX) $(TEX) || true
	$(LATEX) $(TEX)
	$(LATEX) $(TEX)
else
	@echo "error: no LaTeX engine found. Install tectonic (brew install tectonic)"
	@echo "       or a TeX Live distribution providing pdflatex."
	@exit 1
endif
	@echo
	@echo "Built $(TEX).pdf"
	@grep -c 'TODO(author)' $(TEX).tex | xargs -I{} echo "NOTE: {} unresolved TODO(author) markers remain in $(TEX).tex"

## Report anything that would embarrass the submission.
check:
	@echo "== unresolved author TODOs =="
	@grep -n 'TODO(author)' $(TEX).tex || echo "  none"
	@echo
	@# EMSE caps the abstract at 250 words and floors it at 150. The long form of
	@# this abstract ran to 344, so this is a limit the manuscript has already
	@# crossed once; a single added clause crosses it again, and the editorial
	@# office checks it before the paper reaches a reviewer.
	@echo "== abstract length (EMSE: 150-250 words) =="
	@python3 -c 'import re,sys; \
t=open("$(TEX).tex").read(); \
a=re.search(r"\\begin\{abstract\}(.*?)\\end\{abstract\}",t,re.S).group(1); \
a=re.sub(r"(?m)^\s*%.*$$","",a); \
n=len(re.sub(r"\\textbf\{([^}]*)\}",r"\1",a).split()); \
print("  %d words -- %s" % (n, "ok" if 150<=n<=250 else "OUT OF RANGE")); \
sys.exit(0 if 150<=n<=250 else 1)' || echo "  fix the abstract before submitting"
	@echo
	@echo "== ampersands to review (tabular rows are fine; prose is not) =="
	@grep -n '[^\\&]&[^&]' $(TEX).tex | grep -v '\\\\' | grep -v '^\s*[0-9]*:\s*%' || echo "  none found"
	@echo
	@echo "== Markdown bold left in source =="
	@grep -n '\*\*' $(TEX).tex || echo "  none"
	@echo
	@echo "== bare \\cite (ambiguous under natbib author-year; use \\citep/\\citet) =="
	@grep -n '\\cite{' $(TEX).tex || echo "  none"
	@echo
	@echo "== citations in .tex absent from refs.bib =="
	@# Matches \citep, \citet, \citeauthor and bare \cite. Matching only `\cite{'
	@# made this check pass silently the moment the manuscript moved to author-year
	@# citations, which is the failure mode a check like this exists to prevent.
	@for k in $$(grep -oE '\\cite[a-z]*\{[^}]*\}' $(TEX).tex | sed 's/\\cite[a-z]*{//;s/}//' | tr ',' '\n' | tr -d ' ' | sort -u); do \
	  grep -q "{$$k," refs.bib || echo "  MISSING: $$k"; done; echo "  (blank means all resolve)"
	@echo
	@echo "== refs.bib entries never cited =="
	@for k in $$(grep -o '^@[a-z]*{[^,]*' refs.bib | sed 's/^@[a-z]*{//'); do \
	  grep -q "$$k" $(TEX).tex || echo "  UNCITED: $$k"; done; echo "  (uncited entries are citation padding; remove them)"

## Refuse to assemble a submission bundle that still carries author placeholders.
##
## `check' reports them and `paper' prints a NOTE, but both exit 0, so neither
## stops anything: the placeholders render as visible bold [TODO(author): ...]
## boxes in the PDF body and would have travelled to the editorial office intact.
.PHONY: nodraft
nodraft:
	@fail=0; \
	if grep -q 'TODO(author)' $(TEX).tex; then \
	  echo "error: unresolved TODO(author) markers in $(TEX).tex:"; \
	  grep -n 'TODO(author)' $(TEX).tex | sed 's/^/       /'; \
	  fail=1; fi; \
	test $$fail -eq 0 || { \
	  echo; \
	  echo "       Supply the values, or run 'make dist FORCE_DRAFT=1' for a draft bundle."; \
	  test -n "$(FORCE_DRAFT)"; }

## Build a self-contained submission bundle.
##
## The working tree keeps the result tables in ../results/tables/ so that the
## generator owns them and the manuscript cannot drift from the measurements. That
## layout does not survive submission: Springer unpacks the source into one
## directory, where `\input{../results/tables/...}` resolves to nothing and the
## build dies once per table. EMSE also forbids subfolders outright ("Please do
## not use subfolders for your LaTeX submission, e.g. for figures or
## bibliographic files"), so the bundle is flat: tables and figures sit beside the
## manuscript, and flatten_for_submission.py rewrites both kinds of reference in a
## copy. The manuscript source is not edited.
##
## Only source files go into the tarball. The .bbl travels with them because
## Springer's system may not run BibTeX; .aux, .log, .out and the compiled PDF
## are build output and stay in $(DIST)/ for inspection.
BUNDLE_GLOBS := *.tex *.bib *.bbl *.cls *.clo *.bst *.pdf *.eps
dist: nodraft $(TEX).pdf
	rm -rf $(DIST)
	mkdir -p $(DIST)
	cp $(TEX).tex refs.bib $(DIST)/
	@# A table sharing a name with the manuscript would overwrite it in a flat
	@# directory. Refuse rather than ship a bundle with the wrong main file.
	@test ! -e $(TABLES)/$(TEX).tex || { echo "error: a table is named $(TEX).tex"; exit 1; }
	@# Only the tables the manuscript includes. results/tables/ also holds tables
	@# for analyses the paper does not report, which a reviewer unpacking the
	@# bundle would otherwise find and look for in vain.
	for t in $$(grep -o '\\resulttable{[^}]*}' $(TEX).tex | sed 's/.*{//;s/}//' | sort -u); do \
	  cp $(TABLES)/$$t.tex $(DIST)/ || exit 1; done
	@# Only the rendered figures, and only those that exist: figures/ also holds the
	@# .mmd sources, the mermaid config, and superseded/, none of which belong in a
	@# submission. A missing figure must not fail the bundle either, because
	@# \paperfigure degrades to a visible placeholder box that the check below
	@# reports. `find -exec' rather than a glob, so an empty match is not an error.
	@find figures -maxdepth 1 -type f \( -name '*.pdf' -o -name '*.eps' \) \
	  -exec cp {} $(DIST)/ \;
	@# Springer's class, .clo and .bst if the author has fetched them. EMSE wants
	@# the source to build as submitted, and svjour3 is not in any TeX
	@# distribution, so the bundle has to carry it. `find -exec' rather than a
	@# glob, so an absent file is not an error.
	@find . -maxdepth 1 -type f \( -name 'svjour3.cls' -o -name 'svglov3.clo' \
	  -o -name 'spbasic.bst' \) -exec cp {} $(DIST)/ \;
	@# Redirect \resulttable at the flattened copies. Delegated to a script because
	@# the replacement text is backslashes, braces and a `#' parameter marker, each
	@# of which make or the shell would consume first.
	@python3 flatten_for_submission.py $(DIST)/$(TEX).tex
	@# The bundle must build on its own, with no parent directory present.
	@command -v tectonic >/dev/null 2>&1 || command -v pdflatex >/dev/null 2>&1 || { \
	  echo "warning: no LaTeX engine; bundle assembled but NOT verified."; exit 0; }
	@echo "verifying the bundle builds standalone..."
	@cd $(DIST) && { \
	  if command -v tectonic >/dev/null 2>&1; then \
	    tectonic -X compile --keep-intermediates $(TEX).tex >/dev/null; \
	  else \
	    $(LATEX) $(TEX) >/dev/null && $(BIBTEX) $(TEX) >/dev/null 2>&1; \
	    $(LATEX) $(TEX) >/dev/null && $(LATEX) $(TEX) >/dev/null; \
	  fi; }
	@grep -l 'figure not yet produced' $(DIST)/$(TEX).log >/dev/null 2>&1 && \
	  echo "NOTE: bundle contains figure placeholders; regenerate figures/ first." || true
	@# EMSE rejects subfolders, and the rewrite above is only as good as its
	@# pattern: check both the layout and the text before packing.
	@test -z "$$(find $(DIST) -mindepth 1 -type d)" || { \
	  echo "error: $(DIST)/ contains subfolders; EMSE requires a flat submission."; exit 1; }
	@! grep -nE '\\(paperfigure|includegraphics|input)(\[[^]]*\])?\{[^}]*/' $(DIST)/$(TEX).tex \
	  || { echo "error: $(DIST)/$(TEX).tex still references a subfolder (above)."; exit 1; }
	@# The bundle's own PDF is the compiled manuscript, not a figure; keep it out.
	cd $(DIST) && tar -czf ../$(TEX)-submission.tar.gz \
	  $$(ls $(BUNDLE_GLOBS) 2>/dev/null | grep -vx '$(TEX).pdf')
	@echo "Bundle contents:"; tar -tzf $(TEX)-submission.tar.gz | sed 's/^/  /'
	@echo
	@echo "Built $(TEX)-submission.tar.gz from $(DIST)/"
	@echo "Check the PDF in $(DIST)/ before uploading."

## Separate title page for Editorial Manager, written to $(DIST)/.
titlepage: title_page.tex
	mkdir -p $(DIST)
ifneq ($(HAVE_TECTONIC),)
	tectonic -X compile --outdir $(DIST) title_page.tex
else
	$(LATEX) -output-directory=$(DIST) title_page.tex
endif
	mv $(DIST)/title_page.pdf $(DIST)/$(TEX)-title-page.pdf
	@echo "Built $(DIST)/$(TEX)-title-page.pdf"

clean:
	rm -f $(TEX).aux $(TEX).log $(TEX).bbl $(TEX).blg $(TEX).out $(TEX).toc

distclean: clean
	rm -rf $(TEX).pdf $(DIST) $(TEX)-submission.tar.gz
