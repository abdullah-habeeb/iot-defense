# Paper

`paper.tex` / `references.bib` build to `paper.pdf`, a 6-page IEEE-conference-format writeup of
this project's evaluation (see `../EVALUATION.md`, which this paper condenses and cites the same
real numbers from).

No `texlive` is installed on this VM (outside the project's scoped passwordless sudo). Instead,
`~/bin/tectonic` -- a self-contained LaTeX engine that fetches the packages it needs over the
network on first use, no `apt install` required -- was downloaded from
<https://github.com/tectonic-typesetting/tectonic/releases> (the `x86_64-unknown-linux-musl`
static build; the `-gnu` build needs `libgraphite2` which is not installed here).

Rebuild after editing `paper.tex`:

```bash
~/bin/tectonic paper.tex
```

`paper.pdf` is committed alongside the source so the paper is viewable without needing tectonic
installed.
