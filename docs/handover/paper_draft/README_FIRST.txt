IoT DEFENSE PAPER (v2) - status
================================

STATUS (2026-10-26): paper.tex COMPILED (Tectonic on the VM) -> paper.pdf.
  Layout: 6 pages of content; the reference list runs about 1/5 of the way onto page 7.
  Two-column IEEEtran conference format, Times text with bold and italics.
  paper_v1_PREVIOUS_build.pdf and paper_old_9page_draft.pdf are older drafts and do NOT match paper.tex.

TO BUILD
  Overleaf: upload IoT_Defense_Paper_source.zip, compiler pdfLaTeX, main file paper.tex, recompile twice.
  VM:       copy paper.tex refs.bib figs/ to ~/paper_build7, then  cd ~/paper_build7 && ~/bin/tectonic paper.tex
  NOTE: paper.tex loads \usepackage[T1]{fontenc}. Without it Tectonic (XeTeX) silently falls back to Latin Modern
  and loses all bold and italic text.

SPACE: to get references onto page 6 as well, either drop 4-5 references or cut ~20 lines of body text.
  Easy cuts: the "Noisy detector and reactive attacker" paragraph, the "cost of the longer window" paragraph.

CHANGES FROM v1 (after studying the camera-ready reference paper and auditing our own claims)
  Added: Statistical treatment, Setup, Cost and scalability, Limitations and Future work as separate paragraphs,
  numbered key findings, AI-use disclosure, significance table (Table II), three-limitations related-work close,
  reference list 13 -> 22.
  Corrected: abstract no longer says learning "pays only where measurements exist" (PPO and Stackelberg tie);
  the 16/16 naming result is labelled a development-set result; the public-data table uses one 60 s configuration;
  "false actions/hour" became "sustained alarms/hour (upper bound)"; disclosed that priors were committed together
  with the measured evaluation, IoT-23 captures were chosen for size, and table-graded regret reuses the repetitions
  that define the best response.

BEFORE YOU SUBMIT (red text in the PDF marks every placeholder)
  1. Co-authors, guide, emails. Abdullah's email [email] follows the pattern of the reference paper's
     addresses; confirm it.
  2. Acknowledgment: the AI-use statement must be TRUE for you. Claude drafted the text and wrote and ran the
     evaluation code; you must have reviewed the results and text.
  3. Availability: repository URL and data licence.
  4. VERIFY EVERY REFERENCE (volume, pages, year) against the publisher page. Written from memory.
  5. Check the venue's page limit and template.
