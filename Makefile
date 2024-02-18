LAB    = Crypto_RSA
LABPDF = $(LAB).pdf

# If you have .tex files in Code directory that are included in your main document,
# consider listing them here. If not, you can remove the DEPEND variable.
# DEPEND is useful if your LaTeX compilation depends on specific files being present.
# Since you mentioned not using any .tex files for listings, this might not be needed.
# DEPEND  = 

all: $(LABPDF)

$(LABPDF): $(LAB).tex $(DEPEND)
	pdflatex -shell-escape $(LAB)
	bibtex $(LAB)   # Uncomment this line if you have a bibliography
	pdflatex -shell-escape $(LAB)
	pdflatex -shell-escape $(LAB)

clean:
	rm -f *.log *.dvi *.aux *.bbl *.blg *~ *.out *.toc *.lof *.lot *.det
