LAB    = Crypto_RSA
LABPDF = $(LAB).pdf

all: $(LABPDF) clean_aux

$(LABPDF): $(LAB).tex
	pdflatex -shell-escape $(LAB)
	pdflatex -shell-escape $(LAB)
	pdflatex -shell-escape $(LAB)

clean_aux:
	rm -f $(LAB).aux $(LAB).log $(LAB).out $(LAB).fls $(LAB).fdb_latexmk $(LAB).synctex.gz

clean: clean_aux