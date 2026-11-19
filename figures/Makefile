all: architecture.png architecture.svg
%.pdf: %.tex
	pdflatex -interaction=batchmode -halt-on-error $< >/dev/null
%.png: %.pdf
	pdftocairo -png -r 200 -singlefile $< $*
%.svg: %.pdf
	pdftocairo -svg $< $@
clean:
	rm -f *.aux *.log *.pdf
.PHONY: all clean
