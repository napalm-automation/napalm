.PHONY: doctest
doctest:
	cd docs && make clean
	cd docs && sphinx-build -W -b html -d _build/doctrees . _build/html
