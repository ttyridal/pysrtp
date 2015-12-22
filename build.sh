#!/bin/sh
rm -Rf dist/*.egg dist/*.tar.gz
python setup.py bdist_egg
python3 setup.py bdist_egg
python3 setup.py sdist

