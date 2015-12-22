#!/bin/bash
set -e

if [ "$#" -lt 1 ]; then
    exec ./$0 discover
fi

default_python_version=`python -V 2>&1`
default_python_minor_version=${default_python_version:9:1}
default_python_version=${default_python_version:7:1}
echo Default python installation is $default_python_version

python -m coverage erase
echo "running python2 with coverage"
python2 -m coverage run -p --omit "/usr/*" -m unittest $*

echo "running python3 with coverage"
python3 -m coverage run -p --omit "/usr/*" -m unittest $*

python -m coverage combine
python -m coverage report
