#!/bin/bash
CWD=`pwd`
TEST_RESULTS_PATH="$CWD/support/tests"

if [ ! -f "report.json" ]; then
    set -e
    pip install -r ../requirements.txt -r ../requirements-dev.txt

    set +e
    py.test -c /dev/null --cov=./ -vs --json=report.json ../test*/*/test_getters.py
    set -e

    cp report.json $TEST_RESULTS_PATH/report.json
fi
