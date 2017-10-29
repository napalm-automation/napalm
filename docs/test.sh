#!/bin/bash
CWD=`pwd`
TEST_RESULTS_PATH="$CWD/support/tests"

set -e
pip install -r ../requirements/all -r ../requirements/dev

set +e
py.test -c /dev/null --cov=./ -vs --json=report.json ../test*/*/test_getters.py
set -e

cp report.json $TEST_RESULTS_PATH/report.json
