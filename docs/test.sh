#!/bin/bash
CWD=`pwd`
TEST_RESULTS_PATH="$CWD/support/tests"
REPOBASE=$CWD/..

if [ ! -f "report.json" ]; then
    set -e
    py.test --rootdir $REPOBASE -c /dev/null --cov=./ -vs --json=report.json $REPOBASE/test*/*/test_getters.py

    set -e
    cp report.json $TEST_RESULTS_PATH/report.json
fi
