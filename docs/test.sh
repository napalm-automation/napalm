#!/bin/bash
CWD=`pwd`
BUILDPATH=../
TEST_RESULTS_PATH="$CWD/support/tests"
DRIVER=`/bin/cat ../requirements.txt | grep napalm | grep -v base | awk -F\- '{print $2}'`

set -e
pip install -U napalm-base

function process_driver {
	echo PROCESSING $1
	git clone https://github.com/napalm-automation/napalm-$1.git ../$1
	cd ../$1
	git checkout master
	pip install -r requirements-dev.txt

	set +e
	py.test -c /dev/null --cov=./ -vs --json=report.json test/unit/test_getters.py
	set -e

	cp report.json $TEST_RESULTS_PATH/$1.json
	cd $CWD
}

mkdir -p $TEST_RESULTS_PATH

for driver in $DRIVER; do
	if [ ! -d ../$driver ]; then
		process_driver $driver
	fi;
done
