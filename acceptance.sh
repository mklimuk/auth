#!/bin/bash

TEST_FOLDER="acceptance"
#script location
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR > /dev/null

cd $TEST_FOLDER
go test $1 run_test.go context.go
RET=$?
exit $RET

# return to the original folder
popd > /dev/null
