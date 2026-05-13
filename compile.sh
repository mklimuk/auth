#!/bin/sh

# get script's location path
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR > /dev/null

go build -o "$(pwd)/dist/generator" -v "./app/generator"

popd $DIR > /dev/null
