#!/bin/sh

HUSAR_VERSION="$1" docker-compose -f run.yml rm -vf
RET=$?
exit $RET
