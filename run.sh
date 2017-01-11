#!/bin/sh

HUSAR_VERSION="$1" docker-compose -f run.yml up -d
RET=$?
exit $RET
