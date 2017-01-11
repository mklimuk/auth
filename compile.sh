#!/bin/sh

HUSAR_VERSION="$1" docker-compose -f compile.yml run --rm auth_compile
RET=$?
exit $RET
