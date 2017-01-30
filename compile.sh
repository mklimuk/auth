#!/bin/sh

VER=latest
VERSION_FILE=".version"

if [[ ! -z "$1" ]]; then
  VER="$1"
else
  if [[ -e $VERSION_FILE ]]; then
    VER=`cat $VERSION_FILE`
  fi
fi

echo "Compiling with tag: $VER"
echo $VER > .version

HUSAR_VERSION="$VER" docker-compose -f compile.yml run --rm auth_compile
RET=$?
exit $RET
