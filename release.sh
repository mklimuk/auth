#!/bin/sh

VERSION_FILE=".version"
if [[ ! -e $VERSION_FILE ]]; then
  echo "Version file does not exist. Release aborted."
  exit 1
fi

VER=`cat $VERSION_FILE`

if [[ -z "$VER" ]]; then
  echo "Empty version file. Release aborted."
  exit 2
fi

echo "Releasing version: $VER"

docker push "docker.agilesoftware.ninja/mklimuk/auth:$VER"
