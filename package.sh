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

echo "Packaging with tag: $VER"
echo $VER > .version

docker build -t "docker.agilesoftware.ninja/mklimuk/auth:$VER" .
