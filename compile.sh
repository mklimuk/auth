#!/bin/sh

NORM=`tput sgr0`
BOLD=`tput bold`
REV=`tput smso`
FG_GREEN="$(tput setaf 2)"
FG_RED="$(tput setaf 1)"

# get script's location path
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
pushd $DIR > /dev/null

VER=latest
VERSION_FILE=".version"

[ -z "$BUILDTIME" ] && BUILDTIME=$(TZ=GMT date "+%Y-%m-%d_%H:%M_GMT")
[ -z "$GITCOMMIT" ] && GITCOMMIT=$(git rev-parse --short HEAD 2>/dev/null)
[ -z "$GITBRANCH" ] && GITBRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)

if [[ ! -z "$1" ]]; then
  VER="$1"
  echo $VER > $VERSION_FILE
else
  if [[ -e $VERSION_FILE ]]; then
    VER=`cat $VERSION_FILE`
  fi
fi

if [[ ! -d "$DIR/dist/local" ]]; then
  mkdir -p "$DIR/dist/local"
fi

if [[ ! -d "$DIR/dist/x64" ]]; then
  mkdir -p "$DIR/dist/x64"
fi

echo "version info:"
echo "version: ${FG_GREEN}$VER${NORM}"
echo "git commit: ${FG_GREEN}$GITCOMMIT${NORM}"
echo "git branch: ${FG_GREEN}$GITBRANCH${NORM}"
echo "build time: ${FG_GREEN}$BUILDTIME${NORM}"

VERSION=$VER GITCOMMIT=$GITCOMMIT GITBRANCH=$GITBRANCH BUILDTIME=$BUILDTIME docker-compose -f compile.yml up
RET=$?

CGO_ENABLED=0 go build -ldflags '-s -w -X github.com/mklimuk/auth/config.Version=$VERSION -X github.com/mklimuk/auth/config.GitCommit=$GITCOMMIT -X github.com/mklimuk/auth/config.GitBranch=$GITBRANCH -X github.com/mklimuk/auth/config.BuildTime=$BUILDTIME' -o $DIR/dist/local/auth-cli -v github.com/mklimuk/auth/app/cli

popd > /dev/null

exit $RET
