#!/bin/mksh
# -*- mode: sh -*-
# © Thorsten Glaser, DTAG LLCTO, Qvest Digital Ⓕ MirBSD

export LC_ALL=C TZ=UTC
unset LANGUAGE
set -exo pipefail

docker pull alpine:latest
sleep 1
docker pull alpine:latest
cd "$(dirname "$0")"
rm -rf obj image/saachenzip
[[ ! -h image/saachenzip && ! -e image/saachenzip ]]
git=$(git describe --always --dirty)
mkdir obj
cp src/* obj/
# for apparmour, see https://stackoverflow.com/a/78624998/2171120
docker run --security-opt apparmor=unconfined \
    --rm -v "$PWD/obj:/mnt" \
    alpine:latest sh /mnt/bld.sh
install -c -o "$KSHUID" -g "$KSHGID" -m 0555 \
    obj/saachenzip image/
rm -rf obj
cd image
parent=$(docker import "$PWD/base.tgz")
tag=saachenzip:git-$git
docker build --no-cache \
    --build-arg parentimage="$parent" \
    --build-arg gitdescribe="$git" \
    -t "$tag" .
rm -f saachenzip
docker tag "$tag" saachenzip:latest
: "success; run \"docker system prune -f --volumes\" occasionally (RTFM!)"
