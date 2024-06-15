# -*- mode: sh -*-
# © Thorsten Glaser, Qvest Digital Ⓕ MirBSD

set -ex
cd "$(dirname "$0")"
: install build dependencies
apk add alpine-sdk
apk add linux-headers
: compile
gcc -D_GNU_SOURCE \
    -Wdate-time -D_FORTIFY_SOURCE=2 \
    -g -O2 -Wall -Wextra -Wformat -Werror=format-security \
    -Werror=implicit-function-declaration \
    -fstack-protector-strong -fstack-clash-protection -fcf-protection \
    -Wl,-z,relro -Wl,-z,now -Wl,-z,text -fPIE -static-pie \
    -o saachenzip saachenzip.c
: ok
