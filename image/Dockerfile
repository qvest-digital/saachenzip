# © Thorsten Glaser, DTAG LLCTO, Qvest Digital Ⓕ MirBSD

ARG parentimage=unknown
FROM $parentimage
ARG gitdescribe=unknown

MAINTAINER Thorsten Glaser <t.glaser@qvest-digital.com>
LABEL git-describe="$gitdescribe"
LABEL org.opencontainers.image.source=https://github.com/qvest-digital/saachenzip
LABEL org.opencontainers.image.licenses=MirOS

COPY ["saachenzip", "/"]

USER 65534:65534
WORKDIR /
CMD ["/saachenzip", "1024"]
EXPOSE 1024/tcp
EXPOSE 1024/udp
