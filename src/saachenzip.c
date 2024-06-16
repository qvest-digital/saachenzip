static const char licence_header[] __attribute__((__used__)) =
    "@(#) https://github.com/qvest-digital/saachenzip"
	/* Ⓕ MirBSD (The MirOS Licence) */
    "\n	/*-"
    "\n	 * Copyright © 2024"
    "\n	 *	Thorsten Glaser <t.glaser@qvest-digital.com>"
    "\n	 * Copyright © 2020, 2021"
    "\n	 *	Thorsten Glaser, for Deutsche Telekom LLCTO"
    "\n	 * Copyright © 2006"
    "\n	 *	Thorsten Glaser inspired by material provided by"
    "\n	 *	the Regents of the University of California"
    "\n	 * Licensor: Qvest Digital AG, Bonn, Germany"
    "\n	 *"
    "\n	 * Provided that these terms and disclaimer and all copyright notices"
    "\n	 * are retained or reproduced in an accompanying document, permission"
    "\n	 * is granted to deal in this work without restriction, including un‐"
    "\n	 * limited rights to use, publicly perform, distribute, sell, modify,"
    "\n	 * merge, give away, or sublicence."
    "\n	 *"
    "\n	 * This work is provided “AS IS” and WITHOUT WARRANTY of any kind, to"
    "\n	 * the utmost extent permitted by applicable law, neither express nor"
    "\n	 * implied; without malicious intent or gross negligence. In no event"
    "\n	 * may a licensor, author or contributor be held liable for indirect,"
    "\n	 * direct, other damage, loss, or other issues arising in any way out"
    "\n	 * of dealing in the work, even if advised of the possibility of such"
    "\n	 * damage or existence of a defect, except proven that it results out"
    "\n	 * of said person’s immediate fault when using the work as intended."
    "\n	 */"
    "\n";

#include <sys/types.h>
/* in musl, the following does not include the former ☹ */
#include <sys/param.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include "mbsdcc.h"
#include "mbsdint.h"

static const char other_ids[] __attribute__((__used__)) =
    "\n	@(#) " SYSKERN_MBSDCC_H
    "\n	@(#) " SYSKERN_MBSDINT_H
    "\n";

#ifndef HAVE_NI_WITHSCOPEID
#ifdef NI_WITHSCOPEID
#define HAVE_NI_WITHSCOPEID 1
#else
#define HAVE_NI_WITHSCOPEID 0
#endif
#endif

#if HAVE_NI_WITHSCOPEID
/* might cause trouble on old Solaris; undefine it then */
#define NIF_ADDR NI_NUMERICHOST | NI_NUMERICSERV | NI_WITHSCOPEID
#define NIF_FQDN NI_NAMEREQD | NI_NUMERICSERV | NI_WITHSCOPEID
#else
#define NIF_ADDR NI_NUMERICHOST | NI_NUMERICSERV
#define NIF_FQDN NI_NAMEREQD | NI_NUMERICSERV
#endif

#ifdef SO_REUSEPORT
#define ECNBITS_REUSEPORT SO_REUSEPORT
#else
#define ECNBITS_REUSEPORT SO_REUSEADDR
#endif

struct configuration {
#define fdsetp (confp->fdsetp_m)
	fd_set *fdsetp_m;
#define fdcurp (confp->fdcurp_m)
	fd_set *fdcurp_m;
#define fdnby (confp->fdnby_m)
	size_t fdnby_m;
#define maxfd (confp->maxfd_m)
	int maxfd_m;
};

static void sighandler(int);
static void doconf(struct configuration *, char **, int);
static const char *revlookup(const struct sockaddr *, socklen_t);
static void handle_fd(int);

static const char protoname[2][4] = { "udp", "tcp" };

static volatile sig_atomic_t gotsig;

#define cscpy(dst,src) memcpy(dst, src, sizeof(src))

static void
sighandler(int signo __attribute__((__unused__)))
{
	gotsig = 1;
}

int
main(int argc, char *argv[])
{
	int i, n;
#define confp (&confd)
	struct configuration confd;

	doconf(confp, argv, argc);
	putc('\n', stderr);
	fflush(NULL);
 loop:
	memcpy(fdcurp, fdsetp, fdnby);
	n = select(maxfd + 1, fdcurp, NULL, NULL, NULL);
	if (gotsig)
		goto out;
	switch (n) {
	case -1:
		if (errno != EINTR)
			err(1, "select");
		/* FALLTHROUGH */
	case 0:
		goto loop;
	}
	i = -1;
	while ((n > 0) && (++i < maxfd))
		if (FD_ISSET(i, fdcurp)) {
			--n;
			handle_fd(i);
			if (gotsig)
				goto out;
		}
	goto loop;
 out:
	fprintf(stderr, "Terminating\n");
	return (0);
#undef confp
}

static const unsigned char v4mapped[12] = {
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xFF, 0xFF,
};

static const unsigned char nat64[12] = {
	0x00, 0x64, 0xFF, 0x9B,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
};

static const unsigned char nat64nsp[6] = {
	0x00, 0x64, 0xFF, 0x9B,
	0x00, 0x01,
};

/* over-estimate decimal as octal */
#define LKmax(a,b) ((a) > (b) ? (a) : (b))
#define LKFAMILYLEN (LKmax(\
	    ((mbiMASK__BITS(INT_MAX) + 2) / 3 + /* minus */ 1), \
	    ((mbiMASK__BITS(UINT_MAX) + 2) / 3)) + /* NUL */ 1)

static int
dolookup(char host[static INET6_ADDRSTRLEN],
    char port[static /* 0‥65535 + NUL */ 6],
    char family[static LKFAMILYLEN],
    const struct sockaddr *addr, socklen_t addrlen)
{
	int i;

	i = getnameinfo(addr, addrlen, host, INET6_ADDRSTRLEN, port, 6, NIF_ADDR);
	switch (i) {
	case EAI_SYSTEM:
		warn("getnameinfo");
		if (0)
			/* FALLTHROUGH */
	default:
		  warnx("%s: %s", "getnameinfo", gai_strerror(i));
		cscpy(host, "(unknown)");
		cscpy(port, "(?""?""?)");
		break;
	case 0:
		break;
	}
	if (addr->sa_family == AF_INET) {
		cscpy(family, "IPv4");
#ifdef AF_INET6
#define isNet(net) \
	(!memcmp(net, \
	    ((const struct sockaddr_in6 *)addr)->sin6_addr.s6_addr, \
	    sizeof(net)))
	} else if (addr->sa_family == AF_INET6) {
		cscpy(family, "IPv6");
		if (isNet(nat64) || isNet(nat64nsp) ||
		    isNet(v4mapped))
			cscpy(family, "IPv4");
#undef isNet
#endif
	} else if (mbiTYPE_ISU(sa_family_t)) {
		snprintf(family, LKFAMILYLEN, "%u", (unsigned)addr->sa_family);
	} else {
		snprintf(family, LKFAMILYLEN, "%d", (int)addr->sa_family);
	}
	return (i);
}

static const char *
revlookup(const struct sockaddr *addr, socklen_t addrlen)
{
	static char buf[INET6_ADDRSTRLEN + 9];
	char nh[INET6_ADDRSTRLEN];
	char np[/* 0‥65535 + NUL */ 6];
	char nf[LKFAMILYLEN];

	if (dolookup(nh, np, nf, addr, addrlen))
		cscpy(buf, "(unknown)");
	else
		snprintf(buf, sizeof(buf), "[%s]:%s", nh, np);
	return (buf);
}

static void
doconf(struct configuration *confp, char **argv, int argc)
{
	int i, j, s;
	unsigned char pmask;
	char *cp, *host, *service;
	struct addrinfo *ai, *ap, ar;
	struct sigaction sa = {0};

	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &sighandler;
	if (sigaction(SIGTERM, &sa, NULL))
		warn("sigaction: %s", "SIGTERM");
	if (sigaction(SIGINT, &sa, NULL))
		warn("sigaction: %s", "SIGINT");

	fdsetp = NULL;
	maxfd = 0;
	fdnby = 0;

	if (argc < 2)
		errx(1, "Usage: %s [<host>/]<port> […]",
		    argc > 0 && *argv && **argv ? *argv : "saachenzip");

	j = 0;
	while (++j < argc) {
		if (!(cp = strdup(argv[j])))
			err(1, "strdup");
		if (!(service = strrchr(cp, '/'))) {
			host = NULL;
			service = cp;
		} else {
			host = cp;
			*service++ = '\0';
			if (!*host)
				errx(1, "missing %s: %s", "host", argv[j]);
		}
		if (!*service)
			errx(1, "missing %s: %s", "port", argv[j]);

		pmask = 0;
 try_protos:
		if ((pmask & 3) == 3) {
			if (!(pmask & 0x30))
				errx(1, "no protocol for %s", argv[j]);
			free(cp);
			continue;
		}
		memset(&ar, '\0', sizeof(struct addrinfo));
		ar.ai_family = AF_UNSPEC;
		if (!(pmask & 1)) {
			pmask |= 1;
			ar.ai_socktype = SOCK_STREAM;
		} else {
			pmask |= 2;
			ar.ai_socktype = SOCK_DGRAM;
		}
		ar.ai_flags = AI_ADDRCONFIG | AI_PASSIVE; /* no AI_V4MAPPED either */
		i = getaddrinfo(host, service, &ar, &ai);
		switch (i) {
		case EAI_NONAME:
#ifdef EAI_PROTOCOL
		case EAI_PROTOCOL:
#endif
		case EAI_SERVICE:
		case EAI_SOCKTYPE:
			warnx("%s: %s: %s", "getaddrinfo", argv[j],
			    gai_strerror(i));
			goto try_protos;
		case EAI_SYSTEM:
			err(1, "getaddrinfo");
		default:
			errx(1, "%s: %s: %s", "getaddrinfo", argv[j],
			    gai_strerror(i));
		case 0:
			break;
		}

		for (ap = ai; ap != NULL; ap = ap->ai_next) {
			size_t z;

			fprintf(stderr, "Listening on %s/%s...",
			    revlookup(ap->ai_addr, ap->ai_addrlen),
			    protoname[!(pmask & 2)]);

			if ((s = socket(ap->ai_family, ap->ai_socktype,
			    ap->ai_protocol)) == -1) {
				i = errno;
				putc('\n', stderr);
				errno = i;
				warn("socket");
				continue;
			}
			fprintf(stderr, " fd %d...", s);

			i = 1;
			if (setsockopt(s, SOL_SOCKET, ECNBITS_REUSEPORT,
			    (const void *)&i, sizeof(i))) {
				i = errno;
				putc('\n', stderr);
				errno = i;
				warn("setsockopt");
			}

			if (bind(s, ap->ai_addr, ap->ai_addrlen)) {
				i = errno;
				putc('\n', stderr);
				errno = i;
				warn("bind");
				close(s);
				continue;
			}

			if (!(pmask & 2) && listen(s, 100)) {
				i = errno;
				putc('\n', stderr);
				errno = i;
				warn("listen");
				close(s);
				continue;
			}

			z = howmany(s + 1, NFDBITS) * sizeof(fd_mask);
			if (z > fdnby) {
				char *newp;

				z += z / 2;
				if (!(newp = realloc(fdsetp, z)))
					err(1, "realloc");
				memset(newp + fdnby, '\0', z - fdnby);
				fdsetp = (void *)newp;
				fdnby = z;
			}

			FD_SET(s, fdsetp);
			if (s > maxfd)
				maxfd = s;
			pmask |= (pmask & 2) ? 0x20 : 0x10;
			fprintf(stderr, " ok\n");
		}
		freeaddrinfo(ai);
		goto try_protos;
	}

	if (!(fdcurp = malloc(fdnby)))
		err(1, "malloc");
}

static void
handle_fd(int fd)
{
	static char buf[1024];
	int i;
	unsigned char istcp;
	socklen_t saclen, saslen;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
		struct sockaddr_storage ss;
	} saclient, saserver;
	ssize_t z;
	struct timeval tv;
	char shost[INET6_ADDRSTRLEN], chost[INET6_ADDRSTRLEN];
	char sport[6], cport[6];
	char sfamily[LKFAMILYLEN], cfamily[LKFAMILYLEN];

	saclen = sizeof(i);
	errno = EILSEQ;
	if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &i, &saclen) ||
	    saclen != sizeof(i)) {
		warn("getsockopt(%d, %s)", fd, "SO_TYPE");
		return;
	}
	switch (i) {
	case SOCK_STREAM:
		istcp = 1;
		saclen = sizeof(saclient);
		if ((i = accept(fd, &saclient.sa, &saclen)) == -1) {
			warn("accept(%d)", fd);
			return;
		}
		saslen = sizeof(saserver);
		if (getsockname(i, &saserver.sa, &saslen)) {
			warn("getsockname(%d)", fd);
			close(i);
			return;
		}
		if (read(i, buf, sizeof(buf)) < 0)
			warn("read(%d)", fd);
		fd = i;
		break;
	case SOCK_DGRAM:
		istcp = 0;
		saslen = sizeof(saserver);
		if (getsockname(fd, &saserver.sa, &saslen)) {
			warn("getsockname(%d)", fd);
			return;
		}
		saclen = sizeof(saclient);
		if (recvfrom(fd, buf, sizeof(buf), 0, &saclient.sa, &saclen) < 0) {
			warn("recvfrom(%d)", fd);
			return;
		}
		break;
	default:
		warnx("fd %d: unknown socket type: %d", fd, i);
		return;
	}
	dolookup(chost, cport, cfamily, &saclient.sa, saclen);
	fprintf(stderr, "Request from [%s]:%s/%s/%s\n",
	    chost, cport, cfamily, protoname[istcp]);
	dolookup(shost, sport, sfamily, &saserver.sa, saslen);
	if (gettimeofday(&tv, NULL)) {
		warn("gettimeofday");
		tv.tv_sec = -1;
		tv.tv_usec = 0;
	}
	errno = ETXTBSY;
	i = snprintf(buf, sizeof(buf),
	    "{\n  \"client-l3\": \"%s\""
	    ",\n  \"client-l4\": \"%s\""
	    ",\n  \"client-host\": \"%s\""
	    ",\n  \"client-port\": \"%s\""
	    ",\n  \"server-l3\": \"%s\""
	    ",\n  \"server-l4\": \"%s\""
	    ",\n  \"server-host\": \"%s\""
	    ",\n  \"server-port\": \"%s\""
	    ",\n  \"timestamp\": %lld.%06ld"
	     "\n}\n",
	    cfamily, protoname[istcp], chost, cport,
	    sfamily, protoname[istcp], shost, sport,
	    (long long)tv.tv_sec, (long)tv.tv_usec);
	if (i < 1) {
		warn("snprintf%s", ", no reply sent");
		goto out;
	}
	if ((size_t)i >= sizeof(buf))
		warnx("snprintf%s", " truncated");
	z = istcp ? write(fd, buf, (size_t)i) :
	    sendto(fd, buf, (size_t)i, 0, &saclient.sa, saclen);
	if (z == -1)
		warn("%s: %d bytes", istcp ? "write" : "sendto", i);
	else if (z != i)
		warnx("short %s", istcp ? "write" : "sendto");
 out:
	if (istcp)
		close(fd);
}
