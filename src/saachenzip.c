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
#include <sys/uio.h>
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
#include <time.h>
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

#ifdef AI_ADDRCONFIG
#define AIxADDRCONFIG AI_ADDRCONFIG
#else
#define AIxADDRCONFIG 0
#endif

#ifdef SO_REUSEPORT
#define ECNBITS_REUSEPORT SO_REUSEPORT
#define ECNBITSnREUSEPORT "SO_REUSEPORT"
#else
#define ECNBITS_REUSEPORT SO_REUSEADDR
#define ECNBITSnREUSEPORT "SO_REUSEADDR"
#endif

#if defined(IP_RECVPKTINFO)
#define pkti4_recv IP_RECVPKTINFO
#define pkti4nrecv "IP_RECVPKTINFO"
#elif defined(IP_PKTINFO)
#define pkti4_recv IP_PKTINFO
#define pkti4nrecv "IP_PKTINFO"
#elif defined(IP_RECVDSTADDR)
#define pkti4_recv IP_RECVDSTADDR
#define pkti4nrecv "IP_RECVDSTADDR"
#endif

#if defined(AF_INET6) && defined(IPPROTO_IPV6)
#if defined(IPV6_RECVPKTINFO)
#define pkti6_recv IPV6_RECVPKTINFO
#define pkti6nrecv "IPV6_RECVPKTINFO"
#elif defined(IPV6_PKTINFO)
#define pkti6_recv IPV6_PKTINFO
#define pkti6nrecv "IPV6_PKTINFO"
#endif
#endif

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 64
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

union sockun {
	struct sockaddr sa;
	struct sockaddr_in sin;
#ifdef AF_INET6
	struct sockaddr_in6 sin6;
#endif
	struct sockaddr_storage ss;
};

static void sighandler(int);
static void doconf(struct configuration *, char **, int);
static const char *revlookup(const struct sockaddr *, socklen_t);
static void handle_fd(int);
static int recvudp(int, void *, size_t, union sockun *, socklen_t *,
    union sockun *, socklen_t *);

static const char protoname[2][4] = { "udp", "tcp" };

static volatile sig_atomic_t gotsig;
static unsigned char fauxhttp;
static char specdstbuf[40];

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

#ifdef AF_INET6
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
#endif

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
	struct sigaction sa;

	memset(&sa, '\0', sizeof(sa));
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = &sighandler;
	if (sigaction(SIGTERM, &sa, NULL))
		warn("sigaction: %s", "SIGTERM");
	if (sigaction(SIGINT, &sa, NULL))
		warn("sigaction: %s", "SIGINT");

	fdsetp = NULL;
	maxfd = 0;
	fdnby = 0;

	if (argc < 2 || (argc < 3 && argv[1][0] == 'H' && !argv[1][1]))
		errx(1, "Usage: %s [H] [<host>/]<port> […]",
		    argc > 0 && *argv && **argv ? *argv : "saachenzip");

	j = 0;
	if (argv[1][0] == 'H' && !argv[1][1]) {
		++j;
		fauxhttp = 1;
	}
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
		ar.ai_flags = AIxADDRCONFIG | AI_PASSIVE; /* no AI_V4MAPPED either */
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
				warn("setsockopt %s", ECNBITSnREUSEPORT);
			}

#if defined(pkti4_recv) || defined(pkti6_recv)
			if ((pmask & 2)) {
				i = 1;
				switch (ap->ai_family) {
#ifdef pkti6_recv
				case AF_INET6:
					if (setsockopt(s, IPPROTO_IPV6,
					    pkti6_recv,
					    (const void *)&i, sizeof(i))) {
						i = errno;
						putc('\n', stderr);
						errno = i;
						warn("setsockopt %s",
						    pkti6nrecv);
					}
					break;
#endif
#ifdef pkti4_recv
				case AF_INET:
					if (setsockopt(s, IPPROTO_IP,
					    pkti4_recv,
					    (const void *)&i, sizeof(i))) {
						i = errno;
						putc('\n', stderr);
						errno = i;
						warn("setsockopt %s",
						    pkti4nrecv);
					}
					break;
#endif
				}
			}
#endif

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
	static char hdrbuf[160];
	static char tmbuf[32];
	int i;
	unsigned char istcp;
	socklen_t saclen, saslen;
	union sockun saclient, saserver;
	ssize_t z;
	struct timeval tv;
	char shost[INET6_ADDRSTRLEN], chost[INET6_ADDRSTRLEN];
	char sport[6], cport[6];
	char sfamily[LKFAMILYLEN], cfamily[LKFAMILYLEN];

	hdrbuf[0] = '\0';
	specdstbuf[0] = '\0';

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
		if (recvudp(fd, buf, sizeof(buf), &saclient, &saclen,
		    &saserver, &saslen))
			return;
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
	if (fauxhttp) {
		struct tm *tm;

		/* avoid strftime to avoid timezone dependency */
		errno = ETXTBSY;
		if ((tm = gmtime(&tv.tv_sec))) {
			/* RFC-mandated exact strings and UTC */
			static const char xday[8][4] = {
				"Sun", "Mon", "Tue", "Wed",
				"Thu", "Fri", "Sat", "Sun",
			};
			static const char xmonth[12][4] = {
				"Jan", "Feb", "Mar", "Apr",
				"May", "Jun", "Jul", "Aug",
				"Sep", "Oct", "Nov", "Dec",
			};
			if (tm->tm_mon < 0 || tm->tm_mon > 11 ||
			    tm->tm_wday < 0 || tm->tm_wday > 7 ||
			    /* HTTP-mandated limits */
			    tm->tm_year < -1899 || tm->tm_year > 8099) {
				warnx("out-of-spec struct tm");
				goto fallbacktime;
			}
			if (tm->tm_sec > 59)
				tm->tm_sec = 59; /* wrong but HTTP-mandated */
			errno = ETXTBSY;
			i = snprintf(tmbuf, sizeof(tmbuf),
			    "%s, %02d %s %04d %02d:%02d:%02d GMT",
			    xday[tm->tm_wday], tm->tm_mday,
			    xmonth[tm->tm_mon], (int)(tm->tm_year + 1900),
			    tm->tm_hour, tm->tm_min, tm->tm_sec);
			if (i < 1 || (size_t)i >= sizeof(tmbuf)) {
				warn("snprintf%s", ", using dummy time");
				goto fallbacktime;
			}
		} else {
			warn("gmtime");
 fallbacktime:
			cscpy(tmbuf, "Wed, 31 Dec 1969 23:59:59 GMT");
		}
		errno = ETXTBSY;
		i = snprintf(hdrbuf, sizeof(hdrbuf),
		    "HTTP/1.0 200 OK\r\n"
		    "Date: %s\r\n"
		    "Expires: %s\r\n"
		    "Content-Type: text/plain; charset=UTF-8\r\n"
		    "\r\n", tmbuf, tmbuf);
		if (i < 1 || (size_t)i >= sizeof(hdrbuf)) {
			warn("snprintf%s", ", using mini header");
			cscpy(hdrbuf, "HTTP/1.0 200 uh-oh\r\n\r\n");
		}
	}
	errno = ETXTBSY;
	i = snprintf(buf, sizeof(buf), "%s"
	    "{\n  \"client-l3\": \"%s\""
	    ",\n  \"client-l4\": \"%s\""
	    ",\n  \"client-host\": \"%s\""
	    ",\n  \"client-port\": \"%s\""
	    "%s"
	    ",\n  \"server-l3\": \"%s\""
	    ",\n  \"server-l4\": \"%s\""
	    ",\n  \"server-host\": \"%s\""
	    ",\n  \"server-port\": \"%s\""
	    ",\n  \"timestamp\": %lld.%06ld"
	     "\n}\n", hdrbuf,
	    cfamily, protoname[istcp], chost, cport,
	    specdstbuf,
	    sfamily, protoname[istcp], shost, sport,
	    (long long)tv.tv_sec, (long)tv.tv_usec);
	if (i < 1) {
		warn("snprintf%s", ", no reply sent");
		goto out;
	}
	if ((size_t)i >= sizeof(buf))
		warnx("snprintf%s", " truncated");
	fprintf(stderr, "Response: %s", buf + strlen(hdrbuf));
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

#if !defined(pkti4_recv) && !defined(pkti6_recv)
#warning server IP may be imprecise
static int
recvudp(int fd, void *buf, size_t len, union sockun *sac, socklen_t *zac,
    union sockun *sas __attribute__((__unused__)),
    socklen_t *zas __attribute__((__unused__)))
{
	if (recvfrom(fd, buf, len, 0, &(sac->sa), zac) < 0) {
		warn("recvfrom(%d)", fd);
		return (1);
	}
	return (0);
}
#else
#define cmsgtype1
#define cmsgtype2
#define cmsgtype3
#define cmsgtype4
#define cmsgtype cmsgtype1 cmsgtype2 cmsgtype3 cmsgtype4 "(unknown cmsg_type)"
static int
recvudp(int fd, void *buf, size_t len, union sockun *sac, socklen_t *zac,
    union sockun *sas, socklen_t *zas __attribute__((__unused__)))
{
	struct msghdr m;
	struct iovec io;
	char cmsgbuf[64];
	struct cmsghdr *cmsg;
	unsigned int found = 0;

	if (
#ifdef AF_INET6
	    sas->sa.sa_family != AF_INET6 &&
#endif
	    sas->sa.sa_family != AF_INET) {
		if (recvfrom(fd, buf, len, 0, &(sac->sa), zac) < 0) {
			warn("recvfrom(%d)", fd);
			return (1);
		}
		return (0);
	}

	memset(&m, 0, sizeof(m));
	memset(&io, 0, sizeof(io));

	io.iov_base = buf;
	io.iov_len = len;

	m.msg_name = &(sac->sa);
	m.msg_namelen = *zac;
	m.msg_iov = &io;
	m.msg_iovlen = 1;
	m.msg_control = cmsgbuf;
	m.msg_controllen = sizeof(cmsgbuf);
	m.msg_flags = 0;

	if (recvmsg(fd, &m, 0) < 0) {
		warn("recvmsg(%d)", fd);
		return (1);
	}
	*zac = m.msg_namelen;
	if ((m.msg_flags & MSG_CTRUNC))
		warnx("CMSG truncated");
	for (cmsg = CMSG_FIRSTHDR(&m);
	     cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&m, cmsg)) {
		switch (cmsg->cmsg_level) {
#ifdef pkti4_recv
		case IPPROTO_IP:
			if (sas->sa.sa_family != AF_INET) {
				warnx("%s CMSG outside of %s ignored",
				    "IPPROTO_IP", "AF_INET");
				continue;
			}
			switch (cmsg->cmsg_type) {
			/* maybe also, later, obtain iptos? */
#if defined(IP_RECVPKTINFO) || defined(IP_PKTINFO)
#ifdef IP_RECVPKTINFO
#undef cmsgtype1
#define cmsgtype1 cmsg->cmsg_type == IP_RECVPKTINFO ? "IP_RECVPKTINFO" :
			case IP_RECVPKTINFO: /* legacy NetBSD */
#endif
#ifdef IP_PKTINFO
#undef cmsgtype2
#define cmsgtype2 cmsg->cmsg_type == IP_PKTINFO ? "IP_PKTINFO" :
			case IP_PKTINFO:
#endif
				if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in_pktinfo))) {
					struct in_pktinfo *ipi;
					int i;

					ipi = (void *)CMSG_DATA(cmsg);
					memcpy(&(sas->sin.sin_addr),
					    &(ipi->ipi_addr),
					    sizeof(struct in_addr));
					++found;
#if defined(__linux__) || \
    (defined(__sun__) && defined(__svr4__)) || \
    (defined(__sun) && defined(__SVR4))
					errno = ETXTBSY;
					i = snprintf(specdstbuf, sizeof(specdstbuf),
					    ",\n  \"lnx.specdst\": \"%s\"",
					    inet_ntoa(ipi->ipi_spec_dst));
					if (i < 1 || (size_t)i >= sizeof(specdstbuf)) {
						warn("ipi_spec_dst snprintf: %s",
						    inet_ntoa(ipi->ipi_spec_dst));
						specdstbuf[0] = '\0';
					}
#endif
				} else
					warnx("unexpected %s length %zu not %zu, ignored",
					    cmsgtype,
					    (size_t)cmsg->cmsg_len,
					    (size_t)CMSG_LEN(sizeof(struct in_pktinfo)));
				break;
#endif /* defined(IP_RECVPKTINFO) || defined(IP_PKTINFO) */
#ifdef IP_RECVDSTADDR
			case IP_RECVDSTADDR:
				if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in_addr))) {
					memcpy(&(sas->sin.sin_addr),
					    CMSG_DATA(cmsg),
					    sizeof(struct in_addr));
					++found;
				} else
					warnx("unexpected %s length %zu not %zu, ignored",
					    "IP_RECVDSTADDR",
					    (size_t)cmsg->cmsg_len,
					    (size_t)CMSG_LEN(sizeof(struct in_addr)));
				break;
#endif /* IP_RECVDSTADDR */
			}
			break; /* case IPPROTO_IP */
#endif /* pkti4_recv */
#ifdef pkti6_recv
		case IPPROTO_IPV6:
			if (sas->sa.sa_family != AF_INET6) {
				warnx("%s CMSG outside of %s ignored",
				    "IPPROTO_IPV6", "AF_INET6");
				continue;
			}
			switch (cmsg->cmsg_type) {
			/* maybe also, later, obtain iptos? */
#ifdef IPV6_RECVPKTINFO
#undef cmsgtype3
#define cmsgtype3 cmsg->cmsg_type == IPV6_RECVPKTINFO ? "IPV6_RECVPKTINFO" :
			case IPV6_RECVPKTINFO:
#endif
#ifdef IPV6_PKTINFO
#undef cmsgtype4
#define cmsgtype4 cmsg->cmsg_type == IPV6_PKTINFO ? "IPV6_PKTINFO" :
			case IPV6_PKTINFO:
#endif
				if (cmsg->cmsg_len == CMSG_LEN(sizeof(struct in6_pktinfo))) {
					struct in6_pktinfo *i6pi;

					i6pi = (void *)CMSG_DATA(cmsg);
					memcpy(&(sas->sin6.sin6_addr),
					    &(i6pi->ipi6_addr),
					    sizeof(struct in6_addr));
#ifdef IN6_IS_ADDR_LINKLOCAL
					/* KAME */
					if (IN6_IS_ADDR_LINKLOCAL(&(sas->sin6.sin6_addr)))
						sas->sin6.sin6_scope_id =
						    i6pi->ipi6_ifindex;
#endif
					++found;
				} else
					warnx("unexpected %s length %zu not %zu, ignored",
					    cmsgtype,
					    (size_t)cmsg->cmsg_len,
					    (size_t)CMSG_LEN(sizeof(struct in6_pktinfo)));
				break;
			}
			break; /* case IPPROTO_IPV6 */
#endif /* pkti6_recv */
		}
	}
	if (found != 1)
		warnx("found %u server-host CMSGs", found);
	return (0);
}
#endif
