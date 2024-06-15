static const char licence_header[] __attribute__((__used__)) =
    "@(#) https://github.com/qvest-digital/saachenzip"
	/* Ⓕ MirBSD (The MirOS Licence) */
    "\n	/*-"
    "\n	 * Copyright © 2024"
    "\n	 *	Thorsten Glaser <t.glaser@qvest-digital.com>"
    "\n	 * Copyright © 2020, 2021"
    "\n	 *	Thorsten Glaser, for Deutsche Telekom LLCTO"
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
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char *argv[])
{
//	int port;

	printf("main: %016lX\n", (unsigned long)&main);

	uid_t ru, eu, su;
	gid_t rg, eg, sg;
	if (getresuid(&ru, &eu, &su))
		err(1, "getresuid");
	if (getresgid(&rg, &eg, &sg))
		err(1, "getresgid");

	printf("ugid: %u:%u %u:%u %u:%u\n",
	    (unsigned)ru, (unsigned)rg,
	    (unsigned)eu, (unsigned)eg,
	    (unsigned)su, (unsigned)sg);

	if (argc != 2)
		errx(1, "Usage: %s <port>",
		    argc > 0 && *argv && **argv ? *argv : "saachenzip");
	return (0);
}
