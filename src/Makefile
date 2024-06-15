# for dev-test builds (check for warnings) only

PROG=		saachenzip
SRCS?=		${PROG}.c
OBJS?=		${SRCS:.c=.o}

CC?=		gcc
CPPFLAGS=	-D_GNU_SOURCE -Wdate-time -D_FORTIFY_SOURCE=2
CFLAGS=		-g -O2 -Wall -Wextra -Wformat -Werror=format-security -Werror=implicit-function-declaration
LDFLAGS=
LIBS=
LDSTATIC=

all: ${PROG}

${PROG}: ${OBJS}
	${CC} ${CFLAGS} ${LDFLAGS} ${LDSTATIC} -o $@ ${OBJS} ${LIBS}

.c.o:
	${CC} ${CPPFLAGS} ${CFLAGS} -c $<

.c.i:
	${CC} ${CPPFLAGS} ${CFLAGS} -E -o $@ $<

CLEANFILES+=	${OBJS} ${PROG} ${SRCS:.c=.i}

clean:
	-rm -f ${CLEANFILES}

.SUFFIXES: .c .i .o
