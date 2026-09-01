PROG= zkcmp
.PATH: ${.CURDIR}/src
SRCS= zkcmp.c cmd.c crypto.c

CFLAGS+= -O2 -Wall -Wextra -Wpedantic
CFLAGS+= -I${.CURDIR}/include

LDADD=	-lcrypto

PREFIX?= /usr/local
BINDIR=  ${PREFIX}/bin

.include <bsd.prog.mk>
