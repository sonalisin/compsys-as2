certcheck:	certcheck.c
	gcc	-Wall	certcheck.c	-o	certcheck	-lssl	-lcrypto

clean	:
	rm	certcheck.o
