CFLAGS = -O0 -g -Wall -Werror -I/usr/local/include
LDFLAGS = -lmbedcrypto

all:	srp-simple srp-gw keydump

clean:
	rm *.o
	rm srp-simple
	rm srp-gw

srp-simple:	towire.o srp-simple.o sign-mbedtls.o

srp-gw:	srp-gw.o towire.o fromwire.o sign-mbedtls.o verify-mbedtls.o ioloop.o dnssd-proxy.o

keydump:	keydump.o fromwire.o sign-mbedtls.o verify-mbedtls.o




