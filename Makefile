CFLAGS = -O0 -g

all:	srp-simple srp-gw

srp-simple:	towire.o srp-simple.o

srp-gw:	srp-gw.o towire.o fromwire.o

