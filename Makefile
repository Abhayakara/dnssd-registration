CFLAGS = -O0 -g

all:	srp-simple srp-gw

srp-simple:	wire.o srp-simple.o

srp-gw:	srp-gw.o wire.o
