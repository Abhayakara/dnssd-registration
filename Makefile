CFLAGS = -O0 -g -Wall -Werror

all:	srp-simple srp-gw

clean:
	rm *.o
	rm srp-simple
	rm srp-gw

srp-simple:	towire.o srp-simple.o

srp-gw:	srp-gw.o towire.o fromwire.o

