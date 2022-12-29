.PHONY:	all clean

all: pcapng_parser

clean:
	rm pcapng_parser

pcapng_parser: pcapng_parser.c
	gcc -Wall -O2 -o pcapng_parser pcapng_parser.c
