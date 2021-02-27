CC=gcc
CFLAGS=-I.


all: crp_pack crp_unpack

crp_pack: crp_pack.c 
	$(CC) -o crp_pack crp_pack.c

crp_unpack: crp_unpack.c
	$(CC) -o crp_unpack crp_unpack.c
