CC	= gcc
CFLAGS	=  -D_GNU_SOURCE 
PROGS1	= makepod
PROGS2  = get_pod_int
OBJS	= makepod.o

INSTALL = install

pod:
	$(CC) $(CFLAGS) -o $(PROGS1) makepod.c -lcrypto
int:
	$(CC) $(CFLAGS) -o $(PROGS2) get_pod_int.c -lcrypto
all:
	$(CC) $(CFLAGS) -o $(PROGS1) makepod.c -lcrypto
	$(CC) $(CFLAGS) -o $(PROGS2) get_pod_int.c -lcrypto
clean:
	rm -f $(OBJS) $(PROGS1) $(PROGS2)
