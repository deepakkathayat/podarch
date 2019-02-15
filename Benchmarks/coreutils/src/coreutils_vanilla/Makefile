TOP_DIR = ../..
LIBDIR  = $(TOP_DIR)/lib/libcoreutils.a $(TOP_DIR)/src/libver.a
INCLUDE = -I $(TOP_DIR)/lib/

LDFLAGS = -static -std=c99
CC = gcc 
EXECUTABLES = base64 basename cat chcon chmod cksum comm csplit cut dircolors dirname du echo env expand  false fmt fold getlimits head hostid join link logname  mkfifo mknod mktemp  nice nl nohup nproc od paste printenv printf ptx pwd readlink  runcon seq shred shuf sleep split stdbuf stty  sum sync tac tail tee  tr true truncate tsort tty uniq unlink uptime users wc yes

all : $(EXECUTABLES)

$(EXECUTABLES) : 
	$(CC)  -o $@ $@.c  $(LDFLAGS) $(INCLUDE) $(LIBDIR)
clean :
	 $(RM) *~  *.o $(EXECUTABLES)
