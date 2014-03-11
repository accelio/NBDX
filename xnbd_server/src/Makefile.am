# this is Makefile file: src/xnbd_server/Makefile.am

XIO_HOME=/opt/xio/
# additional include pathes necessary to compile the C programs
AM_CFLAGS = -DPIC -fPIC  -I/$(XIO_HOME)/include/ @AM_CFLAGS@
AM_LDFLAGS = -lxio -libverbs -lrdmacm -lrt -lpthread -laio \
	     -L$(XIO_HOME)/lib/ 

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = xnbd_server
	
# list of sources for the binary
xnbd_server_SOURCES = xnbd_server.c		\
		      xnbd_handlers.c		\
		      xnbd_bs.c 		\
		      xnbd_bs_null.c		\
		      xnbd_bs_aio.c		\
		      xnbd_utils.c		\
		      msg_pool.c

# the additional libraries needed to link xnbd_server
EXTRA_DIST =

###############################################################################
