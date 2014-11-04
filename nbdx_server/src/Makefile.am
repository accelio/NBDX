# this is Makefile file: src/nbdx_server/Makefile.am

XIO_HOME=/opt/xio/
# additional include pathes necessary to compile the C programs
AM_CFLAGS = -DPIC -fPIC  -I/$(XIO_HOME)/include/ @AM_CFLAGS@
AM_LDFLAGS = -lxio -libverbs -lrdmacm -lrt -lpthread -laio \
	     -L$(XIO_HOME)/lib/ 

###############################################################################
# THE PROGRAMS TO BUILD
###############################################################################

# the program to build (the names of the final binaries)
bin_PROGRAMS = nbdx_server
	
# list of sources for the binary
nbdx_server_SOURCES = nbdx_server.c		\
		      nbdx_handlers.c		\
		      nbdx_bs.c 		\
		      nbdx_bs_null.c		\
		      nbdx_bs_aio.c		\
		      nbdx_utils.c		\
		      msg_pool.c

# the additional libraries needed to link nbdx_server
EXTRA_DIST =

###############################################################################
