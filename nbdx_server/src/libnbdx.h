/*
 * Copyright (c) 2013 Mellanox Technologies®. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies® BSD license
 * below:
 *
 *      - Redistribution and use in source and binary forms, with or without
 *        modification, are permitted provided that the following conditions
 *        are met:
 *
 *      - Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *      - Neither the name of the Mellanox Technologies® nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef LIBNBDX_H
#define LIBNBDX_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include "libxio.h"

#define MAX_THREADS		6

/*---------------------------------------------------------------------------*/
/* forward declarations	                                                     */
/*---------------------------------------------------------------------------*/
struct timespec;
struct stat64;
struct nbdx_iocb;
struct nbdx_thread_data;
struct nbdx_server_data;

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
typedef struct nbdx_context *nbdx_context_t;
typedef struct nbdx_mr *nbdx_mr_t;

/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum nbdx_iocb_cmd {
	NBDX_CMD_PREAD		= 0,
	NBDX_CMD_PWRITE		= 1,
};

/** events for nbdx server */
enum nbdx_server_events {
	NBDX_CONTROL_EVENT		= 20
};

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct nbdx_iocb_common {
	void			*buf;
	unsigned long long	nbytes;
	long long		offset;
	nbdx_mr_t		mr;
	unsigned int		flags;
	unsigned int		resfd;
};	/* result code is the amount read or negative errno */

struct nbdx_iocb {
	void			*data;  /* Return in the io completion event */
	unsigned int		key;	/* For use in identifying io requests */
	int			nbdx_fildes;
	int			nbdx_lio_opcode;
	int			pad;
	union {
		struct nbdx_iocb_common	c;
	} u;
};

struct nbdx_event {
	void			*data;  /* Return in the io completion event */
	struct nbdx_iocb	*obj;
	unsigned long long	handle; /* release handle */
	unsigned long		res;
	unsigned long		res2;
};

struct nbdx_portal_data  {
	struct	nbdx_thread_data	*tdata;
	void				*dd_data;
};

struct nbdx_session_data {
	struct	xio_session		*session;
	void				*dd_data;
	struct nbdx_portal_data		portal_data[MAX_THREADS];
	SLIST_ENTRY(nbdx_session_data)	srv_ses_list;
};

struct nbdx_thread_data {
	struct nbdx_server_data		*server_data;
	char				portal[64];
	int				affinity;
	int				pad;
	struct xio_msg			rsp;
	struct xio_context		*ctx;
};

/* server private data */
struct nbdx_server_data {
	struct xio_context		*ctx;
	int				evt_fd;
	int				last_used;
	int				last_reaped;
	int				pad;
	SLIST_HEAD(, nbdx_session_data)	ses_list;
	pthread_mutex_t         l_lock;
	TAILQ_HEAD(, nbdx_control_work)		control_work_queue_list;

	pthread_t			thread_id[MAX_THREADS];
	struct nbdx_thread_data		tdata[MAX_THREADS];
};

/**
 * nbdx_open - open file for io operations
 *
 * @addr: address to rcopy server
 * @addrlen: address length
 * @pathname: fullpath to the file or device
 * @flags:    open flags - see "man 2 open"
 *
 * RETURNS: return the new file descriptor, or -1 if an error occurred (in
 * which case, errno is set appropriately)
 */
int nbdx_open(const struct sockaddr *addr, socklen_t addrlen,
	      const char *pathname, int flags);

/**
 * nbdx_fstat - get file status
 *
 * @fd:	the file's file descriptor
 * @buf: the file stat structure
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_fstat(int fd, struct stat64 *buf);

/**
 * nbdx_close - close file or device
 *
 * @fd:	the file's file descriptor
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_close(int fd);

/**
 * nbdx_setup - creates an asynchronous I/O context capable of receiving at
 * most maxevents
 *
 * @fd:		file descriptor to work on
 * @maxevents:	max events to receive
 * @ctxp:	On successful creation of the NBDX context, *ctxp is filled
 *		in with the resulting  handle.
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_setup(int fd, int maxevents, nbdx_context_t *ctxp);

/**
 * nbdx_destroy - destroys an asynchronous I/O context
 *
 * @ctx:	the NBDX context
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_destroy(nbdx_context_t ctx);

/**
 * nbdx_submit - queues nr I/O request blocks for processing in the NBDX
 *		 context ctx
 *
 * @ctx:	the NBDX context
 * @nr:		number of events to queue
 * @handles:	array of io control block requests to queue
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_submit(nbdx_context_t ctx, long nr, struct nbdx_iocb *ios[]);

/**
 * nbdx_cancel - attempt to cancel an outstanding asynchronous I/O operation
 *
 * @ctx:	the NBDX context ID of the operation to be canceled
 * @iocb:	control block to cancel
 * @result:	upon success, a copy of the canceled event
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_cancel(nbdx_context_t ctx, struct nbdx_iocb *iocb,
		struct nbdx_event *evt);

/**
 * nbdx_getevents - read asynchronous I/O events from the completion queue
 *
 * @ctx:	the NBDX context ID
 * @min_nr:	at least min_nr to read
 * @nr:		at most nr to read
 * @events:	returned events array
 * @timeout:	specifies the amount of time to wait for events, where a NULL
 *		timeout waits until at least min_nr events have been seen.
 *
 * RETURNS: On  success,  nbdx_getevents()  returns  the number of events read:
 * 0 if no events are available, or less than min_nr if the timeout has elapsed.
 */
int nbdx_getevents(nbdx_context_t ctx, long min_nr, long nr,
		   struct nbdx_event *events, struct timespec *timeout);

/**
 * nbdx_release - release nbdx resources when events is no longer needed
 *
 * @ctx:	the NBDX context ID
 * @nr:		number of events to release
 * @ihandles:	handles array to release
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_release(nbdx_context_t ctx, long nr, struct nbdx_event *events);

/**
 * nbdx_reg_mr - register memory region for rdma operations
 *
 * @ctx:	the NBDX context ID
 * @buf:	pointer to memory buffer
 * @len:	the buffer's length
 * @mr:		returned memory region
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_reg_mr(nbdx_context_t ctx, void *buf, size_t len, nbdx_mr_t *mr);

/**
 * nbdx_dereg_mr - deregister memory region
 *
 * @ctx:	the NBDX context ID
 * @mr:		the memory region
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int nbdx_dereg_mr(nbdx_context_t ctx, nbdx_mr_t mr);


static inline void nbdx_prep_pread(struct nbdx_iocb *iocb, int fd, void *buf,
				   size_t count, long long offset,
				   nbdx_mr_t mr)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->nbdx_fildes = fd;
	iocb->nbdx_lio_opcode = NBDX_CMD_PREAD;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
	iocb->u.c.mr = mr;
}

static inline void nbdx_prep_pwrite(struct nbdx_iocb *iocb, int fd, void *buf,
				    size_t count, long long offset,
				    nbdx_mr_t mr)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->nbdx_fildes = fd;
	iocb->nbdx_lio_opcode = NBDX_CMD_PWRITE;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
	iocb->u.c.mr = mr;
}

static inline void nbdx_set_eventfd(struct nbdx_iocb *iocb, int eventfd)
{
	iocb->u.c.flags |= (1 << 0) /* NBDXCB_FLAG_RESFD */;
	iocb->u.c.resfd = eventfd;
}

#ifdef __cplusplus
}
#endif

#endif /* LIBNBDX_H */

