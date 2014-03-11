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
#ifndef LIBXNBD_H
#define LIBXNBD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

/*---------------------------------------------------------------------------*/
/* forward declarations	                                                     */
/*---------------------------------------------------------------------------*/
struct timespec;
struct stat64;
struct xnbd_iocb;

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
typedef struct xnbd_context *xnbd_context_t;
typedef struct xnbd_mr *xnbd_mr_t;

/*---------------------------------------------------------------------------*/
/* enums								     */
/*---------------------------------------------------------------------------*/
enum xnbd_iocb_cmd {
	XNBD_CMD_PREAD		= 0,
	XNBD_CMD_PWRITE		= 1,
};

/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct xnbd_iocb_common {
	void			*buf;
	unsigned long long	nbytes;
	long long		offset;
	xnbd_mr_t		mr;
	unsigned int		flags;
	unsigned int		resfd;
};	/* result code is the amount read or negative errno */

struct xnbd_iocb {
	void			*data;  /* Return in the io completion event */
	unsigned int		key;	/* For use in identifying io requests */
	int			xnbd_fildes;
	int			xnbd_lio_opcode;
	int			pad;
	union {
		struct xnbd_iocb_common	c;
	} u;
};

struct xnbd_event {
	void			*data;  /* Return in the io completion event */
	struct xnbd_iocb	*obj;
	unsigned long long	handle; /* release handle */
	unsigned long		res;
	unsigned long		res2;
};

/**
 * xnbd_open - open file for io operations
 *
 * @addr: address to rcopy server
 * @addrlen: address length
 * @pathname: fullpath to the file or device
 * @flags:    open flags - see "man 2 open"
 *
 * RETURNS: return the new file descriptor, or -1 if an error occurred (in
 * which case, errno is set appropriately)
 */
int xnbd_open(const struct sockaddr *addr, socklen_t addrlen,
	      const char *pathname, int flags);

/**
 * xnbd_fstat - get file status
 *
 * @fd:	the file's file descriptor
 * @buf: the file stat structure
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_fstat(int fd, struct stat64 *buf);

/**
 * xnbd_close - close file or device
 *
 * @fd:	the file's file descriptor
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_close(int fd);

/**
 * xnbd_setup - creates an asynchronous I/O context capable of receiving at
 * most maxevents
 *
 * @fd:		file descriptor to work on
 * @maxevents:	max events to receive
 * @ctxp:	On successful creation of the XNBD context, *ctxp is filled
 *		in with the resulting  handle.
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_setup(int fd, int maxevents, xnbd_context_t *ctxp);

/**
 * xnbd_destroy - destroys an asynchronous I/O context
 *
 * @ctx:	the XNBD context
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_destroy(xnbd_context_t ctx);

/**
 * xnbd_submit - queues nr I/O request blocks for processing in the XNBD
 *		 context ctx
 *
 * @ctx:	the XNBD context
 * @nr:		number of events to queue
 * @handles:	array of io control block requests to queue
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_submit(xnbd_context_t ctx, long nr, struct xnbd_iocb *ios[]);

/**
 * xnbd_cancel - attempt to cancel an outstanding asynchronous I/O operation
 *
 * @ctx:	the XNBD context ID of the operation to be canceled
 * @iocb:	control block to cancel
 * @result:	upon success, a copy of the canceled event
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_cancel(xnbd_context_t ctx, struct xnbd_iocb *iocb,
		struct xnbd_event *evt);

/**
 * xnbd_getevents - read asynchronous I/O events from the completion queue
 *
 * @ctx:	the XNBD context ID
 * @min_nr:	at least min_nr to read
 * @nr:		at most nr to read
 * @events:	returned events array
 * @timeout:	specifies the amount of time to wait for events, where a NULL
 *		timeout waits until at least min_nr events have been seen.
 *
 * RETURNS: On  success,  xnbd_getevents()  returns  the number of events read:
 * 0 if no events are available, or less than min_nr if the timeout has elapsed.
 */
int xnbd_getevents(xnbd_context_t ctx, long min_nr, long nr,
		   struct xnbd_event *events, struct timespec *timeout);

/**
 * xnbd_release - release xnbd resources when events is no longer needed
 *
 * @ctx:	the XNBD context ID
 * @nr:		number of events to release
 * @ihandles:	handles array to release
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_release(xnbd_context_t ctx, long nr, struct xnbd_event *events);

/**
 * xnbd_reg_mr - register memory region for rdma operations
 *
 * @ctx:	the XNBD context ID
 * @buf:	pointer to memory buffer
 * @len:	the buffer's length
 * @mr:		returned memory region
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_reg_mr(xnbd_context_t ctx, void *buf, size_t len, xnbd_mr_t *mr);

/**
 * xnbd_dereg_mr - deregister memory region
 *
 * @ctx:	the XNBD context ID
 * @mr:		the memory region
 *
 * RETURNS: On success, zero is returned.  On error, -1 is returned, and errno
 * is set appropriately.
 */
int xnbd_dereg_mr(xnbd_context_t ctx, xnbd_mr_t mr);


static inline void xnbd_prep_pread(struct xnbd_iocb *iocb, int fd, void *buf,
				   size_t count, long long offset,
				   xnbd_mr_t mr)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->xnbd_fildes = fd;
	iocb->xnbd_lio_opcode = XNBD_CMD_PREAD;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
	iocb->u.c.mr = mr;
}

static inline void xnbd_prep_pwrite(struct xnbd_iocb *iocb, int fd, void *buf,
				    size_t count, long long offset,
				    xnbd_mr_t mr)
{
	memset(iocb, 0, sizeof(*iocb));
	iocb->xnbd_fildes = fd;
	iocb->xnbd_lio_opcode = XNBD_CMD_PWRITE;
	iocb->u.c.buf = buf;
	iocb->u.c.nbytes = count;
	iocb->u.c.offset = offset;
	iocb->u.c.mr = mr;
}

static inline void xnbd_set_eventfd(struct xnbd_iocb *iocb, int eventfd)
{
	iocb->u.c.flags |= (1 << 0) /* XNBDCB_FLAG_RESFD */;
	iocb->u.c.resfd = eventfd;
}

#ifdef __cplusplus
}
#endif

#endif /* LIBXNBD_H */

