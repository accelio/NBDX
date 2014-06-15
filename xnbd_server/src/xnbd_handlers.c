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
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include "libxio.h"

#include "xnbd_buffer.h"
#include "xnbd_command.h"
#include "xnbd_handlers.h"
#include "xnbd_utils.h"
#include "xnbd_bs.h"
#include "libxnbd.h"
#include "msg_pool.h"

/*---------------------------------------------------------------------------*/
/* preprocessor macros				                             */
/*---------------------------------------------------------------------------*/
#define MAXBLOCKSIZE	(128*1024)
#define BS_IODEPTH	128
#define NULL_BS_DEV_SIZE (1ULL << 32)
#define EXTRA_MSGS	256

#ifndef TAILQ_FOREACH_SAFE
#define	TAILQ_FOREACH_SAFE(var, head, field, next)			 \
	for ((var) = ((head)->tqh_first);				 \
			(var) != NULL && ((next) = TAILQ_NEXT((var), field), 1); \
			(var) = (next))
#endif


/*---------------------------------------------------------------------------*/
/* data structres				                             */
/*---------------------------------------------------------------------------*/
struct xnbd_io_u {
	struct xnbd_event		ev_data;
	struct xio_msg			*rsp;
	void 				*buf;
	struct xnbd_io_cmd		iocmd;

	TAILQ_ENTRY(xnbd_io_u)		io_u_list;
};

struct xnbd_io_portal_data {
	TAILQ_HEAD(, xnbd_bs)       dev_list;
	int             ndevs;
	int				iodepth;
	int				io_nr;
	int				io_u_free_nr;
	struct xnbd_io_u		*io_us_free;
	struct xio_msg			rsp;
	struct xio_msg			close_rsp;
	struct msg_pool			*rsp_pool;
	struct xio_context		*ctx;
	char				rsp_hdr[512];

	TAILQ_HEAD(, xnbd_io_u)		io_u_free_list;
};

struct xnbd_io_session_data {
	int				portals_nr;
	int				pad;

	struct xnbd_io_portal_data	*pd;
};

/*---------------------------------------------------------------------------*/
/* xnbd_lookup_bs_dev                                   */
/*---------------------------------------------------------------------------*/
struct xnbd_bs *xnbd_lookup_bs_dev(int fd, struct xnbd_io_portal_data *pd)
{
   struct xnbd_bs      *bs_dev;

   TAILQ_FOREACH(bs_dev, &pd->dev_list, list) {
       if (bs_dev->fd == fd) {
           return bs_dev;
       }
   }
   return NULL;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handler_init_session_data				             */
/*---------------------------------------------------------------------------*/
void *xnbd_handler_init_session_data(int portals_nr)
{
	struct xnbd_io_session_data *sd;
	sd = calloc(1, sizeof(*sd));

	sd->pd		= calloc(portals_nr, sizeof(*sd->pd));
	sd->portals_nr	= portals_nr;

	return sd;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handler_init_portal_data				             */
/*---------------------------------------------------------------------------*/
void *xnbd_handler_init_portal_data(void *prv_session_data,
				    int portal_nr, void *ctx)
{
	struct xnbd_io_session_data *sd = prv_session_data;
	struct xnbd_io_portal_data *pd = &sd->pd[portal_nr];

	pd->ctx = ctx;
	pd->rsp.out.header.iov_base = pd->rsp_hdr;
	pd->rsp.out.header.iov_len  = sizeof(pd->rsp_hdr);
	pd->ndevs = 0;
	TAILQ_INIT(&pd->dev_list);

	return pd;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handler_free_session_data				             */
/*---------------------------------------------------------------------------*/
void xnbd_handler_free_session_data(void *prv_session_data)
{
	struct xnbd_io_session_data *sd = prv_session_data;
	free(sd->pd);

	free(sd);
}

/*---------------------------------------------------------------------------*/
/* xnbd_handler_free_portal_data				             */
/*---------------------------------------------------------------------------*/
void xnbd_handler_free_portal_data(void *prv_portal_data)
{
	struct xnbd_io_portal_data	*pd = prv_portal_data;
	struct xnbd_bs      *bs_dev, *tmp;

	TAILQ_FOREACH_SAFE(bs_dev, &pd->dev_list, list, tmp) {
		if (bs_dev->fd != -1 && !bs_dev->is_null)
			close(bs_dev->fd);
		TAILQ_REMOVE(&pd->dev_list, bs_dev, list);
	}

}

/*---------------------------------------------------------------------------*/
/* xnbd_handle_open				                             */
/*---------------------------------------------------------------------------*/
static int xnbd_handle_open(void *prv_session_data,
			    void *prv_portal_data,
			    struct xnbd_command *cmd,
			    char *cmd_data,
			    struct xio_msg *req)
{
	struct xnbd_io_session_data	*sd = prv_session_data;
	struct xnbd_io_portal_data	*pd = prv_portal_data;
	const char	*pathname;
	uint32_t	flags = 0;
	unsigned	overall_size;
	int		fd;
	int i, is_null = 0;


	overall_size = sizeof(fd);

	pathname = unpack_u32(&flags,
			      cmd_data);


	if (sizeof(flags) + strlen(pathname) + 1 != cmd->data_len) {
		fd = -1;
		errno = EINVAL;
		printf("open request rejected\n");
		goto reject;
	}

	if (strcmp(pathname, "/dev/null")) {
		fd = open(pathname, flags);
		if (fd == -1)
			goto reject;

	} else {
		is_null = 1;
		fd = 0;
	}

	for (i = 0; i < sd->portals_nr; i++) {
		struct xnbd_bs *bs_dev;
	    struct xnbd_io_portal_data  *cpd;

	    cpd = &sd->pd[i];
	    if (is_null) {
		    bs_dev = xnbd_bs_init(cpd->ctx, "null");
		    bs_dev->is_null = 1;
	    } else {
		    bs_dev = xnbd_bs_init(cpd->ctx, "aio");
		    bs_dev->is_null = 0;
	    }

	   errno = -xnbd_bs_open(bs_dev, fd);
	   if (errno)
		   break;

	  TAILQ_INSERT_TAIL(&cpd->dev_list, bs_dev, list);
	  cpd->ndevs++;
	}

reject:
	if (fd == -1 || errno) {
		struct xnbd_answer ans = {XNBD_CMD_OPEN, 0,
					   -1, errno};
		pack_u32((uint32_t *)&ans.ret_errno,
			 pack_u32((uint32_t *)&ans.ret,
			 pack_u32(&ans.data_len,
			 pack_u32(&ans.command,
			 pd->rsp_hdr))));
		fprintf(stderr, "open %s failed %m\n", pathname);
	 } else {
		 unsigned overall_size = sizeof(fd);
		 struct xnbd_answer ans = {XNBD_CMD_OPEN,
					   overall_size, 0, 0};
		 pack_u32((uint32_t *)&fd,
			  pack_u32((uint32_t *)&ans.ret_errno,
			  pack_u32((uint32_t *)&ans.ret,
			  pack_u32(&ans.data_len,
			  pack_u32(&ans.command,
			  pd->rsp_hdr)))));
	 }

	pd->rsp.out.header.iov_len = (sizeof(struct xnbd_answer) +
				     overall_size);

	pd->rsp.request = req;

	xio_send_response(&pd->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handle_close				                             */
/*---------------------------------------------------------------------------*/
static int xnbd_handle_close(void *prv_session_data,
			     void *prv_portal_data,
			     struct xnbd_command *cmd,
			     char *cmd_data,
			     struct xio_msg *req)
{
	struct xnbd_io_session_data	*sd = prv_session_data;
	struct xnbd_io_portal_data	*pd = prv_portal_data;
	struct xnbd_io_portal_data  *cpd;
	struct xnbd_bs *bs_dev;
	int				fd;
	int				i, retval = 0;

	unpack_u32((uint32_t *)&fd,
		    cmd_data);

	if (sizeof(fd) != cmd->data_len) {
		retval = -1;
		errno = EINVAL;
		printf("close request rejected\n");
		goto reject;
	}

	bs_dev = xnbd_lookup_bs_dev(fd, pd);
	/* close fd only once */
	if (!bs_dev->is_null) {
		retval = close(bs_dev->fd);
		if (!retval)
			goto reject;
	}

	for (i = 0; i < sd->portals_nr; i++) {
		cpd = &sd->pd[i];
		bs_dev = xnbd_lookup_bs_dev(fd, cpd);
		TAILQ_REMOVE(&cpd->dev_list, bs_dev, list);
		if (!bs_dev->is_null) {
			xnbd_bs_close(bs_dev);
			xnbd_bs_exit(bs_dev);
		}
	}

reject:
	if (retval != 0) {
		struct xnbd_answer ans = { XNBD_CMD_CLOSE, 0, -1, errno };
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 pd->rsp_hdr))));
	} else {
		struct xnbd_answer ans = { XNBD_CMD_CLOSE, 0, 0, 0 };
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 pd->rsp_hdr))));
	 }

	pd->rsp.out.header.iov_len = sizeof(struct xnbd_answer);

	pd->rsp.request = req;

	xio_send_response(&pd->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handle_fstat				                             */
/*---------------------------------------------------------------------------*/
static int xnbd_handle_fstat(void *prv_session_data,
			     void *prv_portal_data,
			     struct xnbd_command *cmd,
			     char *cmd_data,
			     struct xio_msg *req)
{
	struct xnbd_io_portal_data	*pd = prv_portal_data;
	int				fd;
	int				retval = 0;
	struct xnbd_bs          *bs_dev;

	unpack_u32((uint32_t *)&fd,
		    cmd_data);

	if (sizeof(fd) != cmd->data_len) {
		retval = -1;
		errno = EINVAL;
		printf("open request rejected\n");
		goto reject;
	}

	bs_dev = xnbd_lookup_bs_dev(fd, pd);
	if (!bs_dev) {
		printf("%s: Ambigiuous device file descriptor %d\n", __func__, fd);
		retval = -1;
		errno = ENODEV;
		goto reject;
	}

reject:
	if (retval != 0) {
		struct xnbd_answer ans = { XNBD_CMD_FSTAT, 0, -1, errno };
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			  pd->rsp_hdr))));
	} else {
		struct xnbd_answer ans = {XNBD_CMD_FSTAT,
					  STAT_BLOCK_SIZE, 0, 0};
		pack_stat64(&bs_dev->stbuf,
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 pd->rsp_hdr)))));
	}

	pd->rsp.out.header.iov_len = sizeof(struct xnbd_answer) +
				     STAT_BLOCK_SIZE;

	pd->rsp.request = req;

	xio_send_response(&pd->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handle_setup				                             */
/*---------------------------------------------------------------------------*/
static int xnbd_handle_setup(void *prv_session_data,
			     void *prv_portal_data,
			     struct xnbd_command *cmd,
			     char *cmd_data,
			     struct xio_msg *req)
{
	int				i, j, err = 0;
	uint32_t			iodepth;
	struct xnbd_io_session_data	*sd = prv_session_data;
	struct xnbd_io_portal_data	*pd = prv_portal_data;
	struct xnbd_io_portal_data	*cpd;


	if (sizeof(int) != cmd->data_len) {
		err = EINVAL;
		printf("io setup request rejected\n");
		goto reject;
	}

	unpack_u32(&iodepth, cmd_data);

	for (i = 0; i < sd->portals_nr; i++) {
		cpd = &sd->pd[i];
		/* divide remote iodepth between server resources */
		cpd->iodepth = (iodepth / sd->portals_nr) + 1;
		cpd->io_u_free_nr = cpd->iodepth + EXTRA_MSGS;
		cpd->io_us_free = calloc(cpd->io_u_free_nr, sizeof(struct xnbd_io_u));
		cpd->rsp_pool = msg_pool_create(512, MAXBLOCKSIZE, cpd->io_u_free_nr);
		TAILQ_INIT(&cpd->io_u_free_list);

		/* register each io_u in the free list */
		for (j = 0; j < cpd->io_u_free_nr; j++) {
			cpd->io_us_free[j].rsp = msg_pool_get(cpd->rsp_pool);
			cpd->io_us_free[j].buf = cpd->io_us_free[j].rsp->out.data_iov[0].iov_base;
			TAILQ_INSERT_TAIL(&cpd->io_u_free_list,
					  &cpd->io_us_free[j],
					  io_u_list);
		}
	}

reject:
	if (err) {
		struct xnbd_answer ans = { XNBD_CMD_IO_SETUP, 0, -1, err };
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 pd->rsp_hdr))));
	} else {
		struct xnbd_answer ans = { XNBD_CMD_IO_SETUP, 0, 0, 0 };
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			pd->rsp_hdr))));
	 }

	pd->rsp.out.header.iov_len = sizeof(struct xnbd_answer);
	pd->rsp.request = req;

	xio_send_response(&pd->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handle_destroy				                             */
/*---------------------------------------------------------------------------*/
static int xnbd_handle_destroy(void *prv_session_data,
			       void *prv_portal_data,
			       struct xnbd_command *cmd,
			       char *cmd_data,
			       struct xio_msg *req)
{
	struct xnbd_io_portal_data	*pd = prv_portal_data;
	int				fd;
	int				retval = 0;

	unpack_u32((uint32_t *)&fd,
		    cmd_data);

	if (sizeof(fd) != cmd->data_len) {
		retval = -1;
		errno = EINVAL;
		printf("open request rejected\n");
		goto reject;
	}

reject:
	if (retval == -1) {
		struct xnbd_answer ans = { XNBD_CMD_IO_DESTROY, 0, -1, errno };
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 pd->rsp_hdr))));
	} else {
		struct xnbd_answer ans = { XNBD_CMD_IO_DESTROY, 0, 0, 0 };
		pack_u32((uint32_t *)&ans.ret_errno,
		pack_u32((uint32_t *)&ans.ret,
		pack_u32(&ans.data_len,
		pack_u32(&ans.command,
			 pd->rsp_hdr))));
	}

	pd->rsp.out.header.iov_len = sizeof(struct xnbd_answer);
	pd->rsp.out.data_iovlen = 0;

	pd->rsp.request = req;

	xio_send_response(&pd->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xnbd_reject_request				                             */
/*---------------------------------------------------------------------------*/
int xnbd_reject_request(void *prv_session_data,
			void *prv_portal_data,
			struct xnbd_command *cmd,
			char *cmd_data,
			struct xio_msg *req)
{
	struct xnbd_io_portal_data	*pd = prv_portal_data;

	struct xnbd_answer ans = { XNBD_CMD_UNKNOWN, 0, -1, errno };
	pack_u32((uint32_t *)&ans.ret_errno,
	pack_u32((uint32_t *)&ans.ret,
	pack_u32(&ans.data_len,
	pack_u32(&ans.command,
		 pd->rsp_hdr))));

	pd->rsp.out.header.iov_len = sizeof(struct xnbd_answer);
	pd->rsp.out.data_iovlen = 0;
	pd->rsp.request = req;

	xio_send_response(&pd->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* on_cmd_submit_comp				                             */
/*---------------------------------------------------------------------------*/
static int on_cmd_submit_comp(struct xnbd_io_cmd *iocmd)
{
	struct xnbd_io_u	*io_u = iocmd->user_context;
	struct xnbd_answer	ans = { XNBD_CMD_IO_SUBMIT, 0, 0, 0 };

	pack_u32((uint32_t *)&iocmd->res2,
	pack_u32((uint32_t *)&iocmd->res,
	pack_u32((uint32_t *)&ans.ret_errno,
	pack_u32((uint32_t *)&ans.ret,
	pack_u32(&ans.data_len,
	pack_u32(&ans.command,
	io_u->rsp->out.header.iov_base))))));

	io_u->rsp->out.header.iov_len = sizeof(struct xnbd_answer) +
					2*sizeof(uint32_t);

	if ( io_u->iocmd.op == XNBD_CMD_PREAD) {
		if (iocmd->res != iocmd->bcount) {
			if (iocmd->res < iocmd->bcount) {
				io_u->rsp->out.data_iov[0].iov_len = iocmd->res;
			} else {
				io_u->rsp->out.data_iovlen	   = 0;
				io_u->rsp->out.data_iov[0].iov_len = iocmd->res;
			}
		} else {
			io_u->rsp->out.data_iov[0].iov_len = iocmd->bcount;
		}
	} else {
		io_u->rsp->out.data_iov[0].iov_len = 0;
		io_u->rsp->out.data_iovlen = 0;
	}

	xio_send_response(io_u->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handle_submit				                             */
/*---------------------------------------------------------------------------*/
static int xnbd_handle_submit(void *prv_session_data,
			      void *prv_portal_data,
			      struct xnbd_command *cmd,
			      char *cmd_data,
			      struct xio_msg *req)
{
	struct xnbd_io_portal_data	*pd = prv_portal_data;
	struct xnbd_io_u		*io_u;
	struct xnbd_iocb		iocb;
	struct xnbd_bs          *bs_dev;
	struct xnbd_answer		ans;
	int				retval;
	uint32_t			is_last_in_batch;
	uint32_t			msg_sz = SUBMIT_BLOCK_SIZE +
						 sizeof(uint32_t);

	io_u = TAILQ_FIRST(&pd->io_u_free_list);
	if (!io_u) {
		printf("io_u_free_list empty\n");
		errno = ENOSR;
		return -1;
	}

	TAILQ_REMOVE(&pd->io_u_free_list, io_u, io_u_list);
	msg_reset(io_u->rsp);
	pd->io_u_free_nr--;

	if (msg_sz != cmd->data_len) {
		retval = EINVAL;
		printf("io submit request rejected\n");

		goto reject;
	}
	unpack_iocb(&iocb,
	unpack_u32(&is_last_in_batch,
		   cmd_data));

	io_u->iocmd.fd			= iocb.xnbd_fildes;
	io_u->iocmd.op			= iocb.xnbd_lio_opcode;
	io_u->iocmd.bcount		= iocb.u.c.nbytes;

	if ( io_u->iocmd.op == XNBD_CMD_PWRITE) {
		io_u->iocmd.buf			= req->in.data_iov[0].iov_base;
		io_u->iocmd.mr			= req->in.data_iov[0].mr;
	} else {
		io_u->iocmd.buf			= io_u->rsp->out.data_iov[0].iov_base;
		io_u->iocmd.mr			= io_u->rsp->out.data_iov[0].mr;
	}

	bs_dev = xnbd_lookup_bs_dev(io_u->iocmd.fd, pd);
	if (!bs_dev) {
		printf("Ambigiuous device file descriptor %d\n", io_u->iocmd.fd);
		errno = ENODEV;
		goto reject;
	}
	io_u->iocmd.fsize       = bs_dev->stbuf.st_size;
	io_u->iocmd.offset		= iocb.u.c.offset;
	io_u->iocmd.is_last_in_batch    = is_last_in_batch;
	io_u->iocmd.res			= 0;
	io_u->iocmd.res2		= 0;
	io_u->iocmd.user_context	= io_u;
	io_u->iocmd.comp_cb		= on_cmd_submit_comp;

	io_u->rsp->request		= req;
	io_u->rsp->user_context		= io_u;
	io_u->rsp->out.data_iovlen	= 1;


	/* issues request to bs */
	retval = -xnbd_bs_cmd_submit(bs_dev, &io_u->iocmd);
	if (retval)
		goto reject;

	return 0;
reject:
	TAILQ_INSERT_TAIL(&pd->io_u_free_list, io_u, io_u_list);
	pd->io_u_free_nr++;
	msg_reset(&pd->rsp);

	ans.command	= XNBD_CMD_IO_SUBMIT;
	ans.data_len	= 0;
	ans.ret		= -1;
	ans.ret_errno	= retval;

	pack_u32((uint32_t *)&ans.ret_errno,
	pack_u32((uint32_t *)&ans.ret,
	pack_u32(&ans.data_len,
	pack_u32(&ans.command,
		 pd->rsp_hdr))));

	pd->rsp.out.header.iov_len = sizeof(struct xnbd_answer);
	pd->rsp.request = req;

	xio_send_response(&pd->rsp);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handle_submit_comp				                     */
/*---------------------------------------------------------------------------*/
static int xnbd_handle_submit_comp(void *prv_session_data,
				   void *prv_portal_data,
				   struct xio_msg *rsp)
{
	struct xnbd_io_portal_data *pd = prv_portal_data;
	struct xnbd_io_u	   *io_u = rsp->user_context;

	if (io_u) {
		rsp->out.data_iov[0].iov_base = io_u->buf;
		TAILQ_INSERT_TAIL(&pd->io_u_free_list, io_u, io_u_list);
		pd->io_u_free_nr++;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handler_on_req				                             */
/*---------------------------------------------------------------------------*/
int xnbd_handler_on_req(void *prv_session_data,
			 void *prv_portal_data,
			 struct xio_msg *req)
{
	char			*buffer = req->in.header.iov_base;
	char			*cmd_data;
	struct xnbd_command	cmd;
	int			disconnect = 0;


	if (buffer == NULL) {
		xnbd_reject_request(prv_session_data,
				    prv_portal_data,
				    &cmd, NULL,
				    req);
		return 1;
	}

	buffer = (char *)unpack_u32((uint32_t *)&cmd.command,
				    buffer);
	cmd_data = (char *)unpack_u32((uint32_t *)&cmd.data_len,
			      (char *)buffer);

	switch (cmd.command) {
	case XNBD_CMD_IO_SUBMIT:
		xnbd_handle_submit(prv_session_data,
				   prv_portal_data,
				   &cmd, cmd_data,
				   req);
		break;
	case XNBD_CMD_OPEN:
		xnbd_handle_open(prv_session_data,
				 prv_portal_data,
				 &cmd, cmd_data,
				 req);
		break;
	case XNBD_CMD_CLOSE:
		xnbd_handle_close(prv_session_data,
				  prv_portal_data,
				  &cmd, cmd_data,
				  req);
		break;
	case XNBD_CMD_FSTAT:
		xnbd_handle_fstat(prv_session_data,
				  prv_portal_data,
				  &cmd, cmd_data,
				  req);
		break;
	case XNBD_CMD_IO_SETUP:
		/* Once per Session */
		xnbd_handle_setup(prv_session_data,
				  prv_portal_data,
				  &cmd, cmd_data,
				  req);
		break;
	case XNBD_CMD_IO_DESTROY:
		xnbd_handle_destroy(prv_session_data,
				    prv_portal_data,
				    &cmd, cmd_data,
				    req);
		break;
	default:
		/*
		printf("unknown command %d len:%d, sn:%"PRIu64"\n",
		       cmd.command, cmd.data_len, req->sn);
		xio_disconnect(conn);
		*/
		xnbd_reject_request(prv_session_data,
				    prv_portal_data,
				    &cmd, cmd_data,
				    req);
		break;
	};
	return disconnect;
}

/*---------------------------------------------------------------------------*/
/* xnbd_handler_on_rsp_comp				                     */
/*---------------------------------------------------------------------------*/
void xnbd_handler_on_rsp_comp(void *prv_session_data,
			      void *prv_portal_data,
			      struct xio_msg *rsp)
{
	char			*buffer = rsp->out.header.iov_base;
	struct xnbd_command	cmd;

	unpack_u32(&cmd.command, buffer);

	switch (cmd.command) {
	case XNBD_CMD_IO_SUBMIT:
		xnbd_handle_submit_comp(prv_session_data,
					prv_portal_data,
					rsp);
		break;
	case XNBD_CMD_CLOSE:
	case XNBD_CMD_UNKNOWN:
	case XNBD_CMD_IO_DESTROY:
	case XNBD_CMD_OPEN:
	case XNBD_CMD_FSTAT:
	case XNBD_CMD_IO_SETUP:
		break;
	default:
		printf("unknown answer %d\n", cmd.command);
		break;

	};
}

