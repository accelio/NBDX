/*
 * Copyright (c) 2013 Mellanox Technologies��. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies�� BSD license
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
 *      - Neither the name of the Mellanox Technologies�� nor the names of its
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

#include "xnbd.h"

#define DRV_NAME	"xnbd"
#define PFX		DRV_NAME ": "
#define DRV_VERSION	"0.1"

MODULE_AUTHOR("Sagi Grimberg, Max Gurtovoy");
MODULE_DESCRIPTION("XIO network block device");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRV_VERSION);

int created_portals = 0;
static int xnbd_major;
static int xnbd_indexes; /* num of devices created*/
static int submit_queues;
static int hw_queue_depth = 64;
static LIST_HEAD(xnbd_file_list);
struct session_data *g_session_data[SUPPORTED_PORTALS];

static void msg_reset(struct xio_msg *msg)
{
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;
	msg->out.data_iovlen = 0;
	msg->out.header.iov_len = 0;
}

static int xnbd_rq_map_iov(struct request *rq, struct xio_vmsg *vmsg,
			  unsigned long long *len)
{
	struct bio_vec *bvec;
	struct req_iterator iter;
	int i = 0;

	if (XIO_MAX_IOV <= rq->bio->bi_vcnt) {
		pr_err("unsupported io vec size\n");
		return -ENOMEM;
	}

	*len = 0;
	rq_for_each_segment(bvec, rq, iter) {
		vmsg->data_iov[i].iov_base = page_address(bvec->bv_page) +
				bvec->bv_offset;
		vmsg->data_iov[i].iov_len =  bvec->bv_len;
		*len += vmsg->data_iov[i].iov_len;
		i++;
	}
	vmsg->data_iovlen = i;

	return 0;
}


static int xnbd_transfer(struct xnbd_file *xdev,
		  char *buffer,
		  unsigned long start,
		  unsigned long len,
		  int write,
		  struct request *req, //maybe should be the driver_data for end req
		  struct xnbd_queue *q)
{
	struct raio_io_u		*io_u;
	int cpu, retval = 0;

	pr_debug("%s called and req=%p\n", __func__, req);
	io_u = kzalloc(sizeof(*io_u), GFP_KERNEL);
	if (!io_u) {
		pr_err("io_u alloc fail\n");
		return -1;
	}
	msg_reset(&io_u->req);

	if (write) {
		raio_prep_pwrite(q->piocb, xdev->fd, start);
	}
	else
		raio_prep_pread(q->piocb, xdev->fd, start);

	if (!io_u->req.out.header.iov_base) {
		io_u->req.out.header.iov_base = kzalloc(SUBMIT_BLOCK_SIZE +
				sizeof(uint32_t) + sizeof(struct raio_command), GFP_KERNEL);
		if (!io_u->req.out.header.iov_base) {
			pr_err("io_u->req.out.header.iov_base alloc fail\n");
			return -1;
		}

	}

	pr_debug("%s,%d: start=0x%lx, len=0x%lx opcode=%d\n",
		 __func__, __LINE__, start, len, q->piocb->raio_lio_opcode);

	if (q->piocb->raio_lio_opcode == RAIO_CMD_PWRITE) {
		io_u->req.in.data_iovlen  = 0;
		retval = xnbd_rq_map_iov(req, &io_u->req.out,
				&q->piocb->u.c.nbytes);
		if (retval) {
			pr_err("failed to map io vec\n");
			kfree(io_u);
			return retval;
		}
	} else {
		io_u->req.out.data_iovlen = 0;
		retval = xnbd_rq_map_iov(req, &io_u->req.in,
				&q->piocb->u.c.nbytes);
		if (retval) {
			pr_err("failed to map io vec\n");
			kfree(io_u);
			return retval;
		}
	}

	pack_submit_command(q->piocb, 1, io_u->req.out.header.iov_base,
			    &io_u->req.out.header.iov_len);

	io_u->req.user_context = io_u;
	io_u->iocb = q->piocb;
	io_u->breq = req; //needed for on answer to do blk_mq_end_io(breq, 0);

	pr_debug("sending req on cpu=%d\n", q->conn_data->cpu_id);
	cpu = get_cpu();
	xio_send_request(q->conn_data->conn, &io_u->req);
	put_cpu();

	return 0;
}

static struct blk_mq_hw_ctx *xnbd_alloc_hctx(struct blk_mq_reg *reg, unsigned int hctx_index)
{

	int b_size = DIV_ROUND_UP(reg->nr_hw_queues, nr_online_nodes);
	int tip = (reg->nr_hw_queues % nr_online_nodes);
	int node = 0, i, n;
	struct blk_mq_hw_ctx * hctx;

	pr_debug("%s called\n", __func__);
	pr_debug("hctx_index=%u, b_size=%d, tip=%d, nr_online_nodes=%d\n",
		 hctx_index, b_size, tip, nr_online_nodes);
	/*
	 * Split submit queues evenly wrt to the number of nodes. If uneven,
	 * fill the first buckets with one extra, until the rest is filled with
	 * no extra.
	 */
	for (i = 0, n = 1; i < hctx_index; i++, n++) {
		if (n % b_size == 0) {
			n = 0;
			node++;

			tip--;
			if (!tip)
				b_size = reg->nr_hw_queues / nr_online_nodes;
		}
	}

	/*
	 * A node might not be online, therefore map the relative node id to the
	 * real node id.
	 */
	for_each_online_node(n) {
		if (!node)
			break;
		node--;
	}
	pr_debug("%s: n=%d\n", __func__, n);
	hctx = kzalloc_node(sizeof(struct blk_mq_hw_ctx), GFP_KERNEL, n);
	return hctx;
}

static void xnbd_free_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_index)
{
	pr_debug("%s called\n", __func__);
	kfree(hctx);
}

static int xnbd_request(struct request *req, struct xnbd_queue *xq)
{

	struct xnbd_file *xdev;
	unsigned long start = blk_rq_pos(req) << XNBD_SECT_SHIFT;
	unsigned long len  = blk_rq_cur_bytes(req);
	int write = rq_data_dir(req) == WRITE;
	int err;

	pr_debug("%s called\n", __func__);

	xdev = req->rq_disk->private_data;

	if (!req->buffer) {
		pr_err("%s: req->buffer is NULL\n", __func__);
		return 0;
	}

	err = xnbd_transfer(xdev, req->buffer, start, len, write, req, xq);
	if (unlikely(err))
		pr_err("transfer failed for req %p\n", req);

	return err;

}

static int xnbd_queue_rq(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	struct xnbd_queue *xnbd_q;
	int err;

	pr_debug("%s called\n", __func__);
	xnbd_q = hctx->driver_data;
	err = xnbd_request(rq, xnbd_q);

	if (err)
		return err;
	else
		return BLK_MQ_RQ_QUEUE_OK;
}

static int xnbd_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			  unsigned int index)
{
	struct xnbd_file *xdev = data;
	struct xnbd_queue *xq;

	pr_debug("%s called index=%u\n", __func__, index);

	xq = &xdev->queues[index];
	pr_debug("%s called xq=%p\n", __func__, xq);
	xq->conn_data = xdev->conn_data[index];
	xq->xdev = xdev;
	xq->queue_depth = xdev->queue_depth;
	xq->piocb = kzalloc(sizeof(*xq->piocb), GFP_KERNEL);
	hctx->driver_data = xq;
	//xnbd_init_queue(xdev, xq);

	return 0;
}

static struct blk_mq_ops xnbd_mq_ops = {
	.queue_rq       = xnbd_queue_rq,
	.map_queue      = blk_mq_map_queue,
	.init_hctx	= xnbd_init_hctx,
	.alloc_hctx	= xnbd_alloc_hctx,
	.free_hctx	= xnbd_free_hctx,
};

static struct blk_mq_reg xnbd_mq_reg = {
	.ops		= &xnbd_mq_ops,
	.cmd_size	= 0, // TBD sizeof(struct xnbd_cmd),
	.flags		= BLK_MQ_F_SHOULD_MERGE,
	.numa_node	= NUMA_NO_NODE,
};

#if 0
static struct xnbd_file *xnbd_file_find(int fd)
{
	struct xnbd_file *pos;
	struct xnbd_file *ret = NULL;

	list_for_each_entry(pos, &xnbd_file_list, list) {
		if (pos->fd == fd) {
			ret = pos;
			break;
		}
	}
	return ret;
}
#endif

/*---------------------------------------------------------------------------*/
/* on_submit_answer							     */
/*---------------------------------------------------------------------------*/
static void on_submit_answer(struct xio_msg *rsp)
{
	struct raio_io_u	*io_u;
	struct request *breq;

	io_u = rsp->user_context;

	io_u->rsp = rsp;
	breq = io_u->breq;

	pr_debug("%s: Got submit response\n", __func__);
	unpack_u32((uint32_t *)&io_u->res2,
	unpack_u32((uint32_t *)&io_u->res,
	unpack_u32((uint32_t *)&io_u->ans.ret_errno,
	unpack_u32((uint32_t *)&io_u->ans.ret,
	unpack_u32(&io_u->ans.data_len,
	unpack_u32(&io_u->ans.command,
		   io_u->rsp->in.header.iov_base))))));


	pr_debug("fd=%d, res=%x, res2=%x, ans.ret=%d, ans.ret_errno=%d\n",
			io_u->iocb->raio_fildes, io_u->res, io_u->res2,
			io_u->ans.ret, io_u->ans.ret_errno);

	if (io_u->breq)
		blk_mq_end_io(io_u->breq, io_u->ans.ret);
	else
		pr_err("%s: Got NULL request in response\n", __func__);
}

/*---------------------------------------------------------------------------*/
/* on_response								     */
/*---------------------------------------------------------------------------*/
static int on_response(struct xio_session *session,
		       struct xio_msg *rsp,
		       int more_in_batch,
		       void *cb_user_context)
{
	struct blk_connection_data *conn_data = cb_user_context;
	uint32_t command;

	unpack_u32(&command, rsp->in.header.iov_base);
	printk("message: [%llu] - %s\n",
			(rsp->request->sn + 1), (char *)rsp->in.header.iov_base);

	switch (command) {
	case RAIO_CMD_IO_SUBMIT:
		on_submit_answer(rsp);
		xio_release_response(rsp);
		break;
	case RAIO_CMD_OPEN:
	case RAIO_CMD_FSTAT:
	//case RAIO_CMD_CLOSE:
	case RAIO_CMD_IO_SETUP:
	//case RAIO_CMD_IO_DESTROY:
		/* break the loop */
		conn_data->rsp = rsp;
		conn_data->wq_flag = 1;
		wake_up_interruptible(&conn_data->wq);
		break;
	default:
		printk("on_response: unknown answer %d\n", command);
		break;
	};

	return 0;
}


/*---------------------------------------------------------------------------*/
/* on_session_event							     */
/*---------------------------------------------------------------------------*/
static int on_session_event(struct xio_session *session,
		struct xio_session_event_data *event_data,
		void *cb_user_context)
{
	struct session_data *session_data = cb_user_context;
	struct blk_connection_data *conn_data;
	struct xio_connection	*conn = event_data->conn;
	int i;

	printk("session event: %s\n",
	       xio_session_event_str(event_data->event));

	switch (event_data->event) {
	case XIO_SESSION_TEARDOWN_EVENT:
		session_data->session = NULL;
		xio_session_destroy(session);
		for (i = 0; i < submit_queues; i++) {
			conn_data = session_data->conn_data[i];
			xio_context_stop_loop(conn_data->ctx); /* exit */
		}
		break;
	case XIO_SESSION_CONNECTION_TEARDOWN_EVENT:
		printk("destroying connection: %p\n", conn);
		xio_connection_destroy(conn);

		break;
	case XIO_SESSION_CONNECTION_DISCONNECTED_EVENT:
		break;
	default:
		break;
	};

	return 0;
}


/*---------------------------------------------------------------------------*/
/* callbacks								     */
/*---------------------------------------------------------------------------*/
struct xio_session_ops xnbd_ses_ops = {
	.on_session_event		=  on_session_event,
	.on_session_established		=  NULL,
	.on_msg				=  on_response,
	.on_msg_error			=  NULL
};

static int xnbd_open(struct block_device *bd, fmode_t mode)
{
	pr_debug("%s called\n", __func__);
	return 0;
}

static void xnbd_release(struct gendisk *gd, fmode_t mode)
{
	pr_debug("%s called\n", __func__);
}

static int xnbd_media_changed(struct gendisk *gd)
{
	pr_debug("%s called\n", __func__);
	return 0;
}

static int xnbd_revalidate(struct gendisk *gd)
{
	pr_debug("%s called\n", __func__);
	return 0;
}

static int xnbd_ioctl(struct block_device *bd, fmode_t mode,
		      unsigned cmd, unsigned long arg)
{
	pr_debug("%s called\n", __func__);
	return -ENOTTY;
}


static struct block_device_operations xnbd_ops = {
	.owner           = THIS_MODULE,
	.open 	         = xnbd_open,
	.release 	 = xnbd_release,
	.media_changed   = xnbd_media_changed,
	.revalidate_disk = xnbd_revalidate,
	.ioctl	         = xnbd_ioctl
};

static void xnbd_destroy_queues(struct xnbd_file *xdev)
{
	pr_debug("%s called\n", __func__);

	kfree(xdev->queues);
}

static int xnbd_setup_queues(struct xnbd_file *xdev)
{
	pr_debug("%s called\n", __func__);
	xdev->queues = kzalloc(submit_queues * sizeof(*xdev->queues),
			GFP_KERNEL);
	if (!xdev->queues)
		return -ENOMEM;

	return 0;
}

static int xnbd_register_block_device(struct xnbd_file *xnbd_file)
{
	sector_t size = xnbd_file->stbuf.st_size;

	pr_debug("%s called\n", __func__);

	xnbd_mq_reg.queue_depth = hw_queue_depth;
	xnbd_mq_reg.nr_hw_queues = submit_queues;
	xnbd_file->major = xnbd_major;

	xnbd_file->queue = blk_mq_init_queue(&xnbd_mq_reg, xnbd_file);
	if (IS_ERR(xnbd_file->queue)) {
		pr_err("%s: Failed to allocate blk queue ret=%ld\n",
		       __func__, PTR_ERR(xnbd_file->queue));
		return PTR_ERR(xnbd_file->queue);
	}

	xnbd_file->queue->queuedata = xnbd_file;
	queue_flag_set_unlocked(QUEUE_FLAG_NONROT, xnbd_file->queue);

	xnbd_file->disk = alloc_disk_node(1, NUMA_NO_NODE);
	if (!xnbd_file->disk) {
		blk_cleanup_queue(xnbd_file->queue);
		pr_err("%s: Failed to allocate disk node\n", __func__);
		return -ENOMEM;
	}

	xnbd_file->disk->major = xnbd_file->major;
	xnbd_file->disk->first_minor = xnbd_file->index;
	xnbd_file->disk->fops = &xnbd_ops;
	xnbd_file->disk->queue = xnbd_file->queue;
	xnbd_file->disk->private_data = xnbd_file;
	blk_queue_logical_block_size(xnbd_file->queue, XNBD_SECT_SIZE);
	blk_queue_physical_block_size(xnbd_file->queue, XNBD_SECT_SIZE);
	sector_div(size, XNBD_SECT_SIZE);
	set_capacity(xnbd_file->disk, size);
	sprintf(xnbd_file->disk->disk_name, "xnbd%d", xnbd_file->index);
	add_disk(xnbd_file->disk);

	return 0;
}

static int xnbd_setup_remote_device(struct session_data *blk_session_data,
				    struct xnbd_file *xnbd_file)
{

	int retval, cpu;
	struct blk_connection_data *conn_data;

	cpu = get_cpu();
	conn_data = blk_session_data->conn_data[cpu];

	msg_reset(&conn_data->req);
	pack_setup_command(xnbd_file->fd, xnbd_file->queue_depth,
			   conn_data->req.out.header.iov_base,
			   &conn_data->req.out.header.iov_len);

	conn_data->req.out.data_iovlen = 0;

	xio_send_request(conn_data->conn, &conn_data->req);
	put_cpu();

	pr_debug("%s: before waiting for event\n", __func__);
	wait_event_interruptible(conn_data->wq, conn_data->wq_flag != 0);
	pr_debug("%s: after waiting for event\n", __func__);
	conn_data->wq_flag = 0;

	retval = unpack_setup_answer(conn_data->rsp->in.header.iov_base,
				     conn_data->rsp->in.header.iov_len);
	if (retval)
		pr_err("Failed to unpack setup answer, ret=%d\n", retval);

	pr_debug("after unpacking setup_answer\n");

	/* acknowlege xio that response is no longer needed */
	xio_release_response(conn_data->rsp);

	return retval;

}

static int xnbd_stat_remote_device(struct session_data *blk_session_data,
				   struct xnbd_file *xnbd_file)
{
	struct blk_connection_data *conn_data;
	int retval, cpu;

	cpu = get_cpu();
	conn_data = blk_session_data->conn_data[cpu];

	msg_reset(&conn_data->req);
	pack_fstat_command(xnbd_file->fd,
			   conn_data->req.out.header.iov_base,
			   &conn_data->req.out.header.iov_len);

	xio_send_request(conn_data->conn, &conn_data->req);
	put_cpu();

	pr_debug("%s: before wait_event_interruptible\n", __func__);
	wait_event_interruptible(conn_data->wq, conn_data->wq_flag != 0);
	pr_debug("%s: after wait_event_interruptible\n", __func__);
	conn_data->wq_flag = 0;

	retval = unpack_fstat_answer(conn_data->rsp->in.header.iov_base,
				     conn_data->rsp->in.header.iov_len,
				     &xnbd_file->stbuf);
	if (retval) {
		pr_err("failed fstat ret=%d\n", retval);
		return retval;
	}

	pr_debug("after unpacking fstat response file_size=%llx bytes\n",
		 xnbd_file->stbuf.st_size);

	/* acknowlege xio that response is no longer needed */
	xio_release_response(conn_data->rsp);

	return 0;
}

static int xnbd_open_remote_device(struct session_data *session_data,
				   struct xnbd_file *xnbd_file)
{
	struct blk_connection_data *conn_data;
	int retval, cpu;

	cpu = get_cpu();
	conn_data = session_data->conn_data[cpu];
	msg_reset(&conn_data->req);
	pack_open_command(xnbd_file->file_name, O_RDWR,
			  conn_data->req.out.header.iov_base,
			  &conn_data->req.out.header.iov_len);

	retval = xio_send_request(conn_data->conn, &conn_data->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("open file: before wait_event_interruptible\n");
	wait_event_interruptible(conn_data->wq, conn_data->wq_flag != 0);
	pr_debug("open file: after wait_event_interruptible\n");
	conn_data->wq_flag = 0;

	retval = unpack_open_answer(conn_data->rsp->in.header.iov_base,
				    conn_data->rsp->in.header.iov_len,
				    &xnbd_file->fd);
	if (retval) {
		pr_err("failed to open remote device ret=%d\n", retval);
		return retval;
	}

	xio_release_response(conn_data->rsp);
	pr_debug("after unpacking response fd=%d\n", xnbd_file->fd);

	return 0;
}

int xnbd_create_device(struct session_data *blk_session_data,
		       const char *xdev_name)
{
	struct xnbd_file *xnbd_file;
	int retval;

	xnbd_file = kzalloc(sizeof(*xnbd_file), GFP_KERNEL);
	if (!xnbd_file) {
		printk("xnbd_file alloc failed\n");
		return -ENOMEM;
	}

	sscanf(xdev_name, "%s", xnbd_file->file_name);
	list_add(&xnbd_file->list, &blk_session_data->drive_list);
	xnbd_file->index = xnbd_indexes++;
	xnbd_file->nr_queues = submit_queues;
	xnbd_file->queue_depth = hw_queue_depth;
	xnbd_file->conn_data = blk_session_data->conn_data;

	retval = xnbd_setup_queues(xnbd_file);
	if (retval) {
		pr_err("%s: xnbd_setup_queues failed\n", __func__);
		goto err_file;
	}

	retval = xnbd_open_remote_device(blk_session_data, xnbd_file);
	if (retval) {
		pr_err("failed to open remote device ret=%d\n", retval);
		goto err_queues;
	}

	retval = xnbd_stat_remote_device(blk_session_data, xnbd_file);
	if (retval) {
		pr_err("failed to stat remote device %s ret=%d\n",
		       xnbd_file->file_name, retval);
		goto err_queues;
	}

	retval = xnbd_setup_remote_device(blk_session_data, xnbd_file);
	if (retval) {
		pr_err("failed to setup remote device %s ret=%d\n",
		       xnbd_file->file_name, retval);
		goto err_queues;
	}

	retval = xnbd_register_block_device(xnbd_file);
	if (retval) {
		pr_err("failed to register xnbd device %s ret=%d\n",
		       xnbd_file->file_name, retval);
		goto err_queues;
	}

	return 0;

err_queues:
	xnbd_destroy_queues(xnbd_file);
err_file:
	kfree(xnbd_file);
	return retval;
}


static int xnbd_connect_work(void *data)
{
	struct blk_connection_data *conn_data = data;

	pr_info("%s: start connect work on cpu %d\n", __func__,
		conn_data->cpu_id);

	memset(&conn_data->req, 0, sizeof(conn_data->req));
	conn_data->req.out.header.iov_base = kmalloc(MAX_MSG_LEN, GFP_KERNEL);
	conn_data->req.out.header.iov_len = MAX_MSG_LEN;
	conn_data->req.out.data_iovlen = 0;

	init_waitqueue_head(&conn_data->wq);
	conn_data->wq_flag = 0;

	conn_data->ctx = xio_context_create(XIO_LOOP_GIVEN_THREAD, NULL, current, 0, conn_data->cpu_id);
	if (!conn_data->ctx) {
		printk("context open failed\n");
		return 1;
	}
	pr_info("cpu %d: context established ctx=%p\n",
		conn_data->cpu_id, conn_data->ctx);

	conn_data->conn = xio_connect(conn_data->session, conn_data->ctx, 0,
			NULL, conn_data);
	if (!conn_data->conn){
		printk("connection open failed\n");
		xio_context_destroy(conn_data->ctx);
		return 1;
	}
	pr_info("cpu %d: connection established conn=%p\n",
		conn_data->cpu_id, conn_data->conn);

	/* the default xio supplied main loop */
	xio_context_run_loop(conn_data->ctx);
	return 0;
}

/**
 * destroy conn_data before waking up ktread task
 */
static void xnbd_destroy_conn_data(struct blk_connection_data *conn_data)
{
	struct task_struct *task = conn_data->conn_th;

	conn_data->session = NULL;
	conn_data->conn_th = NULL;
	kfree(task);
	kfree(conn_data);

}

int xnbd_session_create(const char *portal)
{
	struct session_data	*session_data;
	struct xio_session *session;
	int i,j;
	char name[50];

	/* client session attributes */
	struct xio_session_attr attr = {
		&xnbd_ses_ops, /* callbacks structure */
		NULL,	  /* no need to pass the server private data */
		0
	};

	session_data = kzalloc(sizeof(*session_data), GFP_KERNEL);
	if (!session_data) {
		printk("session_data alloc failed\n");
		return 1;
	}

	strcpy(session_data->portal, portal);
	/* connect to portal */
	session_data->session = xio_session_create(XIO_SESSION_CLIENT,
		     &attr, session_data->portal, 0, 0, session_data);

	if (!session_data->session)
			goto cleanup;

	INIT_LIST_HEAD(&session_data->drive_list);

	g_session_data[created_portals] = session_data;

	session_data->conn_data = kzalloc(submit_queues * sizeof(*session_data->conn_data),
					  GFP_KERNEL);
	if (!session_data->conn_data) {
		printk("session_data->conn_data alloc failed\n");
		goto cleanup1;
	}

	for (i = 0; i < submit_queues; i++) {
		session_data->conn_data[i] = kzalloc(sizeof(*session_data->conn_data[i]),
							    GFP_KERNEL);
		if (!session_data->conn_data[i]) {
			goto cleanup2;
	    }
		sprintf(name, "session thread %d", i);
		session_data->conn_data[i]->session = session_data->session;
		session_data->conn_data[i]->cpu_id = i;
		printk("opening thread on cpu %d\n", i);
		session_data->conn_data[i]->conn_th = kthread_create(xnbd_connect_work,
								     session_data->conn_data[i],
								     name);
		kthread_bind(session_data->conn_data[i]->conn_th, i);
	}

	/* kick all threads after verify all thread created properly*/
	for (i = 0; i < submit_queues; i++)
		wake_up_process(session_data->conn_data[i]->conn_th);

	return 0;

cleanup2:
	for (j = 0; j < i; j++) {
		xnbd_destroy_conn_data(session_data->conn_data[j]);
		session_data->conn_data[j] = NULL;
	}
	kfree(session_data->conn_data);

cleanup1:
	session = session_data->session;
	session_data->session = NULL;
	xio_session_destroy(session);

cleanup:
	kfree(session_data);

	return 1;

}

static int __init xnbd_init_module(void)
{
	if (xnbd_create_sysfs_files())
		return 1;

	pr_debug("nr_cpu_ids=%d, num_online_cpus=%d\n",
		 nr_cpu_ids, num_online_cpus());
	submit_queues = num_online_cpus();

	xnbd_major = register_blkdev(0, "xnbd");
	if (xnbd_major < 0)
		return xnbd_major;

	return 0;
}

static void __exit xnbd_cleanup_module(void)
{
	int i;

	unregister_blkdev(xnbd_major, "xnbd");

	for (i=0; i < created_portals; i++){
		xnbd_destroy_portal_file(i);
	}

	xnbd_destroy_sysfs_files();

}

module_init(xnbd_init_module);
module_exit(xnbd_cleanup_module);
