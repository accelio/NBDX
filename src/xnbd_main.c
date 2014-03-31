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
int xnbd_major;
int xnbd_indexes; /* num of devices created*/
int submit_queues;
struct list_head g_xnbd_sessions;
struct mutex g_lock;

static void msg_reset(struct xio_msg *msg)
{
	msg->in.header.iov_base = NULL;
	msg->in.header.iov_len = 0;
	msg->in.data_iovlen = 0;
	msg->out.data_iovlen = 0;
	msg->out.header.iov_len = 0;
}

static inline int xnbd_set_device_state(struct xnbd_file *xdev,
					enum xnbd_dev_state state)
{
	int ret = 0;

	spin_lock(&xdev->state_lock);
	switch (state) {
	case DEVICE_OPENNING:
		if (xdev->state == DEVICE_OFFLINE ||
		    xdev->state == DEVICE_RUNNING) {
			ret = -EINVAL;
			goto out;
		}
		xdev->state = state;
		break;
	case DEVICE_RUNNING:
		xdev->state = state;
		break;
	case DEVICE_OFFLINE:
		xdev->state = state;
		break;
	default:
		pr_err("Unknown device state %d\n", state);
		ret = -EINVAL;
	}
out:
	spin_unlock(&xdev->state_lock);
	return ret;
}

int xnbd_transfer(struct xnbd_file *xdev, char *buffer, unsigned long start,
		  unsigned long len, int write, struct request *req,
		  struct xnbd_queue *q)
{
	struct raio_io_u *io_u = req->special;
	struct xnbd_connection *xnbd_conn = q->xnbd_conn;
	int cpu, retval = 0;

	pr_debug("%s called and req=%p\n", __func__, req);

	msg_reset(&io_u->req);

	if (write)
		raio_prep_pwrite(&io_u->iocb, xdev->fd, start);
	else
		raio_prep_pread(&io_u->iocb, xdev->fd, start);

	pr_debug("%s,%d: start=0x%lx, len=0x%lx opcode=%d\n",
		 __func__, __LINE__, start, len, io_u->iocb.raio_lio_opcode);

	if (io_u->iocb.raio_lio_opcode == RAIO_CMD_PWRITE) {
		io_u->req.in.data_iovlen  = 0;
		retval = xnbd_rq_map_iov(req, &io_u->req.out,
					 &io_u->iocb.u.c.nbytes);
		if (retval) {
			pr_err("failed to map io vec\n");
			goto err;
		}
	} else {
		io_u->req.out.data_iovlen = 0;
		retval = xnbd_rq_map_iov(req, &io_u->req.in,
					 &io_u->iocb.u.c.nbytes);
		if (retval) {
			pr_err("failed to map io vec\n");
			goto err;
		}
	}

	pack_submit_command(&io_u->iocb, 1, io_u->req_hdr,
			    &io_u->req.out.header.iov_len);
	io_u->req.out.header.iov_base = io_u->req_hdr;
	io_u->req.user_context = io_u;
	io_u->breq = req;

	cpu = get_cpu();
	pr_debug("sending req on cpu=%d\n", xnbd_conn->cpu_id);
	retval = xio_send_request(xnbd_conn->conn, &io_u->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		goto err;
	}

err:
	return retval;
}

struct xnbd_file *xnbd_file_find(struct xnbd_session *xnbd_session,
				 const char *xdev_name)
{
	struct xnbd_file *pos;
	struct xnbd_file *ret = NULL;

	spin_lock(&xnbd_session->devs_lock);
	list_for_each_entry(pos, &xnbd_session->devs_list, list) {
		if (!strcmp(pos->file_name, xdev_name)) {
			ret = pos;
			break;
		}
	}
	spin_unlock(&xnbd_session->devs_lock);

	return ret;
}

struct xnbd_session *xnbd_session_find(struct list_head *s_data_list,
                                       const char *host_name)
{
	struct xnbd_session *pos;
	struct xnbd_session *ret = NULL;

	list_for_each_entry(pos, s_data_list, list) {
		if (!strcmp(pos->kobj.name, host_name)) {
			ret = pos;
			break;
		}
	}

	return ret;
}

struct xnbd_session *xnbd_session_find_by_portal(struct list_head *s_data_list,
						 const char *portal)
{
	struct xnbd_session *pos;
	struct xnbd_session *ret = NULL;

	mutex_lock(&g_lock);
	list_for_each_entry(pos, s_data_list, list) {
		if (!strcmp(pos->portal, portal)) {
			ret = pos;
			break;
		}
	}
	mutex_unlock(&g_lock);

	return ret;
}

/*---------------------------------------------------------------------------*/
/* on_submit_answer							     */
/*---------------------------------------------------------------------------*/
static void on_submit_answer(struct xnbd_connection *xnbd_conn,
			     struct xio_msg *rsp)
{
	struct raio_io_u *io_u;
	struct request *breq;
	int ret;

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
			io_u->iocb.raio_fildes, io_u->res, io_u->res2,
			io_u->ans.ret, io_u->ans.ret_errno);

	ret = -io_u->ans.ret;
	if (ret) {
		struct xnbd_file *xdev = io_u->breq->rq_disk->private_data;

		pr_err("error response on xdev %s ret=%d\n", xdev->dev_name,
							     ret);
		xnbd_set_device_state(xdev, DEVICE_OFFLINE);
	}

	if (breq)
		blk_mq_end_io(breq, ret);
	else
		pr_err("%s: Got NULL request in response\n", __func__);

	xio_release_response(rsp);
}

/*---------------------------------------------------------------------------*/
/* on_response								     */
/*---------------------------------------------------------------------------*/
static int on_response(struct xio_session *session,
		       struct xio_msg *rsp,
		       int more_in_batch,
		       void *cb_user_context)
{
	struct xnbd_connection *xnbd_conn = cb_user_context;
	uint32_t command;

	unpack_u32(&command, rsp->in.header.iov_base);
	pr_debug("message: [%llu] - %s\n",
			(rsp->request->sn + 1), (char *)rsp->in.header.iov_base);

	switch (command) {
	case RAIO_CMD_IO_SUBMIT:
		on_submit_answer(xnbd_conn, rsp);
		break;
	case RAIO_CMD_OPEN:
	case RAIO_CMD_FSTAT:
	//case RAIO_CMD_CLOSE:
	case RAIO_CMD_IO_SETUP:
	//case RAIO_CMD_IO_DESTROY:
		/* break the loop */
		xnbd_conn->rsp = rsp;
		xnbd_conn->wq_flag = 1;
		wake_up_interruptible(&xnbd_conn->wq);
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
	struct xnbd_session *xnbd_session = cb_user_context;
	struct xnbd_connection *xnbd_conn;
	struct xio_connection	*conn = event_data->conn;
	int i;

	printk("session event: %s\n",
	       xio_session_event_str(event_data->event));

	switch (event_data->event) {
	case XIO_SESSION_CONNECTION_ESTABLISHED_EVENT:
		pr_debug("%s: connection=%p established\n", __func__, conn);
		if (atomic_dec_and_test(&xnbd_session->conns_count)) {
			pr_debug("%s: last connection established\n", __func__);
			complete(&xnbd_session->conns_wait);
		}
		break;
	case XIO_SESSION_TEARDOWN_EVENT:
		xnbd_session->session = NULL;
		xio_session_destroy(session);
		for (i = 0; i < submit_queues; i++) {
			xnbd_conn = xnbd_session->xnbd_conns[i];
			xio_context_stop_loop(xnbd_conn->ctx); /* exit */
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

const char *xnbd_device_state_str(struct xnbd_file *dev)
{
	char *state;

	spin_lock(&dev->state_lock);
	switch (dev->state) {
	case 0:
		state = "Initial state";
		break;
	case DEVICE_OPENNING:
		state = "openning";
		break;
	case DEVICE_RUNNING:
		state = "running";
		break;
	case DEVICE_OFFLINE:
		state = "offline";
		break;
	default:
		state = "unknown device state";
	}
	spin_unlock(&dev->state_lock);

	return state;
}

static int xnbd_setup_remote_device(struct xnbd_session *xnbd_session,
				    struct xnbd_file *xnbd_file)
{

	int retval, cpu;
	struct xnbd_connection *xnbd_conn;

	cpu = get_cpu();
	xnbd_conn = xnbd_session->xnbd_conns[cpu];

	msg_reset(&xnbd_conn->req);
	pack_setup_command(xnbd_file->fd, xnbd_file->queue_depth,
			   xnbd_conn->req.out.header.iov_base,
			   &xnbd_conn->req.out.header.iov_len);

	xnbd_conn->req.out.data_iovlen = 0;

	retval = xio_send_request(xnbd_conn->conn, &xnbd_conn->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("%s: before waiting for event\n", __func__);
	wait_event_interruptible(xnbd_conn->wq, xnbd_conn->wq_flag != 0);
	pr_debug("%s: after waiting for event\n", __func__);
	xnbd_conn->wq_flag = 0;

	retval = unpack_setup_answer(xnbd_conn->rsp->in.header.iov_base,
				     xnbd_conn->rsp->in.header.iov_len);
	if (retval == -EINVAL)
		pr_err("failed to unpack setup response");

	pr_debug("after unpacking setup_answer\n");

	/* acknowlege xio that response is no longer needed */
	xio_release_response(xnbd_conn->rsp);

	return retval;

}

static int xnbd_stat_remote_device(struct xnbd_session *xnbd_session,
				   struct xnbd_file *xnbd_file)
{
	struct xnbd_connection *xnbd_conn;
	int retval, cpu;

	cpu = get_cpu();
	xnbd_conn = xnbd_session->xnbd_conns[cpu];

	msg_reset(&xnbd_conn->req);
	pack_fstat_command(xnbd_file->fd,
			   xnbd_conn->req.out.header.iov_base,
			   &xnbd_conn->req.out.header.iov_len);

	retval = xio_send_request(xnbd_conn->conn, &xnbd_conn->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("%s: before wait_event_interruptible\n", __func__);
	wait_event_interruptible(xnbd_conn->wq, xnbd_conn->wq_flag != 0);
	pr_debug("%s: after wait_event_interruptible\n", __func__);
	xnbd_conn->wq_flag = 0;

	retval = unpack_fstat_answer(xnbd_conn->rsp->in.header.iov_base,
				     xnbd_conn->rsp->in.header.iov_len,
				     &xnbd_file->stbuf);
	if (retval == -EINVAL)
		pr_err("failed to unpack fstat response\n");

	pr_debug("after unpacking fstat response file_size=%llx bytes\n",
		 xnbd_file->stbuf.st_size);

	/* acknowlege xio that response is no longer needed */
	xio_release_response(xnbd_conn->rsp);

	return retval;
}

static int xnbd_open_remote_device(struct xnbd_session *xnbd_session,
				   struct xnbd_file *xnbd_file)
{
	struct xnbd_connection *xnbd_conn;
	int retval, cpu;

	cpu = get_cpu();
	xnbd_conn = xnbd_session->xnbd_conns[cpu];
	msg_reset(&xnbd_conn->req);
	pack_open_command(xnbd_file->file_name, O_RDWR,
			  xnbd_conn->req.out.header.iov_base,
			  &xnbd_conn->req.out.header.iov_len);

	retval = xio_send_request(xnbd_conn->conn, &xnbd_conn->req);
	put_cpu();
	if (retval) {
		pr_err("failed xio_send_request ret=%d\n", retval);
		return retval;
	}

	pr_debug("open file: before wait_event_interruptible\n");
	wait_event_interruptible(xnbd_conn->wq, xnbd_conn->wq_flag != 0);
	pr_debug("open file: after wait_event_interruptible\n");
	xnbd_conn->wq_flag = 0;

	retval = unpack_open_answer(xnbd_conn->rsp->in.header.iov_base,
				    xnbd_conn->rsp->in.header.iov_len,
				    &xnbd_file->fd);
	if (retval == -EINVAL)
		pr_err("failed to unpack open response\n");

	xio_release_response(xnbd_conn->rsp);

	return retval;
}

int xnbd_create_device(struct xnbd_session *xnbd_session,
					   const char *xdev_name, struct kobject *p_kobj)
{
	struct xnbd_file *xnbd_file;
	int retval;

	xnbd_file = kzalloc(sizeof(*xnbd_file), GFP_KERNEL);
	if (!xnbd_file) {
		printk("xnbd_file alloc failed\n");
		return -ENOMEM;
	}

	sscanf(xdev_name, "%s", xnbd_file->file_name);
	xnbd_file->index = xnbd_indexes++;
	sprintf(xnbd_file->dev_name, "xnbd%d", xnbd_file->index);
	xnbd_file->nr_queues = submit_queues;
	xnbd_file->queue_depth = XNBD_QUEUE_DEPTH;
	xnbd_file->xnbd_conns = xnbd_session->xnbd_conns;

	spin_lock_init(&xnbd_file->state_lock);
	retval = xnbd_set_device_state(xnbd_file, DEVICE_OPENNING);
	if (retval) {
		pr_err("device %s: Illegal state transition %s -> openning\n",
		       xnbd_file->dev_name,
		       xnbd_device_state_str(xnbd_file));
		kfree(xnbd_file);
		goto err;
	}

	retval = xnbd_create_device_files(p_kobj, xnbd_file->dev_name, &xnbd_file->kobj);
	if (retval) {
		pr_err("failed to create sysfs for device %s\n",
		       xnbd_file->dev_name);
		goto err;
	}

	retval = xnbd_setup_queues(xnbd_file);
	if (retval) {
		pr_err("%s: xnbd_setup_queues failed\n", __func__);
		goto err_put;
	}

	retval = xnbd_open_remote_device(xnbd_session, xnbd_file);
	if (retval) {
		pr_err("failed to open remote device ret=%d\n", retval);
		goto err_queues;
	}

	retval = xnbd_stat_remote_device(xnbd_session, xnbd_file);
	if (retval) {
		pr_err("failed to stat remote device %s ret=%d\n",
		       xnbd_file->file_name, retval);
		goto err_queues;
	}

	retval = xnbd_setup_remote_device(xnbd_session, xnbd_file);
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

	xnbd_set_device_state(xnbd_file, DEVICE_RUNNING);

	spin_lock(&xnbd_session->devs_lock);
	list_add(&xnbd_file->list, &xnbd_session->devs_list);
	spin_unlock(&xnbd_session->devs_lock);

	return 0;

err_queues:
	xnbd_destroy_queues(xnbd_file);
err_put:
	xnbd_destroy_kobj(&xnbd_file->kobj);
err:
	return retval;
}

void xnbd_destroy_device(struct xnbd_session *xnbd_session,
                         struct xnbd_file *xnbd_file)
{
	pr_debug("%s\n", __func__);

	xnbd_unregister_block_device(xnbd_file);

	xnbd_destroy_queues(xnbd_file);

	spin_lock(&xnbd_session->devs_lock);
	list_del(&xnbd_file->list);
	spin_unlock(&xnbd_session->devs_lock);

}

static void xnbd_destroy_session_devices(struct xnbd_session *xnbd_session)
{
	struct xnbd_file *xdev, *tmp;

	list_for_each_entry_safe(xdev, tmp, &xnbd_session->devs_list, list) {
		xnbd_destroy_device(xnbd_session, xdev);
		xnbd_destroy_kobj(&xdev->kobj);
	}
}

static int xnbd_connect_work(void *data)
{
	struct xnbd_connection *xnbd_conn = data;

	pr_info("%s: start connect work on cpu %d\n", __func__,
		xnbd_conn->cpu_id);

	memset(&xnbd_conn->req, 0, sizeof(xnbd_conn->req));
	xnbd_conn->req.out.header.iov_base = kmalloc(MAX_MSG_LEN, GFP_KERNEL);
	xnbd_conn->req.out.header.iov_len = MAX_MSG_LEN;
	xnbd_conn->req.out.data_iovlen = 0;

	init_waitqueue_head(&xnbd_conn->wq);
	xnbd_conn->wq_flag = 0;

	xnbd_conn->ctx = xio_context_create(XIO_LOOP_GIVEN_THREAD, NULL, current, 0, xnbd_conn->cpu_id);
	if (!xnbd_conn->ctx) {
		printk("context open failed\n");
		return 1;
	}
	pr_info("cpu %d: context established ctx=%p\n",
		xnbd_conn->cpu_id, xnbd_conn->ctx);

	xnbd_conn->conn = xio_connect(xnbd_conn->session, xnbd_conn->ctx, 0,
			NULL, xnbd_conn);
	if (!xnbd_conn->conn){
		printk("connection open failed\n");
		xio_context_destroy(xnbd_conn->ctx);
		return 1;
	}
	pr_info("cpu %d: connection established conn=%p\n",
		xnbd_conn->cpu_id, xnbd_conn->conn);

	/* the default xio supplied main loop */
	xio_context_run_loop(xnbd_conn->ctx);
	return 0;
}

/**
 * destroy xnbd_conn before waking up ktread task
 */
static void xnbd_destroy_conn(struct xnbd_connection *xnbd_conn)
{
	struct task_struct *task = xnbd_conn->conn_th;

	xnbd_conn->session = NULL;
	xnbd_conn->conn_th = NULL;
	kfree(task);
	kfree(xnbd_conn);
}

static int xnbd_create_conn(struct xnbd_session *xnbd_session, int cpu,
			    struct xnbd_connection **conn)
{
	struct xnbd_connection *xnbd_conn;
	char name[50];

	xnbd_conn = kzalloc(sizeof(*xnbd_conn), GFP_KERNEL);
	if (!xnbd_conn) {
		pr_err("failed to allocate xnbd_conn");
		return -ENOMEM;
	}

	sprintf(name, "session thread %d", cpu);
	xnbd_conn->session = xnbd_session->session;
	xnbd_conn->cpu_id = cpu;

	pr_debug("opening thread on cpu %d\n", cpu);
	xnbd_conn->conn_th = kthread_create(xnbd_connect_work, xnbd_conn, name);
	kthread_bind(xnbd_conn->conn_th, cpu);
	atomic_inc(&xnbd_session->conns_count);
	wake_up_process(xnbd_conn->conn_th);
	*conn = xnbd_conn;

	return 0;
}

int xnbd_session_create(const char *portal)
{
	struct xnbd_session *xnbd_session;
	int i, j, ret;

	/* client session attributes */
	struct xio_session_attr attr = {
		&xnbd_ses_ops, /* callbacks structure */
		NULL,	  /* no need to pass the server private data */
		0
	};

	xnbd_session = kzalloc(sizeof(*xnbd_session), GFP_KERNEL);
	if (!xnbd_session) {
		pr_err("failed to allocate xnbd session\n");
		return -ENOMEM;
	}

	ret = xnbd_create_portal_files(&xnbd_session->kobj);
	if (ret) {
		ret = -ENOMEM;
		goto err_sysfs;
	}

	strcpy(xnbd_session->portal, portal);
	xnbd_session->session = xio_session_create(XIO_SESSION_CLIENT,
		     &attr, xnbd_session->portal, 0, 0, xnbd_session);
	if (!xnbd_session->session) {
		pr_err("failed to create xio session\n");
		ret = -ENOMEM;
		goto err_free_session;
	}

	INIT_LIST_HEAD(&xnbd_session->devs_list);
	spin_lock_init(&xnbd_session->devs_lock);

	mutex_lock(&g_lock);
	list_add(&xnbd_session->list, &g_xnbd_sessions);
	created_portals++;
	mutex_unlock(&g_lock);

	xnbd_session->xnbd_conns = kzalloc(submit_queues * sizeof(*xnbd_session->xnbd_conns),
					  GFP_KERNEL);
	if (!xnbd_session->xnbd_conns) {
		pr_err("failed to allocate xnbd connections array\n");
		ret = -ENOMEM;
		goto err_destroy_portal;
	}

	init_completion(&xnbd_session->conns_wait);
	atomic_set(&xnbd_session->conns_count, 0);

	for (i = 0; i < submit_queues; i++) {
		ret = xnbd_create_conn(xnbd_session, i,
				       &xnbd_session->xnbd_conns[i]);
		if (ret)
			goto err_destroy_conns;
	}

	/* wait for all connections establishment to complete */
	if (!wait_for_completion_interruptible_timeout(&xnbd_session->conns_wait,
						       120 * HZ)) {
		pr_err("connection establishment timeout expired\n");
		goto err_destroy_conns;
	}

	return 0;

err_destroy_conns:
	for (j = 0; j < i; j++) {
		xnbd_destroy_conn(xnbd_session->xnbd_conns[j]);
		xnbd_session->xnbd_conns[j] = NULL;
	}
	kfree(xnbd_session->xnbd_conns);
err_destroy_portal:
	mutex_lock(&g_lock);
	list_del(&xnbd_session->list);
	mutex_unlock(&g_lock);
	xio_session_destroy(xnbd_session->session);
err_free_session:
	xnbd_destroy_kobj(&xnbd_session->kobj);
err_sysfs:
	return ret;

}

void xnbd_session_destroy(struct xnbd_session *xnbd_session)
{
	xnbd_destroy_session_devices(xnbd_session);
	mutex_lock(&g_lock);
	list_del(&xnbd_session->list);
	mutex_unlock(&g_lock);
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

	mutex_init(&g_lock);
	INIT_LIST_HEAD(&g_xnbd_sessions);

	return 0;
}

static void __exit xnbd_cleanup_module(void)
{
	struct xnbd_session *xnbd_session, *tmp;

	unregister_blkdev(xnbd_major, "xnbd");

	list_for_each_entry_safe(xnbd_session, tmp, &g_xnbd_sessions, list) {
		xnbd_session_destroy(xnbd_session);
		xnbd_destroy_kobj(&xnbd_session->kobj);
	}

	xnbd_destroy_sysfs_files();

}

module_init(xnbd_init_module);
module_exit(xnbd_cleanup_module);
