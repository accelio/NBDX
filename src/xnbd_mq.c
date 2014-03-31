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

int xnbd_rq_map_iov(struct request *rq, struct xio_vmsg *vmsg,
		    unsigned long long *len)
{
	struct bio_vec bvec;
	struct req_iterator iter;
	int i = 0;

	if (XIO_MAX_IOV <= rq->bio->bi_vcnt) {
		pr_err("unsupported io vec size\n");
		return -ENOMEM;
	}

	*len = 0;
	rq_for_each_segment(bvec, rq, iter) {
		vmsg->data_iov[i].iov_base = page_address(bvec.bv_page) +
					     bvec.bv_offset;
		vmsg->data_iov[i].iov_len =  bvec.bv_len;
		*len += vmsg->data_iov[i].iov_len;
		i++;
	}
	vmsg->data_iovlen = i;

	return 0;
}

static struct blk_mq_hw_ctx *xnbd_alloc_hctx(struct blk_mq_reg *reg,
					     unsigned int hctx_index)
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
	pr_err("%s called\n", __func__);

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

	if (err) {
		rq->errors = -EIO;
		return BLK_MQ_RQ_QUEUE_ERROR;
	} else {
		return BLK_MQ_RQ_QUEUE_OK;
	}
}

static int xnbd_init_hctx(struct blk_mq_hw_ctx *hctx, void *data,
			  unsigned int index)
{
	struct xnbd_file *xdev = data;
	struct xnbd_queue *xq;

	pr_debug("%s called index=%u\n", __func__, index);

	xq = &xdev->queues[index];
	pr_debug("%s called xq=%p\n", __func__, xq);
	xq->xnbd_conn = xdev->xnbd_conns[index];
	xq->xdev = xdev;
	xq->queue_depth = xdev->queue_depth;
	hctx->driver_data = xq;

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
	.cmd_size	= sizeof(struct raio_io_u),
	.flags		= BLK_MQ_F_SHOULD_MERGE,
	.numa_node	= NUMA_NO_NODE,
};

int xnbd_setup_queues(struct xnbd_file *xdev)
{
	pr_debug("%s called\n", __func__);

	xdev->queues = kzalloc(submit_queues * sizeof(*xdev->queues),
			GFP_KERNEL);
	if (!xdev->queues)
		return -ENOMEM;

	return 0;
}

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

void xnbd_destroy_queues(struct xnbd_file *xdev)
{
	pr_debug("%s called\n", __func__);

	kfree(xdev->queues);
}

int xnbd_register_block_device(struct xnbd_file *xnbd_file)
{
	sector_t size = xnbd_file->stbuf.st_size;

	pr_debug("%s called\n", __func__);

	xnbd_mq_reg.queue_depth = XNBD_QUEUE_DEPTH;
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
	sscanf(xnbd_file->dev_name, "%s", xnbd_file->disk->disk_name);
	add_disk(xnbd_file->disk);

	return 0;
}

void xnbd_unregister_block_device(struct xnbd_file *xnbd_file)
{
	del_gendisk(xnbd_file->disk);
	blk_cleanup_queue(xnbd_file->queue);
	put_disk(xnbd_file->disk);
}
