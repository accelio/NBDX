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

#ifndef XNBD_H
#define XNBD_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
#include <asm/atomic.h>
#else
#include <linux/atomic.h>
#endif
#include <linux/completion.h>
#include <linux/list.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/fs.h>
#include <linux/wait.h>
#include <linux/fcntl.h>
#include <linux/cpumask.h>

#include "libxio.h"
#include "raio_kutils.h"
#include "raio_kbuffer.h"

#define MAX_MSG_LEN	    512
#define MAX_PORTAL_NAME	    256
#define MAX_XNBD_DEV_NAME   256
#define SUPPORTED_DISKS	    256
#define SUPPORTED_PORTALS   5
#define XNBD_SECT_SIZE	    512
#define XNBD_SECT_SHIFT	    ilog2(XNBD_SECT_SIZE)
#define XNBD_QUEUE_DEPTH    64

struct xnbd_connection {
	struct xio_session     *session;
	struct xio_context     *ctx;
	struct xio_connection  *conn;
	struct task_struct     *conn_th;
	int			cpu_id;
	int			wq_flag;
	struct xio_msg		req;
	struct xio_msg	       *rsp;
	wait_queue_head_t	wq;
	struct list_head	iou_pool;
	spinlock_t		iou_lock;
};

struct xnbd_session {
	struct xio_session	     *session;
	struct xnbd_connection	    **xnbd_conns;
	char			      portal[MAX_PORTAL_NAME];
	struct list_head	      list;
	struct list_head	      devs_list; /* list of struct xnbd_file */
	spinlock_t		      devs_lock;
	struct kobject		     *kobj;
	struct completion	      conns_wait;
	atomic_t		      conns_count;
};

struct xnbd_queue {
	unsigned int		     queue_depth;
	struct xnbd_connection	    *xnbd_conn;
	struct raio_iocb	    *piocb;
	struct xnbd_file	    *xdev; /* pointer to parent*/
};

struct xnbd_file {
	int			     fd;
	int			     major; /* major number from kernel */
	struct r_stat64		     stbuf; /* remote file stats*/
	char			     file_name[MAX_XNBD_DEV_NAME];
	struct list_head	     list; /* next node in list of struct xnbd_file */
	struct gendisk		    *disk;
	struct request_queue	    *queue; /* The device request queue */
	struct xnbd_queue	    *queues;
	unsigned int		     queue_depth;
	unsigned int		     nr_queues;
	int			     index; /* drive idx */
	char			     dev_name[MAX_XNBD_DEV_NAME];
	struct xnbd_connection	    **xnbd_conns;
};

extern struct list_head g_xnbd_sessions;
extern struct mutex g_lock;
extern int created_portals;
extern int submit_queues;
extern int xnbd_major;
extern int xnbd_indexes;

int xnbd_transfer(struct xnbd_file *xdev, char *buffer, unsigned long start,
		  unsigned long len, int write, struct request *req,
		  struct xnbd_queue *q);
int xnbd_session_create(const char *portal);
int xnbd_create_device(struct xnbd_session *blk_xnbd_session,
		       const char *xdev_name);
int xnbd_destroy_device_by_name(struct xnbd_session *xnbd_session,
		       const char *xdev_name);
int xnbd_create_sysfs_files(void);
void xnbd_destroy_sysfs_files(void);
struct kobject* xnbd_create_portal_files(void);
void xnbd_destroy_portal_file(struct kobject *kobj);
int xnbd_rq_map_iov(struct request *rq, struct xio_vmsg *vmsg,
		    unsigned long long *len);
int xnbd_register_block_device(struct xnbd_file *xnbd_file);
void xnbd_unregister_block_device(struct xnbd_file *xnbd_file);
int xnbd_setup_queues(struct xnbd_file *xdev);
void xnbd_destroy_queues(struct xnbd_file *xdev);
struct xnbd_session *xnbd_session_find(struct list_head *s_data_list,
					    const char *host_name);
struct xnbd_file *xnbd_file_find(struct xnbd_session *xnbd_session,
				 const char *name);
struct xnbd_session *xnbd_session_find_by_portal(struct list_head *s_data_list,
						 const char *portal);
void xnbd_session_destroy(struct xnbd_session *xnbd_session);

#endif  /* XNBD_H */

