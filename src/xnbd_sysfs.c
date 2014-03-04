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

static ssize_t device_show(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   char *buf)
{
	return -1;
}

static ssize_t device_store(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	int idx = kstrtoint(strpbrk(kobj->name, "_") + 1, 10, &idx);
	struct session_data *session_d = g_session_data[idx];
	char xdev_name[MAX_XNBD_DEV_NAME];

	sscanf(buf, "%s", xdev_name);
	if (xnbd_create_device(session_d, xdev_name)) {
		pr_err("failed to open file=%s\n", xdev_name);
		return -1;
	}

	return count;
}

static struct kobj_attribute device_attribute = __ATTR(add_device, 0666,
						       device_show, device_store);

static struct attribute *default_device_attrs[] = {
	&device_attribute.attr,
	NULL,
};

static struct attribute_group default_device_attr_group = {
	.attrs = default_device_attrs,
};

static struct kobject *sysfs_kobj;
static struct kobject *portal_sysfs_kobj[SUPPORTED_PORTALS];

int xnbd_create_portal_files(void)
{
	int err = 0;
	char portal_name[MAX_PORTAL_NAME];

	sprintf(portal_name, "xnbdhost_%d", created_portals);

	portal_sysfs_kobj[created_portals] = kobject_create_and_add(portal_name,
								    sysfs_kobj);
	if (!portal_sysfs_kobj[created_portals]) {
		pr_err("failedto create kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(portal_sysfs_kobj[created_portals],
				 &default_device_attr_group);
	if (err)
		kobject_put(portal_sysfs_kobj[created_portals]);
	else
		created_portals++;

	return err;
}

void xnbd_destroy_portal_file(int index)
{
	kobject_put(portal_sysfs_kobj[index]);
}

static ssize_t add_portal_show(struct kobject *kobj,
		struct kobj_attribute *attr,
		char *buf)
{
	return -1;
}

static ssize_t add_portal_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	char rdma[MAX_PORTAL_NAME] = "rdma://" ;
	sscanf(strcat(rdma, buf), "%s", rdma);

	if (xnbd_session_create(rdma)) {
		printk("Couldn't create new session with %s\n", rdma);
		return -EINVAL;
	}

	xnbd_create_portal_files();
	return count;
}

static struct kobj_attribute add_portal_attribute = __ATTR(add_portal, 0666,
							   add_portal_show,
							   add_portal_store);

static struct attribute *default_attrs[] = {
	&add_portal_attribute.attr,
	NULL,
};

static struct attribute_group default_attr_group = {
	.attrs = default_attrs,
};


int xnbd_create_sysfs_files(void)
{
	int err = 0;

	sysfs_kobj = kobject_create_and_add("xnbd", NULL);
	if (!sysfs_kobj)
		return -ENOMEM;

	err = sysfs_create_group(sysfs_kobj, &default_attr_group);
	if (err)
		kobject_put(sysfs_kobj);

	return err;
}

void xnbd_destroy_sysfs_files(void)
{
	kobject_put(sysfs_kobj);
}
