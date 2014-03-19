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

#define kobj_to_xnbd_dev(x) container_of(x, struct xnbd_file, kobj)
#define kobj_to_xnbd_session(x) container_of(x, struct xnbd_session, kobj)

static ssize_t xnbd_kobj_attr_show(struct kobject *kobj,
				   struct attribute *attr,
				   char *buf)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

	kattr = container_of(attr, struct kobj_attribute, attr);
	if (kattr->show)
		ret = kattr->show(kobj, kattr, buf);
		return ret;
}

static ssize_t xnbd_kobj_attr_store(struct kobject *kobj,
				    struct attribute *attr,
				    const char *buf,
				    size_t count)
{
	struct kobj_attribute *kattr;
	ssize_t ret = -EIO;

   kattr = container_of(attr, struct kobj_attribute, attr);
   if (kattr->store)
		ret = kattr->store(kobj, kattr, buf, count);
        return ret;
}

const struct sysfs_ops xnbd_kobj_sysfs_ops = {
		.show   = xnbd_kobj_attr_show,
		.store  = xnbd_kobj_attr_store,
};

static void _xnbd_destroy_kobj(void *obj)
{
	struct kobject *kobj = (struct kobject *)obj;

	xnbd_destroy_kobj(kobj);
}

static ssize_t delete_show(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   char *buf)
{
	return -1;
}

static ssize_t delete_store(struct kobject *kobj,
			    struct kobj_attribute *attr,
			    const char *buf, size_t count)
{
	int i;
	struct xnbd_session *session_d;

	if (kstrtoint(buf, 10, &i)) {
		pr_err("failed to process input value\n");
		return -EINVAL;
	}

	if (i != 1) {
		pr_err("unknown value: %d\n", i);
		return -EINVAL;
	}

	session_d = kobj_to_xnbd_session(kobj);

	xnbd_session_destroy(session_d);

	sysfs_schedule_callback(kobj, _xnbd_destroy_kobj,
				kobj, THIS_MODULE);

	return count;
}

static struct kobj_attribute delete_attribute = __ATTR(delete, 0666,
						       delete_show, delete_store);

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
	struct xnbd_session *session_d;
	char xdev_name[MAX_XNBD_DEV_NAME];
	ssize_t ret;

	session_d = kobj_to_xnbd_session(kobj);

	sscanf(buf, "%s", xdev_name);
	if(xnbd_file_find(session_d, xdev_name)) {
		pr_err("Device already exists: %s", xdev_name);
		return -EEXIST;
	}

	ret = xnbd_create_device(session_d, xdev_name, kobj);
	if (ret) {
		pr_err("failed to create device %s\n", xdev_name);
		return ret;
	}

	return count;
}

static struct kobj_attribute device_attribute = __ATTR(add_device, 0666,
						       device_show, device_store);

static struct attribute *default_device_attrs[] = {
	&device_attribute.attr,
	&delete_attribute.attr,
	NULL,
};

static struct attribute_group default_device_attr_group = {
	.attrs = default_device_attrs,
};

static void xnbd_session_release(struct kobject *kobj)
{
	struct xnbd_session *xnbd_session;

	xnbd_session = kobj_to_xnbd_session(kobj);

	kfree(xnbd_session);
}

static struct kobj_type xnbd_session_ktype = {
		.sysfs_ops = &xnbd_kobj_sysfs_ops,
		.release = xnbd_session_release,
};

static struct kobject *sysfs_kobj;

int xnbd_create_portal_files(struct kobject *kobj)
{
	int ret = 0;
	char portal_name[MAX_PORTAL_NAME];

	sprintf(portal_name, "xnbdhost_%d", created_portals);

	ret = kobject_init_and_add(kobj, &xnbd_session_ktype, sysfs_kobj, "%s",
							   portal_name);
	if (ret) {
		pr_err("failed to init and add kobject\n");
		goto err;
	}

	ret = sysfs_create_group(kobj, &default_device_attr_group);
	if (ret) {
		pr_err("failed to create sysfs group\n");
		goto err;
	}

	return 0;

err:
	xnbd_destroy_kobj(kobj);

	return ret;
}

void xnbd_destroy_kobj(struct kobject *kobj)
{
	kobject_put(kobj);
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

	if(xnbd_session_find_by_portal(&g_xnbd_sessions, rdma)) {
		pr_err("Portal already exists: %s", buf);
		return -EEXIST;
	}

	if (xnbd_session_create(rdma)) {
		printk("Couldn't create new session with %s\n", rdma);
		return -EINVAL;
	}

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
	xnbd_destroy_kobj(sysfs_kobj);
}

static ssize_t device_state_show(struct kobject *kobj,
				 struct kobj_attribute *attr,
				 char *buf)
{
	struct xnbd_file *xnbd_device;
	ssize_t ret;

	xnbd_device = kobj_to_xnbd_dev(kobj);

	ret = snprintf(buf, PAGE_SIZE, "%s\n", xnbd_device_state_str(xnbd_device));

	return ret;
}

static ssize_t device_state_store(struct kobject *kobj,
 				  struct kobj_attribute *attr,
 				  const char *buf, size_t count)
{
	return -1;
}

static struct kobj_attribute device_state_attribute = __ATTR(state, 0666,
                             device_state_show, device_state_store);

static ssize_t delete_device_show(struct kobject *kobj,
				  struct kobj_attribute *attr,
				  char *buf)
{
	return -1;
}

static ssize_t delete_device_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	struct xnbd_session *xnbd_session;
	struct xnbd_file *xnbd_device;
	int i;

	if (kstrtoint(buf, 10, &i)) {
		pr_err("failed to process input value\n");
		return -EINVAL;
	}

	if (i != 1) {
		pr_err("unknown value: %d\n", i);
		return -EINVAL;
	}

	xnbd_session = kobj_to_xnbd_session(kobj->parent);
	xnbd_device = kobj_to_xnbd_dev(kobj);

	xnbd_destroy_device(xnbd_session, xnbd_device);

	sysfs_schedule_callback(kobj, _xnbd_destroy_kobj, kobj, THIS_MODULE);

	return count;
}

static struct kobj_attribute delete_device_attribute = __ATTR(delete,
		0666, delete_device_show, delete_device_store);

static struct attribute *xnbd_device_attrs[] = {
	&device_state_attribute.attr,
	&delete_device_attribute.attr,
	NULL,
};

static struct attribute_group xnbd_device_attr_group = {
	.attrs = xnbd_device_attrs,
};

static void xnbd_device_release(struct kobject *kobj)
{
	struct xnbd_file *xnbd_device;

	xnbd_device = kobj_to_xnbd_dev(kobj);

	kfree(xnbd_device);
}

static struct kobj_type xnbd_device_ktype = {
		.sysfs_ops = &xnbd_kobj_sysfs_ops,
		.release = xnbd_device_release,
};

int xnbd_create_device_files(struct kobject *p_kobj,
			     const char *dev_name,
			     struct kobject *kobj)
{
	int ret = 0;

	ret = kobject_init_and_add(kobj, &xnbd_device_ktype, p_kobj, "%s",
							   dev_name);
	if (ret)
		goto err;

	ret = sysfs_create_group(kobj, &xnbd_device_attr_group);
	if (ret)
		goto err;

	return 0;

err:
	kobject_put(kobj);

	return ret;
}
