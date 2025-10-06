/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2006, 2007 Cisco Systems, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#define _GNU_SOURCE
#include <config.h>

#include <endian.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <alloca.h>
#include <errno.h>

#include <rdma/ib_user_ioctl_cmds.h>
#include <util/symver.h>
#include <util/util.h>
#include "ibverbs.h"

static pthread_mutex_t dev_list_lock = PTHREAD_MUTEX_INITIALIZER;
static struct list_head device_list = LIST_HEAD_INIT(device_list);

//返回当前系统所有ibv_device设备数目，及ibv_device设备数组
LATEST_SYMVER_FUNC(ibv_get_device_list, 1_1, "IBVERBS_1.1",
		   struct ibv_device **/*返回值类型，识别的所有ibv_device指针*/,
		   int *num/*出参,识别的ibv_device数目*/)
{
	struct ibv_device **l = NULL;
	struct verbs_device *device;
	static bool initialized;/*此函数是否被调用过*/
	int num_devices;
	int i = 0;

	if (num)
		*num = 0;

	pthread_mutex_lock(&dev_list_lock);
	if (!initialized) {
	    /*未初始化，执行verbs初始化*/
		if (ibverbs_init())
			goto out;
		/*标明已初始化*/
		initialized = true;
	}

	/*获取系统内所有ib设备列表*/
	num_devices = ibverbs_get_device_list(&device_list);
	if (num_devices < 0) {
		errno = -num_devices;
		goto out;
	}

	//申请内存，记录所有ib设备
	l = calloc(num_devices + 1, sizeof (struct ibv_device *));
	if (!l) {
		errno = ENOMEM;
		goto out;
	}

	//遍历所有verbs_device,收集对应的ibv_device
	list_for_each(&device_list, device, entry) {
		l[i] = &device->device;
		ibverbs_device_hold(l[i]);
		i++;
	}
	if (num)
		*num = num_devices;
out:
	pthread_mutex_unlock(&dev_list_lock);
	/*返回收集的ibv_device*/
	return l;
}

/*释放由ibv_get_device_list函数识别出来的ibv_device*/
LATEST_SYMVER_FUNC(ibv_free_device_list, 1_1, "IBVERBS_1.1",
		   void,
		   struct ibv_device **list)
{
	int i;

	/*遍历list指定的ibv_device,并将其释放*/
	for (i = 0; list[i]; i++)
		ibverbs_device_put(list[i]);
	free(list);
}

/*取给定的ibv设备名称*/
LATEST_SYMVER_FUNC(ibv_get_device_name, 1_1, "IBVERBS_1.1",
		   const char *,
		   struct ibv_device *device)
{
	return device->name;
}

/*取ibv设备的node_guid,如果没有缓存，则读取设备对应的node_guid文件*/
LATEST_SYMVER_FUNC(ibv_get_device_guid, 1_1, "IBVERBS_1.1",
		   __be64,
		   struct ibv_device *device)
{
	struct verbs_sysfs_dev *sysfs_dev = verbs_get_device(device)->sysfs;
	char attr[24];
	uint64_t guid = 0;
	uint16_t parts[4];
	int i;

	pthread_mutex_lock(&dev_list_lock);
	if (sysfs_dev && sysfs_dev->flags & VSYSFS_READ_NODE_GUID) {
		guid = sysfs_dev->node_guid;
		pthread_mutex_unlock(&dev_list_lock);
		return htobe64(guid);
	}
	pthread_mutex_unlock(&dev_list_lock);

	if (ibv_read_ibdev_sysfs_file(attr, sizeof(attr), sysfs_dev,
				      "node_guid") < 0)
		return 0;

	if (sscanf(attr, "%hx:%hx:%hx:%hx",
		   parts, parts + 1, parts + 2, parts + 3) != 4)
		return 0;

	for (i = 0; i < 4; ++i)
		guid = (guid << 16) | parts[i];

	pthread_mutex_lock(&dev_list_lock);
	sysfs_dev->node_guid = guid;
	sysfs_dev->flags |= VSYSFS_READ_NODE_GUID;
	pthread_mutex_unlock(&dev_list_lock);

	return htobe64(guid);
}

/*取ibv设备的ibdev_idx*/
int ibv_get_device_index(struct ibv_device *device)
{
	struct verbs_sysfs_dev *sysfs_dev = verbs_get_device(device)->sysfs;

	return sysfs_dev ? sysfs_dev->ibdev_idx : -1;
}

void verbs_init_cq(struct ibv_cq *cq, struct ibv_context *context,
		       struct ibv_comp_channel *channel,
		       void *cq_context/*为此cq关联的私有数据*/)
{
	cq->context		   = context;
	cq->channel		   = channel;

	if (cq->channel) {
		pthread_mutex_lock(&context->mutex);
		++cq->channel->refcnt;
		pthread_mutex_unlock(&context->mutex);
	}

	cq->cq_context		   = cq_context;
	cq->comp_events_completed  = 0;
	cq->async_events_completed = 0;
	pthread_mutex_init(&cq->mutex, NULL);
	pthread_cond_init(&cq->cond, NULL);
}

static struct ibv_cq_ex *
__lib_ibv_create_cq_ex(struct ibv_context *context,
		       struct ibv_cq_init_attr_ex *cq_attr)
{
	struct ibv_cq_ex *cq;

	if (cq_attr->wc_flags & ~IBV_CREATE_CQ_SUP_WC_FLAGS) {
	    /*wc_flags中包含不认识的flags,返回NULL*/
		errno = EOPNOTSUPP;
		return NULL;
	}

	/*调用provider回调，创建cq*/
	cq = get_ops(context)->create_cq_ex(context, cq_attr);

	if (cq)
		verbs_init_cq(ibv_cq_ex_to_cq(cq), context,
			        cq_attr->channel, cq_attr->cq_context);

	return cq;
}

/*检查是否有ioctl write*/
static bool has_ioctl_write(struct ibv_context *ctx)
{
	int rc;
	DECLARE_COMMAND_BUFFER(cmdb, UVERBS_OBJECT_DEVICE,
			       UVERBS_METHOD_INVOKE_WRITE, 1);

	if (VERBS_IOCTL_ONLY)
		return true;
	if (VERBS_WRITE_ONLY)
		return false;

	/*
	 * This command should return ENOSPC since the request length is too
	 * small.
	 */
	fill_attr_const_in(cmdb, UVERBS_ATTR_WRITE_CMD,
			   IB_USER_VERBS_CMD_QUERY_DEVICE);
	rc = execute_ioctl(ctx, cmdb);
	if (rc == EPROTONOSUPPORT)
		return false;
	if (rc == ENOTTY)
		return false;
	return true;
}

/*
 * Ownership of cmd_fd is transferred into this function, and it will either
 * be released during the matching call to verbs_uninit_contxt or during the
 * failure path of this function.
 */
int verbs_init_context(struct verbs_context *context_ex/*要初始化的verbs_context*/,
		       struct ibv_device *device/*关联的ib设备*/, int cmd_fd/*verbs命令对应的fd*/,
		       uint32_t driver_id/*驱动类别id*/)
{
	/*verbs context中有ibv_context*/
	struct ibv_context *context = &context_ex->context;

	ibverbs_device_hold(device);

	/*初始化ib context*/
	context->device = device;
	context->cmd_fd = cmd_fd;
	context->async_fd = -1;
	pthread_mutex_init(&context->mutex, NULL);

	context_ex->context.abi_compat = __VERBS_ABI_IS_EXTENDED;
	context_ex->sz = sizeof(*context_ex);/*这个值本身总等于verbs_context,增加它的意义在哪？*/

	/*申请私有结构体*/
	context_ex->priv = calloc(1, sizeof(*context_ex->priv));
	if (!context_ex->priv) {
		errno = ENOMEM;
		close(cmd_fd);
		return -1;
	}

	context_ex->priv->driver_id = driver_id;
	//设置dummy式的ops,用于提供默认实现
	verbs_set_ops(context_ex, &verbs_dummy_ops);
	context_ex->priv->use_ioctl_write = has_ioctl_write(context);

	return 0;
}

/*
 * Allocate and initialize a context structure. This is called to create the
 * driver wrapper, and context_offset is the number of bytes into the wrapper
 * structure where the verbs_context starts.
 */
void *_verbs_init_and_alloc_context(struct ibv_device *device/*关联的ib设备*/, int cmd_fd/*字符设备*/,
				    size_t alloc_size/*driver context结构体大小*/,
				    struct verbs_context *context_offset/*driver context中到verbs_context成员的偏移量*/,
				    uint32_t driver_id/*驱动类型编号*/)
{
	void *drv_context;
	struct verbs_context *context;

	/*申请driver context*/
	drv_context = calloc(1, alloc_size);
	if (!drv_context) {
		errno = ENOMEM;
		close(cmd_fd);
		return NULL;
	}

	/*依据offset自dirver context中拿到verbs_context的起始地址*/
	context = drv_context + (uintptr_t)context_offset;

	/*初始化verbs_context*/
	if (verbs_init_context(context, device, cmd_fd, driver_id))
		goto err_free;

	/*返回driver context*/
	return drv_context;

err_free:
	free(drv_context);
	return NULL;
}

/*设置lib ops（这些回调不能直接调用provider提供的，而需要被代理一层之后再调用）*/
static void set_lib_ops(struct verbs_context *vctx)
{
    /*设置create cq_ex回调(verbs_set_ops函数不设置此回调)*/
	vctx->create_cq_ex = __lib_ibv_create_cq_ex;

	/*
	 * The compat symver entry point behaves identically to what used to
	 * be pointed to by _compat_query_port.
	 */
#undef ibv_query_port
	vctx->context.ops._compat_query_port = ibv_query_port;
	vctx->query_port = __lib_query_port;
	vctx->context.ops._compat_query_device = ibv_query_device;

	/*
	 * In order to maintain backward/forward binary compatibility
	 * with apps compiled against libibverbs-1.1.8 that use the
	 * flow steering addition, we need to set the two
	 * ABI_placeholder entries to match the driver set flow
	 * entries.  This is because apps compiled against
	 * libibverbs-1.1.8 use an inline ibv_create_flow and
	 * ibv_destroy_flow function that looks in the placeholder
	 * spots for the proper entry points.  For apps compiled
	 * against libibverbs-1.1.9 and later, the inline functions
	 * will be looking in the right place.
	 */
	vctx->ABI_placeholder1 =
		(void (*)(void))vctx->ibv_create_flow;
	vctx->ABI_placeholder2 =
		(void (*)(void))vctx->ibv_destroy_flow;
}

//打开ib device，创建并初始化其对应的ibv_context
struct ibv_context *verbs_open_device(struct ibv_device *device, void *private_data/*用户传入的私有数据*/)
{
    /*转对应的verbs_device*/
	struct verbs_device *verbs_device = verbs_get_device(device);
	int cmd_fd = -1;
	struct verbs_context *context_ex;
	int ret;

	if (verbs_device->sysfs) {
		/*
		 * We'll only be doing writes, but we need O_RDWR in case the
		 * provider needs to mmap() the file.
		 */
		//打开/dev/infiniband/下对应的verbs字符设备,例如/dev/infiniband/uverbs0
		cmd_fd = open_cdev(verbs_device->sysfs->sysfs_name,
				   verbs_device->sysfs->sysfs_cdev);
		if (cmd_fd < 0)
			return NULL;
	}

	/*
	 * cmd_fd ownership is transferred into alloc_context, if it fails
	 * then it closes cmd_fd and returns NULL
	 */
	//由此verbs设备的provider负责创建context,例如:
	//verbs_device->ops == mlx5_dev_ops/rxe_dev_ops
	context_ex = verbs_device->ops->alloc_context(device, cmd_fd/*device对应的字符设备fd*/, private_data);
	if (!context_ex)
		return NULL;

	set_lib_ops(context_ex);
	if (verbs_device->sysfs) {
		if (context_ex->context.async_fd == -1) {
		    /*打开异步fd*/
			ret = ibv_cmd_alloc_async_fd(&context_ex->context);
			if (ret) {
				ibv_close_device(&context_ex->context);
				return NULL;
			}
		}
	}

	return &context_ex->context;
}

/*打开指定ib设备，返回其对应的ibv_context*/
LATEST_SYMVER_FUNC(ibv_open_device, 1_1, "IBVERBS_1.1",
		   struct ibv_context *,
		   struct ibv_device *device)
{
	return verbs_open_device(device/*要打开的ib device*/, NULL/*私有数据为空*/);
}

struct ibv_context *ibv_import_device(int cmd_fd)
{
	struct verbs_device *verbs_device = NULL;
	struct verbs_context *context_ex;
	struct ibv_device **dev_list;
	struct ibv_context *ctx = NULL;
	struct stat st;
	int ret;
	int i;

	if (fstat(cmd_fd, &st) || !S_ISCHR(st.st_mode)) {
		errno = EINVAL;
		return NULL;
	}

	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		errno = ENODEV;
		return NULL;
	}

	for (i = 0; dev_list[i]; ++i) {
		if (verbs_get_device(dev_list[i])->sysfs->sysfs_cdev ==
					st.st_rdev) {
			verbs_device = verbs_get_device(dev_list[i]);
			break;
		}
	}

	if (!verbs_device) {
		errno = ENODEV;
		goto out;
	}

	if (!verbs_device->ops->import_context) {
		errno = EOPNOTSUPP;
		goto out;
	}

	/* In case the underlay cdev number was assigned in the meantime to
	 * other device as of some disassociate flow, the next call on the
	 * FD will end up with EIO (i.e. query_context command) and we should
	 * be safe from using the wrong device.
	 */
	context_ex = verbs_device->ops->import_context(&verbs_device->device, cmd_fd);
	if (!context_ex)
		goto out;

	set_lib_ops(context_ex);

	context_ex->priv->imported = true;
	ctx = &context_ex->context;
	ret = ibv_cmd_alloc_async_fd(ctx);
	if (ret) {
		ibv_close_device(ctx);
		ctx = NULL;
	}
out:
	ibv_free_device_list(dev_list);
	return ctx;
}

void verbs_uninit_context(struct verbs_context *context_ex)
{
	free(context_ex->priv);
	if (context_ex->context.cmd_fd != -1)
		close(context_ex->context.cmd_fd);
	if (context_ex->context.async_fd != -1)
		close(context_ex->context.async_fd);
	ibverbs_device_put(context_ex->context.device);
}

LATEST_SYMVER_FUNC(ibv_close_device, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_context *context)
{
	const struct verbs_context_ops *ops = get_ops(context);

	ops->free_context(context);
	return 0;
}

LATEST_SYMVER_FUNC(ibv_get_async_event, 1_1, "IBVERBS_1.1",
		   int,
		   struct ibv_context *context,
		   struct ibv_async_event *event)
{
	struct ib_uverbs_async_event_desc ev;

	if (read(context->async_fd, &ev, sizeof ev) != sizeof ev)
		return -1;

	event->event_type = ev.event_type;

	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
		event->element.cq = (void *) (uintptr_t) ev.element;
		break;

	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_PATH_MIG_ERR:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
		event->element.qp = (void *) (uintptr_t) ev.element;
		break;

	case IBV_EVENT_SRQ_ERR:
	case IBV_EVENT_SRQ_LIMIT_REACHED:
		event->element.srq = (void *) (uintptr_t) ev.element;
		break;

	case IBV_EVENT_WQ_FATAL:
		event->element.wq = (void *) (uintptr_t) ev.element;
		break;
	default:
		event->element.port_num = ev.element;
		break;
	}

	get_ops(context)->async_event(context, event);

	return 0;
}

LATEST_SYMVER_FUNC(ibv_ack_async_event, 1_1, "IBVERBS_1.1",
		   void,
		   struct ibv_async_event *event)
{
	switch (event->event_type) {
	case IBV_EVENT_CQ_ERR:
	{
		struct ibv_cq *cq = event->element.cq;

		pthread_mutex_lock(&cq->mutex);
		++cq->async_events_completed;
		pthread_cond_signal(&cq->cond);
		pthread_mutex_unlock(&cq->mutex);

		return;
	}

	case IBV_EVENT_QP_FATAL:
	case IBV_EVENT_QP_REQ_ERR:
	case IBV_EVENT_QP_ACCESS_ERR:
	case IBV_EVENT_COMM_EST:
	case IBV_EVENT_SQ_DRAINED:
	case IBV_EVENT_PATH_MIG:
	case IBV_EVENT_PATH_MIG_ERR:
	case IBV_EVENT_QP_LAST_WQE_REACHED:
	{
		struct ibv_qp *qp = event->element.qp;

		pthread_mutex_lock(&qp->mutex);
		++qp->events_completed;
		pthread_cond_signal(&qp->cond);
		pthread_mutex_unlock(&qp->mutex);

		return;
	}

	case IBV_EVENT_SRQ_ERR:
	case IBV_EVENT_SRQ_LIMIT_REACHED:
	{
		struct ibv_srq *srq = event->element.srq;

		pthread_mutex_lock(&srq->mutex);
		++srq->events_completed;
		pthread_cond_signal(&srq->cond);
		pthread_mutex_unlock(&srq->mutex);

		return;
	}

	case IBV_EVENT_WQ_FATAL:
	{
		struct ibv_wq *wq = event->element.wq;

		pthread_mutex_lock(&wq->mutex);
		++wq->events_completed;
		pthread_cond_signal(&wq->cond);
		pthread_mutex_unlock(&wq->mutex);

		return;
	}

	default:
		return;
	}
}
