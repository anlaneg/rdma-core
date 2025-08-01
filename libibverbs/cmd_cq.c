/*
 * Copyright (c) 2018 Mellanox Technologies, Ltd.  All rights reserved.
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

#include <infiniband/cmd_write.h>
#include "ibverbs.h"

/*创建cq对应的cmd*/
static int ibv_icmd_create_cq(struct ibv_context *context, int cqe,
			      struct ibv_comp_channel *channel, int comp_vector,
			      uint32_t flags, struct ibv_cq *cq,
			      struct ibv_command_buffer *link/*待link的cmd buffer*/,
			      uint32_t cmd_flags)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_CQ, UVERBS_METHOD_CQ_CREATE, 8, link);
	struct verbs_ex_private *priv = get_priv(context);
	struct ib_uverbs_attr *handle;
	struct ib_uverbs_attr *async_fd_attr;
	uint32_t resp_cqe;
	int ret;

	cq->context = context;

	/*增加attr，并填充attr_id及value*/
	handle = fill_attr_out_obj(cmdb, UVERBS_ATTR_CREATE_CQ_HANDLE);
	fill_attr_out_ptr(cmdb, UVERBS_ATTR_CREATE_CQ_RESP_CQE, &resp_cqe);

	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_CQ_CQE, cqe);/*指明cqe数目*/
	fill_attr_in_uint64(cmdb, UVERBS_ATTR_CREATE_CQ_USER_HANDLE, (uintptr_t)cq);
	if (channel)
		/*如果有channel,则指定channel fd*/
		fill_attr_in_fd(cmdb, UVERBS_ATTR_CREATE_CQ_COMP_CHANNEL, channel->fd);
	fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_CQ_COMP_VECTOR, comp_vector);
	async_fd_attr = fill_attr_in_fd(cmdb, UVERBS_ATTR_CREATE_CQ_EVENT_FD, context->async_fd);
	if (priv->imported)
		fallback_require_ioctl(cmdb);
	else
		/* Prevent fallback to the 'write' mode if kernel doesn't support it */
		attr_optional(async_fd_attr);

	if (flags) {
		if ((flags & ~IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION) ||
		    (!(cmd_flags & CREATE_CQ_CMD_FLAGS_TS_IGNORED_EX)))
			fallback_require_ex(cmdb);
		/*添加cq_flags*/
		fill_attr_in_uint32(cmdb, UVERBS_ATTR_CREATE_CQ_FLAGS, flags);
	}

	/*执行create_cq*/
	switch (execute_ioctl_fallback(cq->context, create_cq, cmdb, &ret)) {
	case TRY_WRITE: {
		DECLARE_LEGACY_UHW_BUFS(link, IB_USER_VERBS_CMD_CREATE_CQ);

		*req = (struct ib_uverbs_create_cq){
			.user_handle = (uintptr_t)cq,
			.cqe = cqe,
			.comp_vector = comp_vector,
			.comp_channel = channel ? channel->fd : -1,
		};

		ret = execute_write_bufs(
			cq->context, IB_USER_VERBS_CMD_CREATE_CQ, req, resp);
		if (ret)
			return ret;

		cq->handle = resp->cq_handle;
		cq->cqe = resp->cqe;

		return 0;
	}
	case TRY_WRITE_EX: {
		DECLARE_LEGACY_UHW_BUFS_EX(link,
					   IB_USER_VERBS_EX_CMD_CREATE_CQ);

		*req = (struct ib_uverbs_ex_create_cq){
			.user_handle = (uintptr_t)cq,
			.cqe = cqe,
			.comp_vector = comp_vector,
			.comp_channel = channel ? channel->fd : -1,
			.flags = flags,
		};

		ret = execute_write_bufs_ex(
			cq->context, IB_USER_VERBS_EX_CMD_CREATE_CQ, req, resp);
		if (ret)
			return ret;

		cq->handle = resp->base.cq_handle;
		cq->cqe = resp->base.cqe;

		return 0;
	}

	case ERROR:
		return ret;

	case SUCCESS:
		break;
	}

	cq->handle = read_attr_obj(UVERBS_ATTR_CREATE_CQ_HANDLE, handle);
	cq->cqe = resp_cqe;

	return 0;
}

static int ibv_icmd_create_cq_ex(struct ibv_context *context,
				 const struct ibv_cq_init_attr_ex *cq_attr,
				 struct verbs_cq *cq,
				 struct ibv_command_buffer *cmdb,
				 uint32_t cmd_flags)
{
	uint32_t flags = 0;

	if (!check_comp_mask(cq_attr->comp_mask,
			     IBV_CQ_INIT_ATTR_MASK_FLAGS |
			     IBV_CQ_INIT_ATTR_MASK_PD))
		return EOPNOTSUPP;

	if (cq_attr->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP ||
	    cq_attr->wc_flags & IBV_WC_EX_WITH_COMPLETION_TIMESTAMP_WALLCLOCK)
		flags |= IB_UVERBS_CQ_FLAGS_TIMESTAMP_COMPLETION;

	if ((cq_attr->comp_mask & IBV_CQ_INIT_ATTR_MASK_FLAGS) &&
	    cq_attr->flags & IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN)
		flags |= IB_UVERBS_CQ_FLAGS_IGNORE_OVERRUN;

	return ibv_icmd_create_cq(context, cq_attr->cqe, cq_attr->channel,
				  cq_attr->comp_vector, flags,
				  &cq->cq, cmdb, cmd_flags);
}

int ibv_cmd_create_cq(struct ibv_context *context, int cqe,
		      struct ibv_comp_channel *channel, int comp_vector,
		      struct ibv_cq *cq, struct ibv_create_cq *cmd,
		      size_t cmd_size, struct ib_uverbs_create_cq_resp *resp,
		      size_t resp_size)
{
    /*初始化cmdb*/
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_CQ,
				  UVERBS_METHOD_CQ_CREATE, cmd, cmd_size, resp,
				  resp_size);

	return ibv_icmd_create_cq(context, cqe, channel, comp_vector, 0, cq,
				  cmdb, 0);
}

int ibv_cmd_create_cq_ex(struct ibv_context *context,
			 const struct ibv_cq_init_attr_ex *cq_attr,
			 struct verbs_cq *cq,
			 struct ibv_create_cq_ex *cmd,
			 size_t cmd_size,
			 struct ib_uverbs_ex_create_cq_resp *resp,
			 size_t resp_size,
			 uint32_t cmd_flags)
{
	DECLARE_CMD_BUFFER_COMPAT(cmdb, UVERBS_OBJECT_CQ,
				  UVERBS_METHOD_CQ_CREATE, cmd, cmd_size, resp,
				  resp_size);

	return ibv_icmd_create_cq_ex(context, cq_attr, cq, cmdb, cmd_flags);
}

int ibv_cmd_create_cq_ex2(struct ibv_context *context,
			  const struct ibv_cq_init_attr_ex *cq_attr,
			  struct verbs_cq *cq,
			  struct ibv_create_cq_ex *cmd,
			  size_t cmd_size,
			  struct ib_uverbs_ex_create_cq_resp *resp,
			  size_t resp_size,
			  uint32_t cmd_flags,
			  struct ibv_command_buffer *driver)
{
	DECLARE_CMD_BUFFER_LINK_COMPAT(cmdb, UVERBS_OBJECT_CQ,
				       UVERBS_METHOD_CQ_CREATE,
				       driver, cmd, cmd_size, resp, resp_size);

	/*调用create cq*/
	return ibv_icmd_create_cq_ex(context, cq_attr, cq, cmdb, cmd_flags);
}

int ibv_cmd_destroy_cq(struct ibv_cq *cq)
{
	DECLARE_FBCMD_BUFFER(cmdb, UVERBS_OBJECT_CQ, UVERBS_METHOD_CQ_DESTROY, 2,
			     NULL);
	struct ib_uverbs_destroy_cq_resp resp;
	int ret;

	fill_attr_out_ptr(cmdb, UVERBS_ATTR_DESTROY_CQ_RESP, &resp);
	fill_attr_in_obj(cmdb, UVERBS_ATTR_DESTROY_CQ_HANDLE, cq->handle);

	switch (execute_ioctl_fallback(cq->context, destroy_cq, cmdb, &ret)) {
	case TRY_WRITE: {
		struct ibv_destroy_cq req;

		req.core_payload = (struct ib_uverbs_destroy_cq){
			.cq_handle = cq->handle,
		};

		/*执行destroy cq命令*/
		ret = execute_cmd_write(cq->context,
					IB_USER_VERBS_CMD_DESTROY_CQ, &req,
					sizeof(req), &resp, sizeof(resp));
		break;
	}

	default:
		break;
	}

	if (verbs_is_destroy_err(&ret))
		return ret;

	pthread_mutex_lock(&cq->mutex);
	while (cq->comp_events_completed != resp.comp_events_reported ||
	       cq->async_events_completed != resp.async_events_reported)
		pthread_cond_wait(&cq->cond, &cq->mutex);
	pthread_mutex_unlock(&cq->mutex);

	return 0;
}
