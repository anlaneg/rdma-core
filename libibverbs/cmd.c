/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2006 Cisco Systems, Inc.  All rights reserved.
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

#include <config.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <alloca.h>
#include <string.h>

#include <infiniband/cmd_write.h>
#include "ibverbs.h"
#include <ccan/minmax.h>

bool verbs_allow_disassociate_destroy;

/*执行alloc pd命令*/
int ibv_cmd_alloc_pd(struct ibv_context *context, struct ibv_pd *pd,
		     struct ibv_alloc_pd *cmd, size_t cmd_size,
		     struct ib_uverbs_alloc_pd_resp *resp, size_t resp_size)
{
	int ret;

	ret = execute_cmd_write(context, IB_USER_VERBS_CMD_ALLOC_PD, cmd,
				cmd_size, resp, resp_size);
	if (ret)
		return ret;

	pd->handle  = resp->pd_handle;
	pd->context = context;

	return 0;
}

int ibv_cmd_open_xrcd(struct ibv_context *context, struct verbs_xrcd *xrcd,
		      int vxrcd_size,
		      struct ibv_xrcd_init_attr *attr,
		      struct ibv_open_xrcd *cmd, size_t cmd_size,
		      struct ib_uverbs_open_xrcd_resp *resp, size_t resp_size)
{
	int ret;

	if (attr->comp_mask >= IBV_XRCD_INIT_ATTR_RESERVED)
		return EOPNOTSUPP;

	if (!(attr->comp_mask & IBV_XRCD_INIT_ATTR_FD) ||
	    !(attr->comp_mask & IBV_XRCD_INIT_ATTR_OFLAGS))
		return EINVAL;

	cmd->fd = attr->fd;
	cmd->oflags = attr->oflags;
	ret = execute_cmd_write(context, IB_USER_VERBS_CMD_OPEN_XRCD, cmd,
				cmd_size, resp, resp_size);
	if (ret)
		return ret;

	xrcd->xrcd.context = context;
	xrcd->comp_mask = 0;
	if (vext_field_avail(struct verbs_xrcd, handle, vxrcd_size)) {
		xrcd->comp_mask = VERBS_XRCD_HANDLE;
		xrcd->handle  = resp->xrcd_handle;
	}

	return 0;
}

int ibv_cmd_reg_mr(struct ibv_pd *pd, void *addr/*待注册的地址*/, size_t length/*待注册的地址长度*/,
		   uint64_t hca_va, int access/*访问标记*/,
		   struct verbs_mr *vmr/*出参，待初始化的变量*/, struct ibv_reg_mr *cmd/*命令变量*/,
		   size_t cmd_size/*命令变量长度*/,
		   struct ib_uverbs_reg_mr_resp *resp, size_t resp_size)
{
	int ret;

	/*填充cmd*/
	cmd->start 	  = (uintptr_t) addr;
	cmd->length 	  = length;
	/* On demand access and entire address space means implicit.
	 * In that case set the value in the command to what kernel expects.
	 */
	if (access & IBV_ACCESS_ON_DEMAND) {
		if (length == SIZE_MAX && addr) {
		    /*长度为max时，addr不能非0*/
			errno = EINVAL;
			return EINVAL;
		}
		if (length == SIZE_MAX)
			cmd->length = UINT64_MAX;
	}

	/*hca_va地址*/
	cmd->hca_va 	  = hca_va;
	/*填充pd_handle*/
	cmd->pd_handle 	  = pd->handle;
	/*访问方式*/
	cmd->access_flags = access;

	/*请求执行memory region注册*/
	ret = execute_cmd_write(pd->context, IB_USER_VERBS_CMD_REG_MR, cmd,
				cmd_size, resp, resp_size);
	if (ret)
		return ret;

	/*使用响应结果*/
	vmr->ibv_mr.handle  = resp->mr_handle;
	vmr->ibv_mr.lkey    = resp->lkey;
	vmr->ibv_mr.rkey    = resp->rkey;
	vmr->ibv_mr.context = pd->context;
	vmr->mr_type        = IBV_MR_TYPE_MR;
	vmr->access = access;

	return 0;
}

int ibv_cmd_rereg_mr(struct verbs_mr *vmr, uint32_t flags, void *addr,
		     size_t length, uint64_t hca_va, int access,
		     struct ibv_pd *pd, struct ibv_rereg_mr *cmd,
		     size_t cmd_sz, struct ib_uverbs_rereg_mr_resp *resp,
		     size_t resp_sz)
{
	int ret;

	cmd->mr_handle	  = vmr->ibv_mr.handle;
	cmd->flags	  = flags;
	cmd->start	  = (uintptr_t)addr;
	cmd->length	  = length;
	cmd->hca_va	  = hca_va;
	cmd->pd_handle	  = (flags & IBV_REREG_MR_CHANGE_PD) ? pd->handle : 0;
	cmd->access_flags = access;

	ret = execute_cmd_write(vmr->ibv_mr.context, IB_USER_VERBS_CMD_REREG_MR,
				cmd, cmd_sz, resp, resp_sz);
	if (ret)
		return ret;

	vmr->ibv_mr.lkey    = resp->lkey;
	vmr->ibv_mr.rkey    = resp->rkey;
	if (flags & IBV_REREG_MR_CHANGE_PD)
		vmr->ibv_mr.context = pd->context;

	return 0;
}

int ibv_cmd_alloc_mw(struct ibv_pd *pd, enum ibv_mw_type type,
		     struct ibv_mw *mw, struct ibv_alloc_mw *cmd,
		     size_t cmd_size,
		     struct ib_uverbs_alloc_mw_resp *resp, size_t resp_size)
{
	int ret;

	cmd->pd_handle	= pd->handle;
	cmd->mw_type	= type;
	memset(cmd->reserved, 0, sizeof(cmd->reserved));

	ret = execute_cmd_write(pd->context, IB_USER_VERBS_CMD_ALLOC_MW, cmd,
				cmd_size, resp, resp_size);
	if (ret)
		return ret;

	mw->context = pd->context;
	mw->pd      = pd;
	mw->rkey    = resp->rkey;
	mw->handle  = resp->mw_handle;
	mw->type    = type;

	return 0;
}

int ibv_cmd_poll_cq(struct ibv_cq *ibcq, int ne, struct ibv_wc *wc)
{
	struct ibv_poll_cq       cmd;
	struct ib_uverbs_poll_cq_resp *resp;
	int                      i;
	int                      rsize;
	int                      ret;

	rsize = sizeof *resp + ne * sizeof(struct ib_uverbs_wc);
	resp  = malloc(rsize);
	if (!resp)
		return -1;

	cmd.cq_handle = ibcq->handle;
	cmd.ne        = ne;

	ret = execute_cmd_write_no_uhw(ibcq->context, IB_USER_VERBS_CMD_POLL_CQ,
				       &cmd, sizeof(cmd), resp, rsize);
	if (ret) {
		ret = -1;
		goto out;
	}

	for (i = 0; i < resp->count; i++) {
		wc[i].wr_id 	     = resp->wc[i].wr_id;
		wc[i].status 	     = resp->wc[i].status;
		wc[i].opcode 	     = resp->wc[i].opcode;
		wc[i].vendor_err     = resp->wc[i].vendor_err;
		wc[i].byte_len 	     = resp->wc[i].byte_len;
		wc[i].imm_data 	     = resp->wc[i].ex.imm_data;
		wc[i].qp_num 	     = resp->wc[i].qp_num;
		wc[i].src_qp 	     = resp->wc[i].src_qp;
		wc[i].wc_flags 	     = resp->wc[i].wc_flags;
		wc[i].pkey_index     = resp->wc[i].pkey_index;
		wc[i].slid 	     = resp->wc[i].slid;
		wc[i].sl 	     = resp->wc[i].sl;
		wc[i].dlid_path_bits = resp->wc[i].dlid_path_bits;
	}

	ret = resp->count;

out:
	free(resp);
	return ret;
}

int ibv_cmd_req_notify_cq(struct ibv_cq *ibcq, int solicited_only)
{
	struct ibv_req_notify_cq req;

	req.core_payload = (struct ib_uverbs_req_notify_cq){
		.cq_handle = ibcq->handle,
		.solicited_only = !!solicited_only,
	};
	return execute_cmd_write_req(ibcq->context,
				     IB_USER_VERBS_CMD_REQ_NOTIFY_CQ, &req,
				     sizeof(req));
}

int ibv_cmd_resize_cq(struct ibv_cq *cq, int cqe,
		      struct ibv_resize_cq *cmd, size_t cmd_size,
		      struct ib_uverbs_resize_cq_resp *resp, size_t resp_size)
{
	int ret;

	cmd->cq_handle = cq->handle;
	cmd->cqe       = cqe;

	ret = execute_cmd_write(cq->context, IB_USER_VERBS_CMD_RESIZE_CQ, cmd,
				cmd_size, resp, resp_size);
	if (ret)
		return ret;

	cq->cqe = resp->cqe;

	return 0;
}

static int ibv_cmd_modify_srq_v3(struct ibv_srq *srq,
				 struct ibv_srq_attr *srq_attr,
				 int srq_attr_mask,
				 struct ibv_modify_srq *new_cmd,
				 size_t new_cmd_size)
{
	struct ibv_modify_srq_v3 *cmd;
	size_t cmd_size;

	cmd_size = sizeof *cmd + new_cmd_size - sizeof *new_cmd;
	cmd      = alloca(cmd_size);
	memcpy(cmd + 1, new_cmd + 1, new_cmd_size - sizeof *new_cmd);

	cmd->core_payload = (struct ib_uverbs_modify_srq_v3){
		.srq_handle = srq->handle,
		.attr_mask = srq_attr_mask,
		.max_wr = srq_attr->max_wr,
		.srq_limit = srq_attr->srq_limit,
	};

	return execute_cmd_write_req(
		srq->context, IB_USER_VERBS_CMD_MODIFY_SRQ_V3, cmd, cmd_size);
}

int ibv_cmd_modify_srq(struct ibv_srq *srq,
		       struct ibv_srq_attr *srq_attr,
		       int srq_attr_mask,
		       struct ibv_modify_srq *cmd, size_t cmd_size)
{
	if (abi_ver == 3)
		return ibv_cmd_modify_srq_v3(srq, srq_attr, srq_attr_mask,
					     cmd, cmd_size);

	cmd->srq_handle	= srq->handle;
	cmd->attr_mask	= srq_attr_mask;
	cmd->max_wr	= srq_attr->max_wr;
	cmd->srq_limit	= srq_attr->srq_limit;

	return execute_cmd_write_req(srq->context, IB_USER_VERBS_CMD_MODIFY_SRQ,
				     cmd, cmd_size);
}

int ibv_cmd_query_srq(struct ibv_srq *srq, struct ibv_srq_attr *srq_attr,
		      struct ibv_query_srq *cmd, size_t cmd_size)
{
	struct ib_uverbs_query_srq_resp resp;
	int ret;

	cmd->srq_handle = srq->handle;
	cmd->reserved   = 0;

	ret = execute_cmd_write(srq->context, IB_USER_VERBS_CMD_QUERY_SRQ, cmd,
				cmd_size, &resp, sizeof(resp));
	if (ret)
		return ret;

	srq_attr->max_wr    = resp.max_wr;
	srq_attr->max_sge   = resp.max_sge;
	srq_attr->srq_limit = resp.srq_limit;

	return 0;
}

enum {
	CREATE_QP_EX2_SUP_CREATE_FLAGS = IBV_QP_CREATE_BLOCK_SELF_MCAST_LB |
					 IBV_QP_CREATE_SCATTER_FCS |
					 IBV_QP_CREATE_CVLAN_STRIPPING |
					 IBV_QP_CREATE_SOURCE_QPN |
					 IBV_QP_CREATE_PCI_WRITE_END_PADDING,
};

int ibv_cmd_open_qp(struct ibv_context *context, struct verbs_qp *qp,
		    int vqp_sz,
		    struct ibv_qp_open_attr *attr,
		    struct ibv_open_qp *cmd, size_t cmd_size,
		    struct ib_uverbs_create_qp_resp *resp, size_t resp_size)
{
	struct verbs_xrcd *xrcd;
	int ret;

	if (attr->comp_mask >= IBV_QP_OPEN_ATTR_RESERVED)
		return EOPNOTSUPP;

	if (!(attr->comp_mask & IBV_QP_OPEN_ATTR_XRCD) ||
	    !(attr->comp_mask & IBV_QP_OPEN_ATTR_NUM) ||
	    !(attr->comp_mask & IBV_QP_OPEN_ATTR_TYPE))
		return EINVAL;

	xrcd = container_of(attr->xrcd, struct verbs_xrcd, xrcd);
	cmd->user_handle = (uintptr_t) qp;
	cmd->pd_handle   = xrcd->handle;
	cmd->qpn         = attr->qp_num;
	cmd->qp_type     = attr->qp_type;

	ret = execute_cmd_write(context, IB_USER_VERBS_CMD_OPEN_QP, cmd,
				cmd_size, resp, resp_size);
	if (ret)
		return ret;

	qp->qp.handle     = resp->qp_handle;
	qp->qp.context    = context;
	qp->qp.qp_context = attr->qp_context;
	qp->qp.pd	  = NULL;
	qp->qp.send_cq	  = NULL;
	qp->qp.recv_cq    = NULL;
	qp->qp.srq	  = NULL;
	qp->qp.qp_num	  = attr->qp_num;
	qp->qp.qp_type	  = attr->qp_type;
	qp->qp.state	  = IBV_QPS_UNKNOWN;
	qp->qp.events_completed = 0;
	pthread_mutex_init(&qp->qp.mutex, NULL);
	pthread_cond_init(&qp->qp.cond, NULL);
	qp->comp_mask = 0;
	if (vext_field_avail(struct verbs_qp, xrcd, vqp_sz)) {
		qp->comp_mask = VERBS_QP_XRCD;
		qp->xrcd	 = xrcd;
	}

	return 0;
}

int ibv_cmd_query_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		     int attr_mask/*属性mask*/,
		     struct ibv_qp_init_attr *init_attr,
		     struct ibv_query_qp *cmd, size_t cmd_size)
{
	struct ib_uverbs_query_qp_resp resp;
	int ret;

	/*
	 * Starting with IBV_QP_RATE_LIMIT the attribute must go through the
	 * _ex path.
	 */
	if (attr_mask & ~(IBV_QP_RATE_LIMIT - 1))
		return EOPNOTSUPP;

	/*设置qp handle*/
	cmd->qp_handle = qp->handle;
	cmd->attr_mask = attr_mask;

	ret = execute_cmd_write(qp->context, IB_USER_VERBS_CMD_QUERY_QP, cmd,
				cmd_size, &resp, sizeof(resp));
	if (ret)
		return ret;

	attr->qkey                          = resp.qkey;
	attr->rq_psn                        = resp.rq_psn;
	attr->sq_psn                        = resp.sq_psn;
	attr->dest_qp_num                   = resp.dest_qp_num;
	attr->qp_access_flags               = resp.qp_access_flags;
	attr->pkey_index                    = resp.pkey_index;
	attr->alt_pkey_index                = resp.alt_pkey_index;
	attr->qp_state                      = resp.qp_state;
	attr->cur_qp_state                  = resp.cur_qp_state;
	attr->path_mtu                      = resp.path_mtu;
	attr->path_mig_state                = resp.path_mig_state;
	attr->sq_draining                   = resp.sq_draining;
	attr->max_rd_atomic                 = resp.max_rd_atomic;
	attr->max_dest_rd_atomic            = resp.max_dest_rd_atomic;
	attr->min_rnr_timer                 = resp.min_rnr_timer;
	attr->port_num                      = resp.port_num;
	attr->timeout                       = resp.timeout;
	attr->retry_cnt                     = resp.retry_cnt;
	attr->rnr_retry                     = resp.rnr_retry;
	attr->alt_port_num                  = resp.alt_port_num;
	attr->alt_timeout                   = resp.alt_timeout;
	attr->cap.max_send_wr               = resp.max_send_wr;
	attr->cap.max_recv_wr               = resp.max_recv_wr;
	attr->cap.max_send_sge              = resp.max_send_sge;
	attr->cap.max_recv_sge              = resp.max_recv_sge;
	attr->cap.max_inline_data           = resp.max_inline_data;

	memcpy(attr->ah_attr.grh.dgid.raw, resp.dest.dgid, 16);
	attr->ah_attr.grh.flow_label        = resp.dest.flow_label;
	attr->ah_attr.dlid                  = resp.dest.dlid;
	attr->ah_attr.grh.sgid_index        = resp.dest.sgid_index;
	attr->ah_attr.grh.hop_limit         = resp.dest.hop_limit;
	attr->ah_attr.grh.traffic_class     = resp.dest.traffic_class;
	attr->ah_attr.sl                    = resp.dest.sl;
	attr->ah_attr.src_path_bits         = resp.dest.src_path_bits;
	attr->ah_attr.static_rate           = resp.dest.static_rate;
	attr->ah_attr.is_global             = resp.dest.is_global;
	attr->ah_attr.port_num              = resp.dest.port_num;

	memcpy(attr->alt_ah_attr.grh.dgid.raw, resp.alt_dest.dgid, 16);
	attr->alt_ah_attr.grh.flow_label    = resp.alt_dest.flow_label;
	attr->alt_ah_attr.dlid              = resp.alt_dest.dlid;
	attr->alt_ah_attr.grh.sgid_index    = resp.alt_dest.sgid_index;
	attr->alt_ah_attr.grh.hop_limit     = resp.alt_dest.hop_limit;
	attr->alt_ah_attr.grh.traffic_class = resp.alt_dest.traffic_class;
	attr->alt_ah_attr.sl                = resp.alt_dest.sl;
	attr->alt_ah_attr.src_path_bits     = resp.alt_dest.src_path_bits;
	attr->alt_ah_attr.static_rate       = resp.alt_dest.static_rate;
	attr->alt_ah_attr.is_global         = resp.alt_dest.is_global;
	attr->alt_ah_attr.port_num          = resp.alt_dest.port_num;

	init_attr->qp_context               = qp->qp_context;
	init_attr->send_cq                  = qp->send_cq;
	init_attr->recv_cq                  = qp->recv_cq;
	init_attr->srq                      = qp->srq;
	init_attr->qp_type                  = qp->qp_type;
	init_attr->cap.max_send_wr          = resp.max_send_wr;
	init_attr->cap.max_recv_wr          = resp.max_recv_wr;
	init_attr->cap.max_send_sge         = resp.max_send_sge;
	init_attr->cap.max_recv_sge         = resp.max_recv_sge;
	init_attr->cap.max_inline_data      = resp.max_inline_data;
	init_attr->sq_sig_all               = resp.sq_sig_all;

	return 0;
}

static void copy_modify_qp_fields(struct ibv_qp *qp, struct ibv_qp_attr *attr,
				  int attr_mask,
				  struct ib_uverbs_modify_qp *cmd)
{
	cmd->qp_handle = qp->handle;
	cmd->attr_mask = attr_mask;

	/*按属性设置mask设置相应字段*/
	if (attr_mask & IBV_QP_STATE)
		cmd->qp_state = attr->qp_state;
	if (attr_mask & IBV_QP_CUR_STATE)
		cmd->cur_qp_state = attr->cur_qp_state;
	if (attr_mask & IBV_QP_EN_SQD_ASYNC_NOTIFY)
		cmd->en_sqd_async_notify = attr->en_sqd_async_notify;
	if (attr_mask & IBV_QP_ACCESS_FLAGS)
		cmd->qp_access_flags = attr->qp_access_flags;
	if (attr_mask & IBV_QP_PKEY_INDEX)
		cmd->pkey_index = attr->pkey_index;
	if (attr_mask & IBV_QP_PORT)
		cmd->port_num = attr->port_num;
	if (attr_mask & IBV_QP_QKEY)
		cmd->qkey = attr->qkey;

	/*如果指定了av*/
	if (attr_mask & IBV_QP_AV) {
		memcpy(cmd->dest.dgid, attr->ah_attr.grh.dgid.raw, 16);
		cmd->dest.flow_label = attr->ah_attr.grh.flow_label;
		cmd->dest.dlid = attr->ah_attr.dlid;
		cmd->dest.reserved = 0;
		cmd->dest.sgid_index = attr->ah_attr.grh.sgid_index;
		cmd->dest.hop_limit = attr->ah_attr.grh.hop_limit;
		cmd->dest.traffic_class = attr->ah_attr.grh.traffic_class;
		cmd->dest.sl = attr->ah_attr.sl;
		cmd->dest.src_path_bits = attr->ah_attr.src_path_bits;
		cmd->dest.static_rate = attr->ah_attr.static_rate;
		cmd->dest.is_global = attr->ah_attr.is_global;
		cmd->dest.port_num = attr->ah_attr.port_num;
	}

	if (attr_mask & IBV_QP_PATH_MTU)
		cmd->path_mtu = attr->path_mtu;
	if (attr_mask & IBV_QP_TIMEOUT)
		cmd->timeout = attr->timeout;
	if (attr_mask & IBV_QP_RETRY_CNT)
		cmd->retry_cnt = attr->retry_cnt;
	if (attr_mask & IBV_QP_RNR_RETRY)
		cmd->rnr_retry = attr->rnr_retry;
	if (attr_mask & IBV_QP_RQ_PSN)
		cmd->rq_psn = attr->rq_psn;
	if (attr_mask & IBV_QP_MAX_QP_RD_ATOMIC)
		cmd->max_rd_atomic = attr->max_rd_atomic;

	/*设置alt*/
	if (attr_mask & IBV_QP_ALT_PATH) {
		cmd->alt_pkey_index = attr->alt_pkey_index;
		cmd->alt_port_num = attr->alt_port_num;
		cmd->alt_timeout = attr->alt_timeout;

		memcpy(cmd->alt_dest.dgid, attr->alt_ah_attr.grh.dgid.raw, 16);
		cmd->alt_dest.flow_label = attr->alt_ah_attr.grh.flow_label;
		cmd->alt_dest.dlid = attr->alt_ah_attr.dlid;
		cmd->alt_dest.reserved = 0;
		cmd->alt_dest.sgid_index = attr->alt_ah_attr.grh.sgid_index;
		cmd->alt_dest.hop_limit = attr->alt_ah_attr.grh.hop_limit;
		cmd->alt_dest.traffic_class =
		    attr->alt_ah_attr.grh.traffic_class;
		cmd->alt_dest.sl = attr->alt_ah_attr.sl;
		cmd->alt_dest.src_path_bits = attr->alt_ah_attr.src_path_bits;
		cmd->alt_dest.static_rate = attr->alt_ah_attr.static_rate;
		cmd->alt_dest.is_global = attr->alt_ah_attr.is_global;
		cmd->alt_dest.port_num = attr->alt_ah_attr.port_num;
	}

	if (attr_mask & IBV_QP_MIN_RNR_TIMER)
		cmd->min_rnr_timer = attr->min_rnr_timer;
	if (attr_mask & IBV_QP_SQ_PSN)
		cmd->sq_psn = attr->sq_psn;
	if (attr_mask & IBV_QP_MAX_DEST_RD_ATOMIC)
		cmd->max_dest_rd_atomic = attr->max_dest_rd_atomic;
	if (attr_mask & IBV_QP_PATH_MIG_STATE)
		cmd->path_mig_state = attr->path_mig_state;
	if (attr_mask & IBV_QP_DEST_QPN)
		cmd->dest_qp_num = attr->dest_qp_num;

	cmd->reserved[0] = cmd->reserved[1] = 0;
}

int ibv_cmd_modify_qp(struct ibv_qp *qp, struct ibv_qp_attr *attr,
		      int attr_mask,
		      struct ibv_modify_qp *cmd, size_t cmd_size)
{
	/*
	 * Starting with IBV_QP_RATE_LIMIT the attribute must go through the
	 * _ex path.
	 */
	if (attr_mask & ~(IBV_QP_RATE_LIMIT - 1))
	    /*遇到不支持的mask,返回not support*/
		return EOPNOTSUPP;

	/*设置属性fields*/
	copy_modify_qp_fields(qp, attr, attr_mask, &cmd->core_payload);

	/*执行qp修改*/
	return execute_cmd_write_req(qp->context, IB_USER_VERBS_CMD_MODIFY_QP,
				     cmd, cmd_size);
}

int ibv_cmd_modify_qp_ex(struct ibv_qp *qp, struct ibv_qp_attr *attr,
			 int attr_mask, struct ibv_modify_qp_ex *cmd,
			 size_t cmd_size,
			 struct ib_uverbs_ex_modify_qp_resp *resp,
			 size_t resp_size)
{
	copy_modify_qp_fields(qp, attr, attr_mask, &cmd->base);

	if (attr_mask & IBV_QP_RATE_LIMIT) {
		if (cmd_size >= offsetof(struct ibv_modify_qp_ex, rate_limit) +
		    sizeof(cmd->rate_limit))
			cmd->rate_limit = attr->rate_limit;
		else
			return EINVAL;
	}

	return execute_cmd_write_ex(qp->context, IB_USER_VERBS_EX_CMD_MODIFY_QP,
				    cmd, cmd_size, resp, resp_size);
}

int ibv_cmd_post_send(struct ibv_qp *ibqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad_wr)
{
	struct ibv_post_send     *cmd;
	struct ib_uverbs_post_send_resp resp;
	struct ibv_send_wr       *i;
	struct ib_uverbs_send_wr  *n, *tmp;
	struct ibv_sge           *s;
	unsigned                  wr_count = 0;
	unsigned                  sge_count = 0;
	int                       cmd_size;
	int                       ret;

	for (i = wr; i; i = i->next) {
		wr_count++;
		sge_count += i->num_sge;
	}

	cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	cmd  = alloca(cmd_size);

	cmd->qp_handle = ibqp->handle;
	cmd->wr_count  = wr_count;
	cmd->sge_count = sge_count;
	cmd->wqe_size  = sizeof *n;

	n = (struct ib_uverbs_send_wr *) ((void *) cmd + sizeof *cmd);
	s = (struct ibv_sge *) (n + wr_count);

	tmp = n;
	for (i = wr; i; i = i->next) {
		tmp->wr_id 	= i->wr_id;
		tmp->num_sge 	= i->num_sge;
		tmp->opcode 	= i->opcode;
		tmp->send_flags = i->send_flags;
		tmp->ex.imm_data = i->imm_data;
		if (ibqp->qp_type == IBV_QPT_UD) {
			tmp->wr.ud.ah 	       = i->wr.ud.ah->handle;
			tmp->wr.ud.remote_qpn  = i->wr.ud.remote_qpn;
			tmp->wr.ud.remote_qkey = i->wr.ud.remote_qkey;
		} else {
			switch (i->opcode) {
			case IBV_WR_RDMA_WRITE:
			case IBV_WR_RDMA_WRITE_WITH_IMM:
			case IBV_WR_RDMA_READ:
				tmp->wr.rdma.remote_addr =
					i->wr.rdma.remote_addr;
				tmp->wr.rdma.rkey = i->wr.rdma.rkey;
				break;
			case IBV_WR_ATOMIC_CMP_AND_SWP:
			case IBV_WR_ATOMIC_FETCH_AND_ADD:
				tmp->wr.atomic.remote_addr =
					i->wr.atomic.remote_addr;
				tmp->wr.atomic.compare_add =
					i->wr.atomic.compare_add;
				tmp->wr.atomic.swap = i->wr.atomic.swap;
				tmp->wr.atomic.rkey = i->wr.atomic.rkey;
				break;
			default:
				break;
			}
		}

		if (tmp->num_sge) {
			memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
			s += tmp->num_sge;
		}

		tmp++;
	}

	resp.bad_wr = 0;
	ret = execute_cmd_write_no_uhw(ibqp->context,
				       IB_USER_VERBS_CMD_POST_SEND, cmd,
				       cmd_size, &resp, sizeof(resp));

	wr_count = resp.bad_wr;
	if (wr_count) {
		i = wr;
		while (--wr_count)
			i = i->next;
		*bad_wr = i;
	} else if (ret)
		*bad_wr = wr;

	return ret;
}

int ibv_cmd_post_recv(struct ibv_qp *ibqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct ibv_post_recv     *cmd;
	struct ib_uverbs_post_recv_resp resp;
	struct ibv_recv_wr       *i;
	struct ib_uverbs_recv_wr  *n, *tmp;
	struct ibv_sge           *s;
	unsigned                  wr_count = 0;
	unsigned                  sge_count = 0;
	int                       cmd_size;
	int                       ret;

	for (i = wr; i; i = i->next) {
		wr_count++;
		sge_count += i->num_sge;
	}

	cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	cmd  = alloca(cmd_size);

	cmd->qp_handle = ibqp->handle;
	cmd->wr_count  = wr_count;
	cmd->sge_count = sge_count;
	cmd->wqe_size  = sizeof *n;

	n = (struct ib_uverbs_recv_wr *) ((void *) cmd + sizeof *cmd);
	s = (struct ibv_sge *) (n + wr_count);

	tmp = n;
	for (i = wr; i; i = i->next) {
		tmp->wr_id   = i->wr_id;
		tmp->num_sge = i->num_sge;

		if (tmp->num_sge) {
			memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
			s += tmp->num_sge;
		}

		tmp++;
	}

	resp.bad_wr = 0;
	ret = execute_cmd_write_no_uhw(ibqp->context,
				       IB_USER_VERBS_CMD_POST_RECV, cmd,
				       cmd_size, &resp, sizeof(resp));

	wr_count = resp.bad_wr;
	if (wr_count) {
		i = wr;
		while (--wr_count)
			i = i->next;
		*bad_wr = i;
	} else if (ret)
		*bad_wr = wr;

	return ret;
}

int ibv_cmd_post_srq_recv(struct ibv_srq *srq, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad_wr)
{
	struct ibv_post_srq_recv *cmd;
	struct ib_uverbs_post_srq_recv_resp resp;
	struct ibv_recv_wr       *i;
	struct ib_uverbs_recv_wr  *n, *tmp;
	struct ibv_sge           *s;
	unsigned                  wr_count = 0;
	unsigned                  sge_count = 0;
	int                       cmd_size;
	int                       ret;

	for (i = wr; i; i = i->next) {
		wr_count++;
		sge_count += i->num_sge;
	}

	cmd_size = sizeof *cmd + wr_count * sizeof *n + sge_count * sizeof *s;
	cmd  = alloca(cmd_size);

	cmd->srq_handle = srq->handle;
	cmd->wr_count  = wr_count;
	cmd->sge_count = sge_count;
	cmd->wqe_size  = sizeof *n;

	n = (struct ib_uverbs_recv_wr *) ((void *) cmd + sizeof *cmd);
	s = (struct ibv_sge *) (n + wr_count);

	tmp = n;
	for (i = wr; i; i = i->next) {
		tmp->wr_id = i->wr_id;
		tmp->num_sge = i->num_sge;

		if (tmp->num_sge) {
			memcpy(s, i->sg_list, tmp->num_sge * sizeof *s);
			s += tmp->num_sge;
		}

		tmp++;
	}

	resp.bad_wr = 0;
	ret = execute_cmd_write_no_uhw(srq->context,
				       IB_USER_VERBS_CMD_POST_SRQ_RECV, cmd,
				       cmd_size, &resp, sizeof(resp));

	wr_count = resp.bad_wr;
	if (wr_count) {
		i = wr;
		while (--wr_count)
			i = i->next;
		*bad_wr = i;
	} else if (ret)
		*bad_wr = wr;

	return ret;
}

int ibv_cmd_create_ah(struct ibv_pd *pd, struct ibv_ah *ah,
		      struct ibv_ah_attr *attr,
		      struct ib_uverbs_create_ah_resp *resp,
		      size_t resp_size)
{
	struct ibv_create_ah      cmd;
	int ret;

	cmd.user_handle            = (uintptr_t) ah;
	cmd.pd_handle              = pd->handle;
	cmd.reserved               = 0;
	cmd.attr.dlid              = attr->dlid;
	cmd.attr.sl                = attr->sl;
	cmd.attr.src_path_bits     = attr->src_path_bits;
	cmd.attr.static_rate       = attr->static_rate;
	cmd.attr.is_global         = attr->is_global;
	cmd.attr.port_num          = attr->port_num;
	cmd.attr.reserved          = 0;
	cmd.attr.grh.flow_label    = attr->grh.flow_label;
	cmd.attr.grh.sgid_index    = attr->grh.sgid_index;
	cmd.attr.grh.hop_limit     = attr->grh.hop_limit;
	cmd.attr.grh.traffic_class = attr->grh.traffic_class;
	cmd.attr.grh.reserved      = 0;
	memcpy(cmd.attr.grh.dgid, attr->grh.dgid.raw, 16);

	ret = execute_cmd_write(pd->context, IB_USER_VERBS_CMD_CREATE_AH, &cmd,
				sizeof(cmd), resp, resp_size);
	if (ret)
		return ret;

	ah->handle  = resp->ah_handle;
	ah->context = pd->context;

	return 0;
}

int ibv_cmd_attach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	struct ibv_attach_mcast req;

	req.core_payload = (struct ib_uverbs_attach_mcast){
		.qp_handle = qp->handle,
		.mlid = lid,
	};
	memcpy(req.gid, gid->raw, sizeof(req.gid));
	return execute_cmd_write_req(
		qp->context, IB_USER_VERBS_CMD_ATTACH_MCAST, &req, sizeof(req));
}

int ibv_cmd_detach_mcast(struct ibv_qp *qp, const union ibv_gid *gid, uint16_t lid)
{
	struct ibv_detach_mcast req;
	int ret;

	req.core_payload = (struct ib_uverbs_detach_mcast){
		.qp_handle = qp->handle,
		.mlid = lid,
	};
	memcpy(req.gid, gid->raw, sizeof(req.gid));
	ret = execute_cmd_write_req(qp->context, IB_USER_VERBS_CMD_DETACH_MCAST,
				    &req, sizeof(req));
	if (verbs_is_destroy_err(&ret))
		return ret;

	return 0;
}

static int buffer_is_zero(char *addr, ssize_t size)
{
	return addr[0] == 0 && !memcmp(addr, addr + 1, size - 1);
}

static int get_filters_size(struct ibv_flow_spec *ib_spec,
			    struct ibv_kern_spec *kern_spec,
			    int *ib_filter_size, int *kern_filter_size,
			    enum ibv_flow_spec_type type)
{
	void *ib_spec_filter_mask;
	int curr_kern_filter_size;
	int min_filter_size;

	*ib_filter_size = (ib_spec->hdr.size - sizeof(ib_spec->hdr)) / 2;

	switch (type) {
	case IBV_FLOW_SPEC_IPV4_EXT:
		min_filter_size =
			offsetof(struct ib_uverbs_flow_ipv4_filter, flags) +
			sizeof(kern_spec->ipv4_ext.mask.flags);
		curr_kern_filter_size = min_filter_size;
		ib_spec_filter_mask = (void *)&ib_spec->ipv4_ext.val +
			*ib_filter_size;
		break;
	case IBV_FLOW_SPEC_IPV6:
		min_filter_size =
			offsetof(struct ib_uverbs_flow_ipv6_filter, hop_limit) +
			sizeof(kern_spec->ipv6.mask.hop_limit);
		curr_kern_filter_size = min_filter_size;
		ib_spec_filter_mask = (void *)&ib_spec->ipv6.val +
			*ib_filter_size;
		break;
	case IBV_FLOW_SPEC_VXLAN_TUNNEL:
		min_filter_size =
			offsetof(struct ib_uverbs_flow_tunnel_filter,
				 tunnel_id) +
			sizeof(kern_spec->tunnel.mask.tunnel_id);
		curr_kern_filter_size = min_filter_size;
		ib_spec_filter_mask = (void *)&ib_spec->tunnel.val +
			*ib_filter_size;
		break;
	default:
		return EINVAL;
	}

	if (*ib_filter_size < min_filter_size)
		return EINVAL;

	if (*ib_filter_size > curr_kern_filter_size &&
	    !buffer_is_zero(ib_spec_filter_mask + curr_kern_filter_size,
			    *ib_filter_size - curr_kern_filter_size))
		return EOPNOTSUPP;

	*kern_filter_size = min_t(int, curr_kern_filter_size, *ib_filter_size);

	return 0;
}

static int ib_spec_to_kern_spec(struct ibv_flow_spec *ib_spec,
				struct ibv_kern_spec *kern_spec)
{
	int kern_filter_size;
	int ib_filter_size;
	int ret;

	kern_spec->hdr.type = ib_spec->hdr.type;

	switch (kern_spec->hdr.type) {
	case IBV_FLOW_SPEC_ETH:
	case IBV_FLOW_SPEC_ETH | IBV_FLOW_SPEC_INNER:
		kern_spec->eth.size = sizeof(struct ib_uverbs_flow_spec_eth);
		memcpy(&kern_spec->eth.val, &ib_spec->eth.val,
		       sizeof(struct ibv_flow_eth_filter));
		memcpy(&kern_spec->eth.mask, &ib_spec->eth.mask,
		       sizeof(struct ibv_flow_eth_filter));
		break;
	case IBV_FLOW_SPEC_IPV4:
	case IBV_FLOW_SPEC_IPV4 | IBV_FLOW_SPEC_INNER:
		kern_spec->ipv4.size = sizeof(struct ibv_kern_spec_ipv4);
		memcpy(&kern_spec->ipv4.val, &ib_spec->ipv4.val,
		       sizeof(struct ibv_flow_ipv4_filter));
		memcpy(&kern_spec->ipv4.mask, &ib_spec->ipv4.mask,
		       sizeof(struct ibv_flow_ipv4_filter));
		break;
	case IBV_FLOW_SPEC_IPV4_EXT:
	case IBV_FLOW_SPEC_IPV4_EXT | IBV_FLOW_SPEC_INNER:
		ret = get_filters_size(ib_spec, kern_spec,
				       &ib_filter_size, &kern_filter_size,
				       IBV_FLOW_SPEC_IPV4_EXT);
		if (ret)
			return ret;

		kern_spec->hdr.type = IBV_FLOW_SPEC_IPV4 |
				     (IBV_FLOW_SPEC_INNER & ib_spec->hdr.type);
		kern_spec->ipv4_ext.size = sizeof(struct
						  ib_uverbs_flow_spec_ipv4);
		memcpy(&kern_spec->ipv4_ext.val, &ib_spec->ipv4_ext.val,
		       kern_filter_size);
		memcpy(&kern_spec->ipv4_ext.mask, (void *)&ib_spec->ipv4_ext.val
		       + ib_filter_size, kern_filter_size);
		break;
	case IBV_FLOW_SPEC_IPV6:
	case IBV_FLOW_SPEC_IPV6 | IBV_FLOW_SPEC_INNER:
		ret = get_filters_size(ib_spec, kern_spec,
				       &ib_filter_size, &kern_filter_size,
				       IBV_FLOW_SPEC_IPV6);
		if (ret)
			return ret;

		kern_spec->ipv6.size = sizeof(struct ib_uverbs_flow_spec_ipv6);
		memcpy(&kern_spec->ipv6.val, &ib_spec->ipv6.val,
		       kern_filter_size);
		memcpy(&kern_spec->ipv6.mask, (void *)&ib_spec->ipv6.val
		       + ib_filter_size, kern_filter_size);
		break;
	case IBV_FLOW_SPEC_ESP:
	case IBV_FLOW_SPEC_ESP | IBV_FLOW_SPEC_INNER:
		kern_spec->esp.size = sizeof(struct ib_uverbs_flow_spec_esp);
		memcpy(&kern_spec->esp.val, &ib_spec->esp.val,
		       sizeof(struct ib_uverbs_flow_spec_esp_filter));
		memcpy(&kern_spec->esp.mask, (void *)&ib_spec->esp.mask,
		       sizeof(struct ib_uverbs_flow_spec_esp_filter));
		break;
	case IBV_FLOW_SPEC_TCP:
	case IBV_FLOW_SPEC_UDP:
	case IBV_FLOW_SPEC_TCP | IBV_FLOW_SPEC_INNER:
	case IBV_FLOW_SPEC_UDP | IBV_FLOW_SPEC_INNER:
		kern_spec->tcp_udp.size = sizeof(struct ib_uverbs_flow_spec_tcp_udp);
		memcpy(&kern_spec->tcp_udp.val, &ib_spec->tcp_udp.val,
		       sizeof(struct ibv_flow_tcp_udp_filter));
		memcpy(&kern_spec->tcp_udp.mask, &ib_spec->tcp_udp.mask,
		       sizeof(struct ibv_flow_tcp_udp_filter));
		break;
	case IBV_FLOW_SPEC_GRE:
		kern_spec->gre.size = sizeof(struct ib_uverbs_flow_spec_gre);
		memcpy(&kern_spec->gre.val, &ib_spec->gre.val,
		       sizeof(struct ibv_flow_gre_filter));
		memcpy(&kern_spec->gre.mask, &ib_spec->gre.mask,
		       sizeof(struct ibv_flow_gre_filter));
		break;
	case IBV_FLOW_SPEC_MPLS:
	case IBV_FLOW_SPEC_MPLS | IBV_FLOW_SPEC_INNER:
		kern_spec->mpls.size = sizeof(struct ib_uverbs_flow_spec_mpls);
		memcpy(&kern_spec->mpls.val, &ib_spec->mpls.val,
		       sizeof(struct ibv_flow_mpls_filter));
		memcpy(&kern_spec->mpls.mask, &ib_spec->mpls.mask,
		       sizeof(struct ibv_flow_mpls_filter));
		break;
	case IBV_FLOW_SPEC_VXLAN_TUNNEL:
		ret = get_filters_size(ib_spec, kern_spec,
				       &ib_filter_size, &kern_filter_size,
				       IBV_FLOW_SPEC_VXLAN_TUNNEL);
		if (ret)
			return ret;

		kern_spec->tunnel.size = sizeof(struct ib_uverbs_flow_spec_tunnel);
		memcpy(&kern_spec->tunnel.val, &ib_spec->tunnel.val,
		       kern_filter_size);
		memcpy(&kern_spec->tunnel.mask, (void *)&ib_spec->tunnel.val
		       + ib_filter_size, kern_filter_size);
		break;
	case IBV_FLOW_SPEC_ACTION_TAG:
		kern_spec->flow_tag.size =
			sizeof(struct ib_uverbs_flow_spec_action_tag);
		kern_spec->flow_tag.tag_id = ib_spec->flow_tag.tag_id;
		break;
	case IBV_FLOW_SPEC_ACTION_DROP:
		kern_spec->drop.size = sizeof(struct ib_uverbs_flow_spec_action_drop);
		break;
	case IBV_FLOW_SPEC_ACTION_HANDLE: {
		const struct verbs_flow_action *vaction =
			container_of((const struct ibv_flow_action *)ib_spec->handle.action,
				     const struct verbs_flow_action, action);
		kern_spec->handle.size = sizeof(struct ib_uverbs_flow_spec_action_handle);
		kern_spec->handle.handle = vaction->handle;
		break;
	}
	case IBV_FLOW_SPEC_ACTION_COUNT: {
		const struct verbs_counters *vcounters =
			container_of(ib_spec->flow_count.counters,
				     const struct verbs_counters, counters);
		kern_spec->flow_count.size =
			sizeof(struct ib_uverbs_flow_spec_action_count);
		kern_spec->flow_count.handle = vcounters->handle;
		break;
	}
	default:
		return EINVAL;
	}
	return 0;
}

int ibv_cmd_create_flow(struct ibv_qp *qp,
			struct ibv_flow *flow_id,
			struct ibv_flow_attr *flow_attr,
			void *ucmd,
			size_t ucmd_size)
{
	struct ibv_create_flow *cmd;
	struct ib_uverbs_create_flow_resp resp;
	size_t cmd_size;
	size_t written_size;
	int i, err;
	void *kern_spec;
	void *ib_spec;

	cmd_size = sizeof(*cmd) + (flow_attr->num_of_specs *
				  sizeof(struct ibv_kern_spec));
	cmd = alloca(cmd_size + ucmd_size);
	memset(cmd, 0, cmd_size + ucmd_size);

	cmd->qp_handle = qp->handle;

	cmd->flow_attr.type = flow_attr->type;
	cmd->flow_attr.priority = flow_attr->priority;
	cmd->flow_attr.num_of_specs = flow_attr->num_of_specs;
	cmd->flow_attr.port = flow_attr->port;
	cmd->flow_attr.flags = flow_attr->flags;

	kern_spec = cmd + 1;
	ib_spec = flow_attr + 1;
	for (i = 0; i < flow_attr->num_of_specs; i++) {
		err = ib_spec_to_kern_spec(ib_spec, kern_spec);
		if (err) {
			errno = err;
			return err;
		}
		cmd->flow_attr.size +=
			((struct ibv_kern_spec *)kern_spec)->hdr.size;
		kern_spec += ((struct ibv_kern_spec *)kern_spec)->hdr.size;
		ib_spec += ((struct ibv_flow_spec *)ib_spec)->hdr.size;
	}

	written_size = sizeof(*cmd) + cmd->flow_attr.size;
	if (ucmd) {
		memcpy((char *)cmd + written_size, ucmd, ucmd_size);
		written_size += ucmd_size;
	}

	err = execute_cmd_write_ex_full(qp->context,
					IB_USER_VERBS_EX_CMD_CREATE_FLOW, cmd,
					written_size - ucmd_size, written_size,
					&resp, sizeof(resp), sizeof(resp));
	if (err)
		return err;

	flow_id->context = qp->context;
	flow_id->handle = resp.flow_handle;
	return 0;
}

int ibv_cmd_modify_wq(struct ibv_wq *wq, struct ibv_wq_attr *attr,
		      struct ibv_modify_wq *cmd, size_t cmd_size)
{
	int err;

	if (attr->attr_mask >= IBV_WQ_ATTR_RESERVED)
		return EINVAL;

	memset(cmd, 0, sizeof(*cmd));

	cmd->curr_wq_state = attr->curr_wq_state;
	cmd->wq_state = attr->wq_state;
	if (attr->attr_mask & IBV_WQ_ATTR_FLAGS) {
		if (attr->flags_mask & ~(IBV_WQ_FLAGS_RESERVED - 1))
			return EOPNOTSUPP;
		cmd->flags = attr->flags;
		cmd->flags_mask = attr->flags_mask;
	}
	cmd->wq_handle = wq->handle;
	cmd->attr_mask = attr->attr_mask;

	err = execute_cmd_write_ex_req(
		wq->context, IB_USER_VERBS_EX_CMD_MODIFY_WQ, cmd, cmd_size);
	if (err)
		return err;

	if (attr->attr_mask & IBV_WQ_ATTR_STATE)
		wq->state = attr->wq_state;

	return 0;
}

int ibv_cmd_create_rwq_ind_table(struct ibv_context *context,
				 struct ibv_rwq_ind_table_init_attr *init_attr,
				 struct ibv_rwq_ind_table *rwq_ind_table,
				 struct ib_uverbs_ex_create_rwq_ind_table_resp *resp,
				 size_t resp_size)
{
	struct ibv_create_rwq_ind_table *cmd;
	int err;
	unsigned int i;
	unsigned int num_tbl_entries;
	size_t cmd_size;

	if (init_attr->comp_mask >= IBV_CREATE_IND_TABLE_RESERVED)
		return EINVAL;

	num_tbl_entries = 1 << init_attr->log_ind_tbl_size;

	/* The entire message must be size aligned to 8 bytes. */
	cmd_size = sizeof(*cmd) + num_tbl_entries * sizeof(cmd->wq_handles[0]);
	cmd_size = (cmd_size + 7) / 8 * 8;
	cmd = alloca(cmd_size);
	memset(cmd, 0, cmd_size);

	for (i = 0; i < num_tbl_entries; i++)
		cmd->wq_handles[i] = init_attr->ind_tbl[i]->handle;

	cmd->log_ind_tbl_size = init_attr->log_ind_tbl_size;
	cmd->comp_mask = 0;

	err = execute_cmd_write_ex_full(context,
					IB_USER_VERBS_EX_CMD_CREATE_RWQ_IND_TBL,
					cmd, cmd_size, cmd_size, resp,
					sizeof(*resp), resp_size);
	if (err)
		return err;

	if (resp->response_length < sizeof(*resp))
		return EINVAL;

	rwq_ind_table->ind_tbl_handle = resp->ind_tbl_handle;
	rwq_ind_table->ind_tbl_num = resp->ind_tbl_num;
	rwq_ind_table->context = context;
	return 0;
}

int ibv_cmd_modify_cq(struct ibv_cq *cq,
		      struct ibv_modify_cq_attr *attr,
		      struct ibv_modify_cq *cmd,
		      size_t cmd_size)
{

	if (attr->attr_mask >= IBV_CQ_ATTR_RESERVED)
		return EINVAL;

	cmd->cq_handle = cq->handle;
	cmd->attr_mask = attr->attr_mask;
	cmd->attr.cq_count =  attr->moderate.cq_count;
	cmd->attr.cq_period = attr->moderate.cq_period;
	cmd->reserved = 0;

	return execute_cmd_write_ex_req(
		cq->context, IB_USER_VERBS_EX_CMD_MODIFY_CQ, cmd, cmd_size);
}
