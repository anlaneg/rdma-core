// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2019-2024 Amazon.com, Inc. or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <util/util.h>

#include "efa.h"
#include "verbs.h"

static void efa_free_context(struct ibv_context *ibvctx);

#define PCI_VENDOR_ID_AMAZON 0x1d0f

static const struct verbs_match_ent efa_table[] = {
	VERBS_DRIVER_ID(RDMA_DRIVER_EFA),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_AMAZON, 0xefa0, NULL),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_AMAZON, 0xefa1, NULL),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_AMAZON, 0xefa2, NULL),
	VERBS_PCI_MATCH(PCI_VENDOR_ID_AMAZON, 0xefa3, NULL),
	{}
};

static const struct verbs_context_ops efa_ctx_ops = {
	.alloc_pd = efa_alloc_pd,
	.create_ah = efa_create_ah,
	.create_cq = efa_create_cq,
	.create_cq_ex = efa_create_cq_ex,
	.create_qp = efa_create_qp,
	.create_qp_ex = efa_create_qp_ex,
	.cq_event = efa_cq_event,
	.dealloc_pd = efa_dealloc_pd,
	.dereg_mr = efa_dereg_mr,
	.destroy_ah = efa_destroy_ah,
	.destroy_cq = efa_destroy_cq,
	.destroy_qp = efa_destroy_qp,
	.modify_qp = efa_modify_qp,
	.poll_cq = efa_poll_cq,
	.post_recv = efa_post_recv,
	.post_send = efa_post_send,
	.query_device_ex = efa_query_device_ex,
	.query_port = efa_query_port,
	.query_qp = efa_query_qp,
	.query_qp_data_in_order = efa_query_qp_data_in_order,
	.reg_dmabuf_mr = efa_reg_dmabuf_mr,
	.reg_mr = efa_reg_mr,
	.req_notify_cq = efa_arm_cq,
	.free_context = efa_free_context,
};

static struct verbs_context *efa_alloc_context(struct ibv_device *vdev,
					       int cmd_fd,
					       void *private_data)
{
	struct efa_alloc_ucontext_resp resp = {};
	struct efa_alloc_ucontext cmd = {};
	struct efa_context *ctx;

	cmd.comp_mask |= EFA_ALLOC_UCONTEXT_CMD_COMP_TX_BATCH;
	cmd.comp_mask |= EFA_ALLOC_UCONTEXT_CMD_COMP_MIN_SQ_WR;

	ctx = verbs_init_and_alloc_context(vdev, cmd_fd, ctx, ibvctx,
					   RDMA_DRIVER_EFA);
	if (!ctx)
		return NULL;

	if (ibv_cmd_get_context(&ctx->ibvctx, &cmd.ibv_cmd, sizeof(cmd),
				NULL, &resp.ibv_resp, sizeof(resp))) {
		verbs_err(&ctx->ibvctx, "ibv_cmd_get_context failed\n");
		goto err_free_ctx;
	}

	ctx->sub_cqs_per_cq = resp.sub_cqs_per_cq;
	ctx->cmds_supp_udata_mask = resp.cmds_supp_udata_mask;
	ctx->cqe_size = sizeof(struct efa_io_rx_cdesc);
	ctx->ex_cqe_size = sizeof(struct efa_io_rx_cdesc_ex);
	ctx->inline_buf_size = resp.inline_buf_size;
	ctx->max_llq_size = resp.max_llq_size;
	ctx->max_tx_batch = resp.max_tx_batch;
	ctx->min_sq_wr = resp.min_sq_wr;
	pthread_spin_init(&ctx->qp_table_lock, PTHREAD_PROCESS_PRIVATE);

	/* ah udata is mandatory for ah number retrieval */
	if (!(ctx->cmds_supp_udata_mask & EFA_USER_CMDS_SUPP_UDATA_CREATE_AH)) {
		verbs_err(&ctx->ibvctx, "Kernel does not support AH udata\n");
		goto err_free_spinlock;
	}

	verbs_set_ops(&ctx->ibvctx, &efa_ctx_ops);

	if (efa_query_device_ctx(ctx))
		goto err_free_spinlock;
	return &ctx->ibvctx;

err_free_spinlock:
	pthread_spin_destroy(&ctx->qp_table_lock);
err_free_ctx:
	verbs_uninit_context(&ctx->ibvctx);
	free(ctx);
	return NULL;
}

static void efa_free_context(struct ibv_context *ibvctx)
{
	struct efa_context *ctx = to_efa_context(ibvctx);

	free(ctx->qp_table);
	pthread_spin_destroy(&ctx->qp_table_lock);
	verbs_uninit_context(&ctx->ibvctx);
	free(ctx);
}

static struct verbs_device *efa_device_alloc(struct verbs_sysfs_dev *sysfs_dev)
{
	struct efa_dev *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		return NULL;

	dev->pg_sz = sysconf(_SC_PAGESIZE);

	return &dev->vdev;
}

static void efa_uninit_device(struct verbs_device *verbs_device)
{
	struct efa_dev *dev = to_efa_dev(&verbs_device->device);

	free(dev);
}

/*efa对应的verbs设备驱动*/
static const struct verbs_device_ops efa_dev_ops = {
	.name = "efa",
	.match_min_abi_version = EFA_ABI_VERSION,
	.match_max_abi_version = EFA_ABI_VERSION,
	.match_table = efa_table,
	.alloc_device = efa_device_alloc,
	.uninit_device = efa_uninit_device,
	.alloc_context = efa_alloc_context,
};

bool is_efa_dev(struct ibv_device *device)
{
	struct verbs_device *verbs_device = verbs_get_device(device);

	return verbs_device->ops == &efa_dev_ops;
}


/*efa设备注册verbs驱动*/
PROVIDER_DRIVER(efa, efa_dev_ops);
