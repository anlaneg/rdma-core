/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <malloc.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <time.h>
#include <inttypes.h>

#include "pingpong.h"

#include <ccan/minmax.h>

enum {
	PINGPONG_RECV_WRID = 1,
	PINGPONG_SEND_WRID = 2,
};

static int page_size;
static int use_odp;
static int implicit_odp;
static int prefetch_mr;
static int use_ts;
static int validate_buf;
static int use_dm;
static int use_new_send;

struct pingpong_context {
	struct ibv_context	*context;
	struct ibv_comp_channel *channel;
	struct ibv_pd		*pd;
	struct ibv_mr		*mr;
	struct ibv_dm		*dm;
	union {
		struct ibv_cq		*cq;
		struct ibv_cq_ex	*cq_ex;
	} cq_s;
	struct ibv_qp		*qp;
	struct ibv_qp_ex	*qpx;
	/*消息buffer,已按页对齐*/
	char			*buf;
	/*消息大小*/
	int			 size;
	int			 send_flags;
	int			 rx_depth;
	int			 pending;
	struct ibv_port_attr     portinfo;
	uint64_t		 completion_timestamp_mask;
};

static struct ibv_cq *pp_cq(struct pingpong_context *ctx)
{
	return use_ts ? ibv_cq_ex_to_cq(ctx->cq_s.cq_ex) :
		ctx->cq_s.cq;
}

struct pingpong_dest {
	int lid;
	int qpn;
	int psn;
	union ibv_gid gid;
};

static int pp_connect_ctx(struct pingpong_context *ctx, int port, int my_psn,
			  enum ibv_mtu mtu, int sl,
			  struct pingpong_dest *dest, int sgid_idx)
{
	struct ibv_qp_attr attr = {
		.qp_state		= IBV_QPS_RTR,
		.path_mtu		= mtu,
		.dest_qp_num		= dest->qpn,
		.rq_psn			= dest->psn,
		.max_dest_rd_atomic	= 1,
		.min_rnr_timer		= 12,
		.ah_attr		= {
			.is_global	= 0,
			.dlid		= dest->lid,
			.sl		= sl,
			.src_path_bits	= 0,
			.port_num	= port
		}
	};

	if (dest->gid.global.interface_id) {
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.hop_limit = 1;
		attr.ah_attr.grh.dgid = dest->gid;
		attr.ah_attr.grh.sgid_index = sgid_idx;
	}
	if (ibv_modify_qp(ctx->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_AV                 |
			  IBV_QP_PATH_MTU           |
			  IBV_QP_DEST_QPN           |
			  IBV_QP_RQ_PSN             |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER)) {
		fprintf(stderr, "Failed to modify QP to RTR\n");
		return 1;
	}

	attr.qp_state	    = IBV_QPS_RTS;
	attr.timeout	    = 14;
	attr.retry_cnt	    = 7;
	attr.rnr_retry	    = 7;
	attr.sq_psn	    = my_psn;
	attr.max_rd_atomic  = 1;
	if (ibv_modify_qp(ctx->qp, &attr,
			  IBV_QP_STATE              |
			  IBV_QP_TIMEOUT            |
			  IBV_QP_RETRY_CNT          |
			  IBV_QP_RNR_RETRY          |
			  IBV_QP_SQ_PSN             |
			  IBV_QP_MAX_QP_RD_ATOMIC)) {
		fprintf(stderr, "Failed to modify QP to RTS\n");
		return 1;
	}

	return 0;
}

/*两端通过带外交换pingpong_dest*/
static struct pingpong_dest *pp_client_exch_dest(const char *servername/*目的地址*/, int port/*目的端口*/,
						 const struct pingpong_dest *my_dest)
{
	struct addrinfo *res, *t;
	struct addrinfo hints = {
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	char *service;
	char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
	int n;
	int sockfd = -1;
	struct pingpong_dest *rem_dest = NULL;
	char gid[33];

	/*格式化目的port*/
	if (asprintf(&service, "%d", port) < 0)
		return NULL;

	/*解析目的地址*/
	n = getaddrinfo(servername, service, &hints, &res);

	if (n < 0) {
		fprintf(stderr, "%s for %s:%d\n", gai_strerror(n), servername, port);
		free(service);
		return NULL;
	}

	/*遍历解析结果*/
	for (t = res; t; t = t->ai_next) {
		/*创建与解析地址匹配的socket*/
		sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
		if (sockfd >= 0) {
			/*连接到对应，如果成功，则跳出*/
			if (!connect(sockfd, t->ai_addr, t->ai_addrlen))
				break;
			close(sockfd);
			sockfd = -1;
		}
	}

	freeaddrinfo(res);
	free(service);

	if (sockfd < 0) {
		/*与对端连接失败*/
		fprintf(stderr, "Couldn't connect to %s:%d\n", servername, port);
		return NULL;
	}

	/*将gid内容转换后写入gid中*/
	gid_to_wire_gid(&my_dest->gid, gid);
	/*格式化my_dest,并填充到msg中*/
	sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn,
							my_dest->psn, gid);

	/*将msg填充发送给对端*/
	if (write(sockfd, msg, sizeof msg) != sizeof msg) {
		fprintf(stderr, "Couldn't send local address\n");
		goto out;
	}

	/*从对端读取响应，将内容填充到msg*/
	if (read(sockfd, msg, sizeof msg) != sizeof msg ||
			/*并向对端写done*/
	    write(sockfd, "done", sizeof "done") != sizeof "done") {
		perror("client read/write");
		fprintf(stderr, "Couldn't read/write remote address\n");
		goto out;
	}

	/*解析server端响应的msg,并填充到rem_dest中*/
	rem_dest = malloc(sizeof *rem_dest);
	if (!rem_dest)
		goto out;

	sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn,
						&rem_dest->psn, gid);
	/*填充远端gid*/
	wire_gid_to_gid(gid, &rem_dest->gid);

out:
	close(sockfd);
	return rem_dest;
}

static struct pingpong_dest *pp_server_exch_dest(struct pingpong_context *ctx,
						 int ib_port, enum ibv_mtu mtu,
						 int port, int sl,
						 const struct pingpong_dest *my_dest,
						 int sgid_idx)
{
	struct addrinfo *res, *t;
	struct addrinfo hints = {
		.ai_flags    = AI_PASSIVE,
		.ai_family   = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM
	};
	char *service;
	char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
	int n;
	int sockfd = -1, connfd;
	struct pingpong_dest *rem_dest = NULL;
	char gid[33];

	if (asprintf(&service, "%d", port) < 0)
		return NULL;

	/*解析service*/
	n = getaddrinfo(NULL, service, &hints, &res);

	if (n < 0) {
		fprintf(stderr, "%s for port %d\n", gai_strerror(n), port);
		free(service);
		return NULL;
	}

	/*遍历解析地址，完成端口监听*/
	for (t = res; t; t = t->ai_next) {
		sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
		if (sockfd >= 0) {
			n = 1;

			setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof n);

			if (!bind(sockfd, t->ai_addr, t->ai_addrlen))
				break;
			close(sockfd);
			sockfd = -1;
		}
	}

	freeaddrinfo(res);
	free(service);

	if (sockfd < 0) {
		fprintf(stderr, "Couldn't listen to port %d\n", port);
		return NULL;
	}

	listen(sockfd, 1);
	connfd = accept(sockfd, NULL, NULL);
	close(sockfd);
	if (connfd < 0) {
		fprintf(stderr, "accept() failed\n");
		return NULL;
	}

	/*读取client发送过来的消息*/
	n = read(connfd, msg, sizeof msg);
	if (n != sizeof msg) {
		perror("server read");
		fprintf(stderr, "%d/%d: Couldn't read remote address\n", n, (int) sizeof msg);
		goto out;
	}

	rem_dest = malloc(sizeof *rem_dest);
	if (!rem_dest)
		goto out;

	/*解析目地地址*/
	sscanf(msg, "%x:%x:%x:%s", &rem_dest->lid, &rem_dest->qpn,
							&rem_dest->psn, gid);
	wire_gid_to_gid(gid, &rem_dest->gid);

	/*连接对端qp*/
	if (pp_connect_ctx(ctx, ib_port, my_dest->psn, mtu, sl, rem_dest,
								sgid_idx)) {
		fprintf(stderr, "Couldn't connect to remote QP\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}


	/*向对端发送自已的地址*/
	gid_to_wire_gid(&my_dest->gid, gid);
	sprintf(msg, "%04x:%06x:%06x:%s", my_dest->lid, my_dest->qpn,
							my_dest->psn, gid);
	if (write(connfd, msg, sizeof msg) != sizeof msg ||
		/*并收取对端成功接收后，传回的done*/
	    read(connfd, msg, sizeof msg) != sizeof "done") {
		fprintf(stderr, "Couldn't send/recv local address\n");
		free(rem_dest);
		rem_dest = NULL;
		goto out;
	}


out:
	close(connfd);
	return rem_dest;
}

/*初始化pingpong_context*/
static struct pingpong_context *pp_init_ctx(struct ibv_device *ib_dev, int size,
					    int rx_depth/*队列深度*/, int port,
					    int use_event)
{
	struct pingpong_context *ctx;
	int access_flags = IBV_ACCESS_LOCAL_WRITE;

	ctx = calloc(1, sizeof *ctx);
	if (!ctx)
		return NULL;

	ctx->size       = size;
	ctx->send_flags = IBV_SEND_SIGNALED;
	ctx->rx_depth   = rx_depth;

	/*按页对齐，申请消息buffer*/
	ctx->buf = memalign(page_size, size);
	if (!ctx->buf) {
		fprintf(stderr, "Couldn't allocate work buf.\n");
		goto clean_ctx;
	}

	/* FIXME memset(ctx->buf, 0, size); */
	memset(ctx->buf, 0x7b, size);

	/*打开ib设备，针对ibdev创建ibv_context*/
	ctx->context = ibv_open_device(ib_dev);
	if (!ctx->context) {
		fprintf(stderr, "Couldn't get context for %s\n",
			ibv_get_device_name(ib_dev));
		goto clean_buffer;
	}

	/*使用了sleep,创建channel*/
	if (use_event) {
		ctx->channel = ibv_create_comp_channel(ctx->context);
		if (!ctx->channel) {
			fprintf(stderr, "Couldn't create completion channel\n");
			goto clean_device;
		}
	} else
		ctx->channel = NULL;

	/*创建pd*/
	ctx->pd = ibv_alloc_pd(ctx->context);
	if (!ctx->pd) {
		fprintf(stderr, "Couldn't allocate PD\n");
		goto clean_comp_channel;
	}

	if (use_odp || use_ts || use_dm) {
		const uint32_t rc_caps_mask = IBV_ODP_SUPPORT_SEND |
					      IBV_ODP_SUPPORT_RECV;
		struct ibv_device_attr_ex attrx;

		if (ibv_query_device_ex(ctx->context, NULL, &attrx)) {
			fprintf(stderr, "Couldn't query device for its features\n");
			goto clean_pd;
		}

		if (use_odp) {
			if (!(attrx.odp_caps.general_caps & IBV_ODP_SUPPORT) ||
			    (attrx.odp_caps.per_transport_caps.rc_odp_caps & rc_caps_mask) != rc_caps_mask) {
				fprintf(stderr, "The device isn't ODP capable or does not support RC send and receive with ODP\n");
				goto clean_pd;
			}
			if (implicit_odp &&
			    !(attrx.odp_caps.general_caps & IBV_ODP_SUPPORT_IMPLICIT)) {
				fprintf(stderr, "The device doesn't support implicit ODP\n");
				goto clean_pd;
			}
			access_flags |= IBV_ACCESS_ON_DEMAND;
		}

		if (use_ts) {
			if (!attrx.completion_timestamp_mask) {
				fprintf(stderr, "The device isn't completion timestamp capable\n");
				goto clean_pd;
			}
			ctx->completion_timestamp_mask = attrx.completion_timestamp_mask;
		}

		if (use_dm) {
			struct ibv_alloc_dm_attr dm_attr = {};

			if (!attrx.max_dm_size) {
				fprintf(stderr, "Device doesn't support dm allocation\n");
				goto clean_pd;
			}

			if (attrx.max_dm_size < size) {
				fprintf(stderr, "Device memory is insufficient\n");
				goto clean_pd;
			}

			dm_attr.length = size;
			ctx->dm = ibv_alloc_dm(ctx->context, &dm_attr);
			if (!ctx->dm) {
				fprintf(stderr, "Dev mem allocation failed\n");
				goto clean_pd;
			}

			access_flags |= IBV_ACCESS_ZERO_BASED;
		}
	}

	/*注册内存区域*/
	if (implicit_odp) {
		ctx->mr = ibv_reg_mr(ctx->pd, NULL, SIZE_MAX, access_flags);
	} else {
		ctx->mr = use_dm ? ibv_reg_dm_mr(ctx->pd, ctx->dm, 0,
						 size, access_flags) :
			ibv_reg_mr(ctx->pd, ctx->buf, size, access_flags);
	}

	if (!ctx->mr) {
		fprintf(stderr, "Couldn't register MR\n");
		goto clean_dm;
	}

	if (prefetch_mr) {
		struct ibv_sge sg_list;
		int ret;

		sg_list.lkey = ctx->mr->lkey;
		sg_list.addr = (uintptr_t)ctx->buf;
		sg_list.length = size;

		ret = ibv_advise_mr(ctx->pd, IBV_ADVISE_MR_ADVICE_PREFETCH_WRITE,
				    IB_UVERBS_ADVISE_MR_FLAG_FLUSH,
				    &sg_list, 1);

		if (ret)
			fprintf(stderr, "Couldn't prefetch MR(%d). Continue anyway\n", ret);
	}

	if (use_ts) {
		struct ibv_cq_init_attr_ex attr_ex = {
			.cqe = rx_depth + 1,
			.cq_context = NULL,
			.channel = ctx->channel,
			.comp_vector = 0,
			.wc_flags = IBV_WC_EX_WITH_COMPLETION_TIMESTAMP
		};

		ctx->cq_s.cq_ex = ibv_create_cq_ex(ctx->context, &attr_ex);
	} else {
		/*利用context创建cq*/
		ctx->cq_s.cq = ibv_create_cq(ctx->context, rx_depth + 1, NULL,
					     ctx->channel, 0);
	}

	if (!pp_cq(ctx)) {
		fprintf(stderr, "Couldn't create CQ\n");
		goto clean_mr;
	}

	{
		struct ibv_qp_attr attr;
		struct ibv_qp_init_attr init_attr = {
			.send_cq = pp_cq(ctx),
			.recv_cq = pp_cq(ctx),
			.cap     = {
				.max_send_wr  = 1,
				.max_recv_wr  = rx_depth,
				.max_send_sge = 1,
				.max_recv_sge = 1
			},
			.qp_type = IBV_QPT_RC /*指明qp类型为rc*/
		};

		if (use_new_send) {
			struct ibv_qp_init_attr_ex init_attr_ex = {};

			init_attr_ex.send_cq = pp_cq(ctx);
			init_attr_ex.recv_cq = pp_cq(ctx);
			init_attr_ex.cap.max_send_wr = 1;
			init_attr_ex.cap.max_recv_wr = rx_depth;
			init_attr_ex.cap.max_send_sge = 1;
			init_attr_ex.cap.max_recv_sge = 1;
			init_attr_ex.qp_type = IBV_QPT_RC;

			init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_PD |
						  IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
			init_attr_ex.pd = ctx->pd;
			init_attr_ex.send_ops_flags = IBV_QP_EX_WITH_SEND;

			ctx->qp = ibv_create_qp_ex(ctx->context, &init_attr_ex);
		} else {
		    /*创建qp*/
			ctx->qp = ibv_create_qp(ctx->pd, &init_attr);
		}

		if (!ctx->qp)  {
			fprintf(stderr, "Couldn't create QP\n");
			goto clean_cq;
		}

		if (use_new_send)
			ctx->qpx = ibv_qp_to_qp_ex(ctx->qp);

		ibv_query_qp(ctx->qp, &attr, IBV_QP_CAP, &init_attr);
		if (init_attr.cap.max_inline_data >= size && !use_dm)
			/*max_inline数据大于size,打上inline标记*/
			ctx->send_flags |= IBV_SEND_INLINE;
	}

	{
		struct ibv_qp_attr attr = {
			.qp_state        = IBV_QPS_INIT,
			.pkey_index      = 0,
			.port_num        = port,
			.qp_access_flags = 0
		};

		if (ibv_modify_qp(ctx->qp, &attr,
				  IBV_QP_STATE              |
				  IBV_QP_PKEY_INDEX         |
				  IBV_QP_PORT               |
				  IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "Failed to modify QP to INIT\n");
			goto clean_qp;
		}
	}

	return ctx;

clean_qp:
	ibv_destroy_qp(ctx->qp);

clean_cq:
	ibv_destroy_cq(pp_cq(ctx));

clean_mr:
	ibv_dereg_mr(ctx->mr);

clean_dm:
	if (ctx->dm)
		ibv_free_dm(ctx->dm);

clean_pd:
	ibv_dealloc_pd(ctx->pd);

clean_comp_channel:
	if (ctx->channel)
		ibv_destroy_comp_channel(ctx->channel);

clean_device:
	ibv_close_device(ctx->context);

clean_buffer:
	free(ctx->buf);

clean_ctx:
	free(ctx);

	return NULL;
}

static int pp_close_ctx(struct pingpong_context *ctx)
{
	if (ibv_destroy_qp(ctx->qp)) {
		fprintf(stderr, "Couldn't destroy QP\n");
		return 1;
	}

	if (ibv_destroy_cq(pp_cq(ctx))) {
		fprintf(stderr, "Couldn't destroy CQ\n");
		return 1;
	}

	if (ibv_dereg_mr(ctx->mr)) {
		fprintf(stderr, "Couldn't deregister MR\n");
		return 1;
	}

	if (ctx->dm) {
		if (ibv_free_dm(ctx->dm)) {
			fprintf(stderr, "Couldn't free DM\n");
			return 1;
		}
	}

	if (ibv_dealloc_pd(ctx->pd)) {
		fprintf(stderr, "Couldn't deallocate PD\n");
		return 1;
	}

	if (ctx->channel) {
		if (ibv_destroy_comp_channel(ctx->channel)) {
			fprintf(stderr, "Couldn't destroy completion channel\n");
			return 1;
		}
	}

	if (ibv_close_device(ctx->context)) {
		fprintf(stderr, "Couldn't release context\n");
		return 1;
	}

	free(ctx->buf);
	free(ctx);

	return 0;
}

static int pp_post_recv(struct pingpong_context *ctx, int n)
{
	struct ibv_sge list = {
		.addr	= use_dm ? 0 : (uintptr_t) ctx->buf,
		.length = ctx->size,
		.lkey	= ctx->mr->lkey
	};
	struct ibv_recv_wr wr = {
		.wr_id	    = PINGPONG_RECV_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
	};
	struct ibv_recv_wr *bad_wr;
	int i;

	/*尝试n次post recv*/
	for (i = 0; i < n; ++i)
		if (ibv_post_recv(ctx->qp, &wr, &bad_wr))
			break;

	return i;
}

static int pp_post_send(struct pingpong_context *ctx)
{
    /*构造一组待发送的地址*/
	struct ibv_sge list = {
		.addr	= use_dm ? 0 : (uintptr_t) ctx->buf,
		.length = ctx->size,
		.lkey	= ctx->mr->lkey
	};
	/*构造work request*/
	struct ibv_send_wr wr = {
		.wr_id	    = PINGPONG_SEND_WRID,
		.sg_list    = &list,
		.num_sge    = 1,
		.opcode     = IBV_WR_SEND,
		.send_flags = ctx->send_flags,
	};
	struct ibv_send_wr *bad_wr;

	if (use_new_send) {
		/*使用新的接口*/
		ibv_wr_start(ctx->qpx);

		ctx->qpx->wr_id = PINGPONG_SEND_WRID;
		ctx->qpx->wr_flags = ctx->send_flags;

		ibv_wr_send(ctx->qpx);
		ibv_wr_set_sge(ctx->qpx, list.lkey, list.addr, list.length);

		return ibv_wr_complete(ctx->qpx);
	} else {
	    /*不使用new_send,仍采用ibv_post_send进行发送完成通知*/
		return ibv_post_send(ctx->qp, &wr, &bad_wr);
	}
}

struct ts_params {
	uint64_t		 comp_recv_max_time_delta;
	uint64_t		 comp_recv_min_time_delta;
	uint64_t		 comp_recv_total_time_delta;
	uint64_t		 comp_recv_prev_time;
	int			 last_comp_with_ts;
	unsigned int		 comp_with_time_iters;
};

static inline int parse_single_wc(struct pingpong_context *ctx, int *scnt,
				  int *rcnt, int *routs, int iters,
				  uint64_t wr_id, enum ibv_wc_status status,
				  uint64_t completion_timestamp,
				  struct ts_params *ts)
{
	if (status != IBV_WC_SUCCESS) {
		/*不成功*/
		fprintf(stderr, "Failed status %s (%d) for wr_id %d\n",
			ibv_wc_status_str(status),
			status, (int)wr_id);
		return 1;
	}

	switch ((int)wr_id) {
	case PINGPONG_SEND_WRID:
		/*发送成功*/
		++(*scnt);
		break;

	case PINGPONG_RECV_WRID:
		if (--(*routs) <= 1) {
			/*执行post recv*/
			*routs += pp_post_recv(ctx, ctx->rx_depth - *routs);
			if (*routs < ctx->rx_depth) {
				fprintf(stderr,
					"Couldn't post receive (%d)\n",
					*routs);
				return 1;
			}
		}

		++(*rcnt);/*收成功*/
		if (use_ts) {
			if (ts->last_comp_with_ts) {
				uint64_t delta;

				/* checking whether the clock was wrapped around */
				if (completion_timestamp >= ts->comp_recv_prev_time)
					delta = completion_timestamp - ts->comp_recv_prev_time;
				else
					delta = ctx->completion_timestamp_mask - ts->comp_recv_prev_time +
						completion_timestamp + 1;

				ts->comp_recv_max_time_delta = max(ts->comp_recv_max_time_delta, delta);
				ts->comp_recv_min_time_delta = min(ts->comp_recv_min_time_delta, delta);
				ts->comp_recv_total_time_delta += delta;
				ts->comp_with_time_iters++;
			}

			ts->comp_recv_prev_time = completion_timestamp;
			ts->last_comp_with_ts = 1;
		} else {
			ts->last_comp_with_ts = 0;
		}

		break;

	default:
		fprintf(stderr, "Completion for unknown wr_id %d\n",
			(int)wr_id);
		return 1;
	}

	ctx->pending &= ~(int)wr_id;
	if (*scnt < iters && !ctx->pending) {
		/*继续执行post send*/
		if (pp_post_send(ctx)) {
			fprintf(stderr, "Couldn't post send\n");
			return 1;
		}
		ctx->pending = PINGPONG_RECV_WRID |
			PINGPONG_SEND_WRID;
	}

	return 0;
}

static void usage(const char *argv0)
{
	printf("Usage:\n");
	printf("  %s            start a server and wait for connection\n", argv0);
	printf("  %s <host>     connect to server at <host>\n", argv0);
	printf("\n");
	printf("Options:\n");
	printf("  -p, --port=<port>      listen on/connect to port <port> (default 18515)\n");
	printf("  -d, --ib-dev=<dev>     use IB device <dev> (default first device found)\n");
	printf("  -i, --ib-port=<port>   use port <port> of IB device (default 1)\n");
	printf("  -s, --size=<size>      size of message to exchange (default 4096)\n");
	printf("  -m, --mtu=<size>       path MTU (default 1024)\n");
	printf("  -r, --rx-depth=<dep>   number of receives to post at a time (default 500)\n");
	printf("  -n, --iters=<iters>    number of exchanges (default 1000)\n");
	printf("  -l, --sl=<sl>          service level value\n");
	printf("  -e, --events           sleep on CQ events (default poll)\n");
	printf("  -g, --gid-idx=<gid index> local port gid index\n");
	printf("  -o, --odp		    use on demand paging\n");
	printf("  -O, --iodp		    use implicit on demand paging\n");
	printf("  -P, --prefetch	    prefetch an ODP MR\n");
	printf("  -t, --ts	            get CQE with timestamp\n");
	printf("  -c, --chk	            validate received buffer\n");
	printf("  -j, --dm	            use device memory\n");
	printf("  -N, --new_send            use new post send WR API\n");
}

int main(int argc, char *argv[])
{
	struct ibv_device      **dev_list;
	struct ibv_device	*ib_dev;
	struct pingpong_context *ctx;
	struct pingpong_dest     my_dest;
	struct pingpong_dest    *rem_dest;
	struct timeval           start, end;
	/*通过-d参数指明使用哪个ib设备，如不指明，默认使用第一个设备*/
	char                    *ib_devname = NULL;
	char                    *servername = NULL;/*server端名称*/
	/*通过-p参数指明的连接/监听的端口*/
	unsigned int             port = 18515;
	/*通过-i参数指明使用ib设备的哪个ib_port*/
	int                      ib_port = 1;
	/*通过-s参数指明我们要交换的消息大小，如不指明，默认大小4096*/
	unsigned int             size = 4096;
	/*指明对应的mtu*/
	enum ibv_mtu		 mtu = IBV_MTU_1024;
	/*通过-r参数指明我们一次收多少*/
	unsigned int             rx_depth = 500;
	/*通过-n参数提明迭代次数*/
	unsigned int             iters = 1000;
	int                      use_event = 0;
	int                      routs;
	int                      rcnt, scnt;
	int                      num_cq_events = 0;
	int                      sl = 0;
	int			 gidx = -1;
	char			 gid[33];
	struct ts_params	 ts;

	srand48(getpid() * time(NULL));

	while (1) {
		int c;

		static struct option long_options[] = {
			{ .name = "port",     .has_arg = 1, .val = 'p' },
			{ .name = "ib-dev",   .has_arg = 1, .val = 'd' },
			{ .name = "ib-port",  .has_arg = 1, .val = 'i' },
			{ .name = "size",     .has_arg = 1, .val = 's' },
			{ .name = "mtu",      .has_arg = 1, .val = 'm' },
			{ .name = "rx-depth", .has_arg = 1, .val = 'r' },
			{ .name = "iters",    .has_arg = 1, .val = 'n' },
			{ .name = "sl",       .has_arg = 1, .val = 'l' },
			{ .name = "events",   .has_arg = 0, .val = 'e' },
			{ .name = "gid-idx",  .has_arg = 1, .val = 'g' },
			{ .name = "odp",      .has_arg = 0, .val = 'o' },
			{ .name = "iodp",     .has_arg = 0, .val = 'O' },
			{ .name = "prefetch", .has_arg = 0, .val = 'P' },
			{ .name = "ts",       .has_arg = 0, .val = 't' },
			{ .name = "chk",      .has_arg = 0, .val = 'c' },
			{ .name = "dm",       .has_arg = 0, .val = 'j' },
			{ .name = "new_send", .has_arg = 0, .val = 'N' },
			{}
		};

		c = getopt_long(argc, argv, "p:d:i:s:m:r:n:l:eg:oOPtcjN",
				long_options, NULL);

		if (c == -1)
			break;

		switch (c) {
		case 'p':
		    /*连接/监听的端口*/
			port = strtoul(optarg, NULL, 0);
			if (port > 65535) {
				usage(argv[0]);
				return 1;
			}
			break;

		case 'd':
		    /*指明使用哪个ib设备*/
			ib_devname = strdupa(optarg);
			break;

		case 'i':
		    /*指明使用哪个ib_port*/
			ib_port = strtol(optarg, NULL, 0);
			if (ib_port < 1) {
				usage(argv[0]);
				return 1;
			}
			break;

		case 's':
		    /*指明我们要交换的消息大小*/
			size = strtoul(optarg, NULL, 0);
			break;

		case 'm':
		    /*指明对应的mtu*/
			mtu = pp_mtu_to_enum(strtol(optarg, NULL, 0));
			if (mtu == 0) {
				usage(argv[0]);
				return 1;
			}
			break;

		case 'r':
			rx_depth = strtoul(optarg, NULL, 0);
			break;

		case 'n':
			iters = strtoul(optarg, NULL, 0);
			break;

		case 'l':
			sl = strtol(optarg, NULL, 0);
			break;

		case 'e':
			++use_event;
			break;

		case 'g':
			gidx = strtol(optarg, NULL, 0);
			break;

		case 'o':
			use_odp = 1;
			break;
		case 'P':
			prefetch_mr = 1;
			break;
		case 'O':
			use_odp = 1;
			implicit_odp = 1;
			break;
		case 't':
			use_ts = 1;
			break;
		case 'c':
			validate_buf = 1;
			break;

		case 'j':
			use_dm = 1;
			break;

		case 'N':
		    /*指明采用new的发送*/
			use_new_send = 1;
			break;

		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind == argc - 1)
	    /*取要连接的servername*/
		servername = strdupa(argv[optind]);
	else if (optind < argc) {
	    /*有多余参数，显示用法并退出*/
		usage(argv[0]);
		return 1;
	}

	if (use_odp && use_dm) {
	    /*-o与-j选项冲突*/
		fprintf(stderr, "DM memory region can't be on demand\n");
		return 1;
	}

	if (!use_odp && prefetch_mr) {
	    /*-P选项仅在-o选项情况下有效*/
		fprintf(stderr, "prefetch is valid only with on-demand memory region\n");
		return 1;
	}

	if (use_ts) {
		ts.comp_recv_max_time_delta = 0;
		ts.comp_recv_min_time_delta = 0xffffffff;
		ts.comp_recv_total_time_delta = 0;
		ts.comp_recv_prev_time = 0;
		ts.last_comp_with_ts = 0;
		ts.comp_with_time_iters = 0;
	}

	/*取页大小*/
	page_size = sysconf(_SC_PAGESIZE);

	/*返回当前所有可用的ib设备*/
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		perror("Failed to get IB devices list");
		return 1;
	}

	if (!ib_devname) {
	    /*没有指定设备名，使用第一个设备*/
		ib_dev = *dev_list;
		if (!ib_dev) {
			fprintf(stderr, "No IB devices found\n");
			return 1;
		}
	} else {
	    /*指定了设备名称，查找到对应的ib_dev*/
		int i;
		for (i = 0; dev_list[i]; ++i)
			if (!strcmp(ibv_get_device_name(dev_list[i]), ib_devname))
				break;
		ib_dev = dev_list[i];
		if (!ib_dev) {
			/*没有找到给定名称的设备*/
			fprintf(stderr, "IB device %s not found\n", ib_devname);
			return 1;
		}
	}

	/*初始化pingpong ctx*/
	ctx = pp_init_ctx(ib_dev/*用于通信的设备*/, size/*要交换的数据长度*/, rx_depth, ib_port/*交换用的port id*/, use_event);
	if (!ctx)
		return 1;

	/*执行post recv,准备接收用的buffer*/
	routs = pp_post_recv(ctx, ctx->rx_depth);
	if (routs < ctx->rx_depth) {
		fprintf(stderr, "Couldn't post receive (%d)\n", routs);
		return 1;
	}

	if (use_event)
		if (ibv_req_notify_cq(pp_cq(ctx), 0)) {
			fprintf(stderr, "Couldn't request CQ notification\n");
			return 1;
		}


	if (pp_get_port_info(ctx->context, ib_port, &ctx->portinfo)) {
		fprintf(stderr, "Couldn't get port info\n");
		return 1;
	}

	my_dest.lid = ctx->portinfo.lid;
	if (ctx->portinfo.link_layer != IBV_LINK_LAYER_ETHERNET &&
							!my_dest.lid) {
		fprintf(stderr, "Couldn't get local LID\n");
		return 1;
	}

	if (gidx >= 0) {
		/*通过gidx,查询并填充gid*/
		if (ibv_query_gid(ctx->context, ib_port, gidx, &my_dest.gid)) {
			fprintf(stderr, "can't read sgid of index %d\n", gidx);
			return 1;
		}
	} else
		/*将gid初始化为0*/
		memset(&my_dest.gid, 0, sizeof my_dest.gid);

	my_dest.qpn = ctx->qp->qp_num;
	my_dest.psn = lrand48() & 0xffffff;
	inet_ntop(AF_INET6, &my_dest.gid, gid, sizeof gid);
	printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
	       my_dest.lid, my_dest.qpn, my_dest.psn, gid);


	if (servername)
		/*设置了servername,即client端处理,与server端交换my_dest*/
		rem_dest = pp_client_exch_dest(servername, port, &my_dest);
	else
		/*服务端处理,连接client端的qp，并交换my_dest*/
		rem_dest = pp_server_exch_dest(ctx, ib_port, mtu, port, sl,
								&my_dest, gidx);

	if (!rem_dest)
		return 1;

	/*显示对端地址*/
	inet_ntop(AF_INET6, &rem_dest->gid, gid, sizeof gid);
	printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
	       rem_dest->lid, rem_dest->qpn, rem_dest->psn, gid);

	if (servername)
		/*客户端连接对端qp*/
		if (pp_connect_ctx(ctx, ib_port, my_dest.psn, mtu, sl, rem_dest,
					gidx))
			return 1;

	ctx->pending = PINGPONG_RECV_WRID;

	if (servername) {
	    /*client端处理*/
		if (validate_buf)
			for (int i = 0; i < size; i += page_size)
				ctx->buf[i] = i / page_size % sizeof(char);

		if (use_dm)
			if (ibv_memcpy_to_dm(ctx->dm, 0, (void *)ctx->buf, size)) {
				fprintf(stderr, "Copy to dm buffer failed\n");
				return 1;
			}

		/*客户端执行post send*/
		if (pp_post_send(ctx)) {
			fprintf(stderr, "Couldn't post send\n");
			return 1;
		}
		ctx->pending |= PINGPONG_SEND_WRID;
	}

	/*取start时间*/
	if (gettimeofday(&start, NULL)) {
		perror("gettimeofday");
		return 1;
	}

	rcnt = scnt = 0;
	while (rcnt < iters || scnt < iters) {
		int ret;

		if (use_event) {
			struct ibv_cq *ev_cq;
			void          *ev_ctx;

			if (ibv_get_cq_event(ctx->channel, &ev_cq, &ev_ctx)) {
				fprintf(stderr, "Failed to get cq_event\n");
				return 1;
			}

			++num_cq_events;

			if (ev_cq != pp_cq(ctx)) {
				fprintf(stderr, "CQ event for unknown CQ %p\n", ev_cq);
				return 1;
			}

			if (ibv_req_notify_cq(pp_cq(ctx), 0)) {
				fprintf(stderr, "Couldn't request CQ notification\n");
				return 1;
			}
		}

		if (use_ts) {
			struct ibv_poll_cq_attr attr = {};

			do {
				ret = ibv_start_poll(ctx->cq_s.cq_ex, &attr);
			} while (!use_event && ret == ENOENT);

			if (ret) {
				fprintf(stderr, "poll CQ failed %d\n", ret);
				return ret;
			}
			ret = parse_single_wc(ctx, &scnt, &rcnt, &routs,
					      iters,
					      ctx->cq_s.cq_ex->wr_id,
					      ctx->cq_s.cq_ex->status,
					      ibv_wc_read_completion_ts(ctx->cq_s.cq_ex),
					      &ts);
			if (ret) {
				ibv_end_poll(ctx->cq_s.cq_ex);
				return ret;
			}
			ret = ibv_next_poll(ctx->cq_s.cq_ex);
			if (!ret)
				ret = parse_single_wc(ctx, &scnt, &rcnt, &routs,
						      iters,
						      ctx->cq_s.cq_ex->wr_id,
						      ctx->cq_s.cq_ex->status,
						      ibv_wc_read_completion_ts(ctx->cq_s.cq_ex),
						      &ts);
			ibv_end_poll(ctx->cq_s.cq_ex);
			if (ret && ret != ENOENT) {
				fprintf(stderr, "poll CQ failed %d\n", ret);
				return ret;
			}
		} else {
			int ne, i;
			struct ibv_wc wc[2];

			do {
				/*等待完成*/
				ne = ibv_poll_cq(pp_cq(ctx), 2, wc);
				if (ne < 0) {
					fprintf(stderr, "poll CQ failed %d\n", ne);
					return 1;
				}
			} while (!use_event && ne < 1);

			/*遍历完成的*/
			for (i = 0; i < ne; ++i) {
				ret = parse_single_wc(ctx, &scnt, &rcnt, &routs,
						      iters/*当前次数*/,
						      wc[i].wr_id,
						      wc[i].status,
						      0, &ts);
				if (ret) {
					fprintf(stderr, "parse WC failed %d\n", ne);
					return 1;
				}
			}
		}
	}

	/*获取结束时间*/
	if (gettimeofday(&end, NULL)) {
		perror("gettimeofday");
		return 1;
	}

	/*显示pingpong结果*/
	{
		float usec = (end.tv_sec - start.tv_sec) * 1000000 +
			(end.tv_usec - start.tv_usec);
		long long bytes = (long long) size * iters * 2;

		printf("%lld bytes in %.2f seconds = %.2f Mbit/sec\n",
		       bytes, usec / 1000000., bytes * 8. / usec);
		printf("%d iters in %.2f seconds = %.2f usec/iter\n",
		       iters, usec / 1000000., usec / iters);

		if (use_ts && ts.comp_with_time_iters) {
			printf("Max receive completion clock cycles = %" PRIu64 "\n",
			       ts.comp_recv_max_time_delta);
			printf("Min receive completion clock cycles = %" PRIu64 "\n",
			       ts.comp_recv_min_time_delta);
			printf("Average receive completion clock cycles = %f\n",
			       (double)ts.comp_recv_total_time_delta / ts.comp_with_time_iters);
		}

		if ((!servername) && (validate_buf)) {
			if (use_dm)
				if (ibv_memcpy_from_dm(ctx->buf, ctx->dm, 0, size)) {
					fprintf(stderr, "Copy from DM buffer failed\n");
					return 1;
				}
			for (int i = 0; i < size; i += page_size)
				if (ctx->buf[i] != i / page_size % sizeof(char))
					printf("invalid data in page %d\n",
					       i / page_size);
		}
	}

	ibv_ack_cq_events(pp_cq(ctx), num_cq_events);

	if (pp_close_ctx(ctx))
		return 1;

	ibv_free_device_list(dev_list);
	free(rem_dest);

	return 0;
}
