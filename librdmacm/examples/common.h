/*
 * Copyright (c) 2005-2012 Intel Corporation.  All rights reserved.
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
 *
 * $Id$
 */

#include <stdlib.h>
#include <sys/types.h>
#include <endian.h>
#include <poll.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>

#include <rdma/rdma_cma.h>
#include <rdma/rsocket.h>
#include <infiniband/ib.h>

/* Defined in common.c; used in all rsocket demos to determine whether to use
 * rsocket calls or standard socket calls.
 */
extern int use_rs;

static inline int rs_socket(int f, int t, int p)
{
	int fd;

	if (!use_rs)
		return socket(f, t, p);

	fd = rsocket(f, t, p);
	if (fd < 0) {
		if (t == SOCK_STREAM && errno == ENODEV)
			fprintf(stderr, "No RDMA devices were detected\n");
		else
			perror("rsocket failed");
	}
	return fd;
}

#define rs_bind(s,a,l)    use_rs ? rbind(s,a,l)    : bind(s,a,l)
#define rs_listen(s,b)    use_rs ? rlisten(s,b)    : listen(s,b)
#define rs_connect(s,a,l) use_rs ? rconnect(s,a,l) : connect(s,a,l)
#define rs_accept(s,a,l)  use_rs ? raccept(s,a,l)  : accept(s,a,l)
#define rs_shutdown(s,h)  use_rs ? rshutdown(s,h)  : shutdown(s,h)
#define rs_close(s)       use_rs ? rclose(s)       : close(s)
#define rs_recv(s,b,l,f)  use_rs ? rrecv(s,b,l,f)  : recv(s,b,l,f)
#define rs_send(s,b,l,f)  use_rs ? rsend(s,b,l,f)  : send(s,b,l,f)
#define rs_recvfrom(s,b,l,f,a,al) \
	use_rs ? rrecvfrom(s,b,l,f,a,al) : recvfrom(s,b,l,f,a,al)
#define rs_sendto(s,b,l,f,a,al) \
	use_rs ? rsendto(s,b,l,f,a,al)   : sendto(s,b,l,f,a,al)
#define rs_poll(f,n,t)	  use_rs ? rpoll(f,n,t)	   : poll(f,n,t)
#define rs_fcntl(s,c,p)   use_rs ? rfcntl(s,c,p)   : fcntl(s,c,p)
#define rs_setsockopt(s,l,n,v,ol) \
	use_rs ? rsetsockopt(s,l,n,v,ol) : setsockopt(s,l,n,v,ol)
#define rs_getsockopt(s,l,n,v,ol) \
	use_rs ? rgetsockopt(s,l,n,v,ol) : getsockopt(s,l,n,v,ol)

union socket_addr {
	struct sockaddr		sa;
	struct sockaddr_in	sin;
	struct sockaddr_in6	sin6;
};

enum rs_optimization {
	opt_mixed,
	opt_latency,
	opt_bandwidth
};

int get_rdma_addr(const char *src, const char *dst, const char *port,
		  struct rdma_addrinfo *hints, struct rdma_addrinfo **rai);

struct oob_root {
	int *sock;
	int cnt;
};

int sock_recvdata(int sock, void *data, size_t size);
int sock_senddata(int sock, void *data, size_t size);

int oob_try_bind(const char *src_addr, const char *port);
int oob_root_setup(int listen_sock, struct oob_root *root, int cnt);
int oob_leaf_setup(const char *dst_addr, const char *port, int *sock);
int oob_syncup(int sock, char val);
int oob_syncdown(struct oob_root *root, char val);
int oob_gather(struct oob_root *root, void *data, size_t size_per_leaf);
int oob_senddown(struct oob_root *root, void *data, size_t size);
void oob_close_root(struct oob_root *root);

void size_str(char *str, size_t ssize, long long size);
void cnt_str(char *str, size_t ssize, long long cnt);
int size_to_count(int size);
void format_buf(void *buf, int size);
int verify_buf(void *buf, int size);
int do_poll(struct pollfd *fds, int timeout);

struct rdma_event_channel *create_event_channel(void);

static inline uint64_t gettime_ns(void)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return now.tv_sec * 1000000000 + now.tv_nsec;
}

static inline uint64_t gettime_us(void)
{
	return gettime_ns() / 1000;
}

static inline int sleep_us(unsigned int time_us)
{
	struct timespec spec;

	if (!time_us)
		return 0;

	spec.tv_sec = 0;
	spec.tv_nsec = time_us * 1000;
	return nanosleep(&spec, NULL);
}


struct work_item {
	struct work_item *next;
	void (*work_handler)(struct work_item *item);
};

struct work_queue {
	pthread_mutex_t lock;
	pthread_cond_t cond;

	pthread_t *thread;
	int thread_cnt;
	bool running;

	struct work_item *head;
	struct work_item *tail;
};

int wq_init(struct work_queue *wq, int thread_cnt);
void wq_cleanup(struct work_queue *wq);
void wq_insert(struct work_queue *wq, struct work_item *item,
	       void (*work_handler)(struct work_item *item));
struct work_item *wq_remove(struct work_queue *wq);
