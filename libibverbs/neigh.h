/* Licensed under the OpenIB.org BSD license (FreeBSD Variant) - See COPYING.md
 */

#ifndef _NEIGH_H_
#define _NEIGH_H_

#include <stddef.h>
#include <stdint.h>
#include "config.h"
#include <netlink/object-api.h>

struct get_neigh_handler {
	struct nl_sock *sock;
	struct nl_cache *link_cache;/*link信息*/
	struct nl_cache	*neigh_cache;/*neigh信息*/
	struct nl_cache *route_cache;/*route信息*/
	int32_t oif;/*出接口if*/
	int vid;/*出接口对应的vlan id*/
	struct rtnl_neigh *filter_neigh;/*目的neigh*/
	struct nl_addr *found_ll_addr;/*获取neigh对应的Link local地址*/
	struct nl_addr *dst;
	struct nl_addr *src;
	uint64_t timeout;
};

int process_get_neigh(struct get_neigh_handler *neigh_handler);
void neigh_free_resources(struct get_neigh_handler *neigh_handler);
void neigh_set_vlan_id(struct get_neigh_handler *neigh_handler, uint16_t vid);
uint16_t neigh_get_vlan_id_from_dev(struct get_neigh_handler *neigh_handler);
int neigh_init_resources(struct get_neigh_handler *neigh_handler, int timeout);

int neigh_set_src(struct get_neigh_handler *neigh_handler,
		  int family, void *buf, size_t size);
void neigh_set_oif(struct get_neigh_handler *neigh_handler, int oif);
int neigh_set_dst(struct get_neigh_handler *neigh_handler,
		  int family, void *buf, size_t size);
int neigh_get_oif_from_src(struct get_neigh_handler *neigh_handler);
int neigh_get_ll(struct get_neigh_handler *neigh_handler, void *addr_buf,
		 int addr_size);

#endif
