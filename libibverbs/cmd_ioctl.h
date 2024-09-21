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

#ifndef __INFINIBAND_VERBS_IOCTL_H
#define __INFINIBAND_VERBS_IOCTL_H

#include <config.h>

#include <stdint.h>
#include <assert.h>
#include <rdma/rdma_user_ioctl_cmds.h>
#include <infiniband/verbs.h>
#include <ccan/container_of.h>
#include <util/compiler.h>

/*指针转换为u64类型*/
static inline uint64_t ioctl_ptr_to_u64(const void *ptr)
{
	if (sizeof(ptr) == sizeof(uint64_t))
		return (uintptr_t)ptr;

	/*
	 * Some CPU architectures require sign extension when converting from
	 * a 32 bit to 64 bit pointer.  This should match the kernel
	 * implementation of compat_ptr() for the architecture.
	 */
#if defined(__tilegx__)
	return (int64_t)(intptr_t)ptr;
#else
	return (uintptr_t)ptr;
#endif
}

static inline void _scrub_ptr_attr(void **ptr)
{
#if UINTPTR_MAX == UINT64_MAX
	/* Do nothing */
#else
	RDMA_UAPI_PTR(void *, data) *scrub_data;

	scrub_data = container_of(ptr, typeof(*scrub_data), data);
	scrub_data->data_data_u64 = ioctl_ptr_to_u64(scrub_data->data);
#endif
}

#define scrub_ptr_attr(ptr) _scrub_ptr_attr((void **)(&ptr))

/*
 * The command buffer is organized as a linked list of blocks of attributes.
 * Each stack frame allocates its block and then calls up toward to core code
 * which will do the ioctl. The frame that does the ioctl calls the special
 * FINAL variant which will allocate enough space to linearize the attribute
 * buffer for the kernel.
 *
 * The current range of attributes to fill is next_attr -> last_attr.
 */
struct ibv_command_buffer {
    /*用于链接其它command buffer*/
	struct ibv_command_buffer *next;
	/*指向当前待填充的ib_uverbs_attr结构*/
	struct ib_uverbs_attr *next_attr;
	/*指向最后一个属性（可填充attr的最大边界）*/
	struct ib_uverbs_attr *last_attr;
	/*
	 * Used by the legacy write interface to keep track of where the UHW
	 * buffer is located and the 'headroom' space that the common code
	 * uses to construct the command header and common command struct
	 * directly before the drivers' UHW.
	 */
	uint8_t uhw_in_idx;/*UVERBS_ATTR_UHW_IN属性attr的位置（请求）*/
	uint8_t uhw_out_idx;/*UVERBS_ATTR_UHW_OUT属性attr的位置（响应）*/
	uint8_t uhw_in_headroom_dwords;/*core request长度*/
	uint8_t uhw_out_headroom_dwords;/*core response长度*/

	/*标记buffer在填充过程中遇到错误*/
	uint8_t buffer_error:1;
	/*
	 * These flags control what execute_ioctl_fallback does if the kernel
	 * does not support ioctl
	 */
	uint8_t fallback_require_ex:1;
	uint8_t fallback_ioctl_only:1;
	struct ib_uverbs_ioctl_hdr hdr;
	/*结尾是多个struct ib_uverbs_attr类型*/
};

enum {_UHW_NO_INDEX = 0xFF};

/*
 * Constructing an array of ibv_command_buffer is a reasonable way to expand
 * the VLA in hdr.attrs on the stack and also allocate some internal state in
 * a single contiguous stack memory region. It will over-allocate the region in
 * some cases, but this approach allows the number of elements to be dynamic,
 * and not fixed as a compile time constant.
 */
#define _IOCTL_NUM_CMDB(_num_attrs)                                            \
    /*获取当前需要多少个ibv_command_buffer结构来存放_num_attrs个struct ib_uvers_attr结构体*/\
	((sizeof(struct ibv_command_buffer)/*需要一个cmd buffer结构体*/ +        \
	  sizeof(struct ib_uverbs_attr) * (_num_attrs) +                       \
	  /*结构体按sizeof(struct ibv_command_buffer)进行对齐*/\
	  sizeof(struct ibv_command_buffer) - 1) /                             \
	 sizeof(struct ibv_command_buffer))

unsigned int __ioctl_final_num_attrs(unsigned int num_attrs,
				     struct ibv_command_buffer *link);

/* If the user doesn't provide a link then don't create a VLA */
#define _ioctl_final_num_attrs(_num_attrs/*属性数目*/, _link/*需要link的buffer*/)                              \
	((__builtin_constant_p(!(_link)) && !(_link))                          \
	     /*没有link，以_num_attrs为准*/\
		 ? (_num_attrs)                                                \
		 /*包含link buffer,计算link buffer中的属性数目，并与_num_attrs合并*/\
		 : __ioctl_final_num_attrs(_num_attrs, _link))

/*初始化ibv_command_buffer结构体的hdr成员（struct ib_uverbs_ioctl_hdr 类型）
 * .next,.uhw_in_idx,uhw_out_idx,next_attr,last_attr成员*/
#define _COMMAND_BUFFER_INIT(_hdr, _object_id, _method_id, _num_attrs, _link)  \
	((struct ibv_command_buffer){                                          \
		.hdr =                                                         \
			{                                                      \
	            /*设置obj与method id*/\
				.object_id = (_object_id),                     \
				.method_id = (_method_id),                     \
			},                                                     \
			/*指向下一个cmd buffer*/\
		.next = _link,                                                 \
		.uhw_in_idx = _UHW_NO_INDEX,                                   \
		.uhw_out_idx = _UHW_NO_INDEX,                                  \
		/*指向待填充的第一个属性*/\
		.next_attr = (_hdr).attrs,                                     \
		/*指向可填充的属性结尾*/\
		.last_attr = (_hdr).attrs + _num_attrs})

/*
 * C99 does not permit an initializer for VLAs, so this function does the init
 * instead. It is called in the wonky way so that DELCARE_COMMAND_BUFFER can
 * still be a 'variable', and we so we don't require C11 mode.
 */
static inline int _ioctl_init_cmdb(struct ibv_command_buffer *cmd/*命令buffer起始地址*/,
				   uint16_t object_id, uint16_t method_id,
				   size_t num_attrs/*属性总数*/,
				   struct ibv_command_buffer *link/*cmd链接的其它cmd buffer*/)
{
    /*初始化cmd，设置object_id及method_id*/
	*cmd = _COMMAND_BUFFER_INIT(cmd->hdr, object_id, method_id, num_attrs,
				    link);
	return 0;
}

/*
 * Construct an IOCTL command buffer on the stack with enough space for
 * _num_attrs elements. _num_attrs does not have to be a compile time constant.
 * _link is a previous COMMAND_BUFFER in the call chain.
 */
#ifndef __CHECKER__
#define DECLARE_COMMAND_BUFFER_LINK(_name/*命令buffer名称*/, _object_id/*obj编号*/, _method_id/*method编号*/, _num_attrs/*属性数*/, \
				    _link/*需要link的Buffer*/)                                     \
	/*定义属性数目总大小*/\
	const unsigned int __##_name##total =                                  \
		_ioctl_final_num_attrs(_num_attrs, _link);                     \
	/*定义command buffer,名称为_name，其内容长度足以容纳total个属性+cmd buffer*/\
	struct ibv_command_buffer _name[_IOCTL_NUM_CMDB(__##_name##total)];    \
	/*初始化command buffer*/\
	int __attribute__((unused)) __##_name##dummy = _ioctl_init_cmdb(       \
		_name, _object_id, _method_id, __##_name##total, _link)
#else
/*
 * sparse enforces kernel rules which forbids VLAs. Make the VLA into a static
 * array when running sparse. Don't actually run the sparse compile result.
 * Sparse also doesn't like arrays of VLAs
 */
#define DECLARE_COMMAND_BUFFER_LINK(_name, _object_id, _method_id, _num_attrs, \
				    _link)                                     \
	uint64_t __##_name##storage[10];                                       \
	struct ibv_command_buffer *_name = (void *)__##_name##storage[10];     \
	int __attribute__((unused)) __##_name##dummy =                         \
		_ioctl_init_cmdb(_name, _object_id, _method_id, 10, _link)
#endif

/*定义command buffer,并简单初始化（_link为NULL）*/
#define DECLARE_COMMAND_BUFFER(_name/*变量名*/, _object_id, _method_id, _num_attrs/*属性数目*/)      \
	DECLARE_COMMAND_BUFFER_LINK(_name, _object_id, _method_id, _num_attrs, \
				    NULL/*link buffer为NULL*/)

int execute_ioctl(struct ibv_context *context, struct ibv_command_buffer *cmd);

/*分配一个指定attr_id的ib_uverbs_attr*/
static inline struct ib_uverbs_attr *
_ioctl_next_attr(struct ibv_command_buffer *cmd, uint16_t attr_id)
{
	struct ib_uverbs_attr *attr;

	/*小于最后一个属性（确保有空间）*/
	assert(cmd->next_attr < cmd->last_attr);

	/*增加attr,并进行设置attr*/
	attr = cmd->next_attr++;

	/*设置此属性id*/
	*attr = (struct ib_uverbs_attr){
		.attr_id = attr_id,
		/*
		 * All attributes default to mandatory. Wrapper the fill_*
		 * call in attr_optional() to make it optional.
		 */
		.flags = UVERBS_ATTR_F_MANDATORY,/*指明用户输入的属性*/
	};

	/*返回当前新分配的attr空间*/
	return attr;
}

/*
 * This construction is insane, an expression with a side effect that returns
 * from the calling function, but it is a non-invasive way to get the compiler
 * to elide the IOCTL support in the backwards compat command functions
 * without disturbing native ioctl support.
 *
 * A command function will set last_attr on the stack to NULL, and if it is
 * coded properly, the compiler will prove that last_attr is never changed and
 * elide the function. Unfortunately this penalizes native ioctl uses with the
 * extra if overhead.
 *
 * For this reason, _ioctl_next_attr must never be called outside a fill
 * function.
 */
#if VERBS_WRITE_ONLY
#define _ioctl_next_attr(cmd, attr_id)                                         \
	({                                                                     \
		if (!((cmd)->last_attr))                                       \
			return NULL;                                           \
		_ioctl_next_attr(cmd, attr_id);                                \
	})
#endif

/* Make the attribute optional. */
static inline struct ib_uverbs_attr *attr_optional(struct ib_uverbs_attr *attr)
{
	if (!attr)
		return attr;

	attr->flags &= ~UVERBS_ATTR_F_MANDATORY;
	return attr;
}

/* Send attributes of kernel type UVERBS_ATTR_TYPE_IDR */
static inline struct ib_uverbs_attr *
fill_attr_in_obj(struct ibv_command_buffer *cmd, uint16_t attr_id, uint32_t idr)
{
    /*构造attr，并设置idr*/
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	/* UVERBS_ATTR_TYPE_IDR uses a 64 bit value for the idr # */
	attr->data = idr;
	return attr;
}

static inline struct ib_uverbs_attr *
fill_attr_out_obj(struct ibv_command_buffer *cmd, uint16_t attr_id)
{
    /*添加attr_id的struct ib_uverbs_attr*/
	return fill_attr_in_obj(cmd, attr_id, 0);
}

static inline uint32_t read_attr_obj(uint16_t attr_id,
				     struct ib_uverbs_attr *attr)
{
	assert(attr->attr_id == attr_id);
	return attr->data;
}

/* Send attributes of kernel type UVERBS_ATTR_TYPE_PTR_IN */
static inline struct ib_uverbs_attr *
fill_attr_in(struct ibv_command_buffer *cmd, uint16_t attr_id, const void *data,
	     size_t len)
{
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	if (unlikely(len > UINT16_MAX))
	    /*无效长度*/
		cmd->buffer_error = 1;

	attr->len = len;
	/*内容长度小于u64,则填充到attr->data,否则使指针指向*/
	if (len <= sizeof(uint64_t))
		memcpy(&attr->data, data, len);
	else
		attr->data = ioctl_ptr_to_u64(data);

	return attr;
}

#define fill_attr_in_ptr(cmd, attr_id, ptr)                                    \
	fill_attr_in(cmd, attr_id, ptr, sizeof(*ptr))

/* Send attributes of various inline kernel types */

static inline struct ib_uverbs_attr *
fill_attr_in_uint64(struct ibv_command_buffer *cmd, uint16_t attr_id,
		    uint64_t data)
{
	/*新建属性，并设置attr(uint64类型）*/
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	attr->len = sizeof(data);
	attr->data = data;/*属性值*/

	return attr;
}

/*增加一个属性(attr_id)*/
#define fill_attr_const_in(cmd, attr_id, _data) \
	fill_attr_in_uint64(cmd, attr_id, _data)

static inline struct ib_uverbs_attr *
fill_attr_in_uint32(struct ibv_command_buffer *cmd, uint16_t attr_id,
		    uint32_t data)
{
	/*新建属性，并设置attr(uint32类型）*/
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	attr->len = sizeof(data);
	memcpy(&attr->data, &data, sizeof(data));

	return attr;
}

static inline struct ib_uverbs_attr *
fill_attr_in_fd(struct ibv_command_buffer *cmd, uint16_t attr_id, int fd)
{
	struct ib_uverbs_attr *attr;

	if (fd == -1)
		return NULL;

	attr = _ioctl_next_attr(cmd, attr_id);
	/* UVERBS_ATTR_TYPE_FD uses a 64 bit value for the idr # */
	attr->data = fd;
	return attr;
}

static inline struct ib_uverbs_attr *
fill_attr_out_fd(struct ibv_command_buffer *cmd, uint16_t attr_id, int fd)
{
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	attr->data = 0;
	return attr;
}

/*读取返回的属性*/
static inline int read_attr_fd(uint16_t attr_id, struct ib_uverbs_attr *attr)
{
	assert(attr->attr_id == attr_id);
	/* The kernel cannot fail to create a FD here, it never returns -1 */
	return attr->data;
}

/* Send attributes of kernel type UVERBS_ATTR_TYPE_PTR_OUT */
/*在cmd buffer上分配并填充指定attr_id的ib_uverbs_attr*/
static inline struct ib_uverbs_attr *
fill_attr_out(struct ibv_command_buffer *cmd, uint16_t attr_id/*属性id号*/, void *data/*属性value*/,
	      size_t len/*属性value对应的长度*/)
{
    /*分配此类型的attr*/
	struct ib_uverbs_attr *attr = _ioctl_next_attr(cmd, attr_id);

	if (unlikely(len > UINT16_MAX))
		cmd->buffer_error = 1;

	/*设置len,data*/
	attr->len = len;
	attr->data = ioctl_ptr_to_u64(data);

	return attr;
}

/*分配并填充attr_id*/
#define fill_attr_out_ptr(cmd, attr_id, ptr)                                 \
	fill_attr_out(cmd, attr_id, ptr, sizeof(*(ptr)))

/* If size*nelems overflows size_t this returns SIZE_MAX */
static inline size_t _array_len(size_t size, size_t nelems)
{
	if (size != 0 &&
	    SIZE_MAX / size <= nelems)
		return SIZE_MAX;
	return size * nelems;
}

#define fill_attr_out_ptr_array(cmd, attr_id, ptr, nelems)                     \
	fill_attr_out(cmd, attr_id, ptr, _array_len(sizeof(*ptr), nelems))

#define fill_attr_in_ptr_array(cmd, attr_id, ptr, nelems)                       \
	fill_attr_in(cmd, attr_id, ptr, _array_len(sizeof(*ptr), nelems))

static inline size_t __check_divide(size_t val, unsigned int div)
{
	assert(val % div == 0);
	return val / div;
}

static inline struct ib_uverbs_attr *
fill_attr_in_enum(struct ibv_command_buffer *cmd, uint16_t attr_id,
		  uint8_t elem_id, const void *data, size_t len)
{
	struct ib_uverbs_attr *attr;

	attr = fill_attr_in(cmd, attr_id, data, len);
	attr->attr_data.enum_data.elem_id = elem_id;

	return attr;
}

/* Send attributes of kernel type UVERBS_ATTR_TYPE_IDRS_ARRAY */
static inline struct ib_uverbs_attr *
fill_attr_in_objs_arr(struct ibv_command_buffer *cmd, uint16_t attr_id,
		      const uint32_t *idrs_arr, size_t nelems)
{
	return fill_attr_in(cmd, attr_id, idrs_arr,
			    _array_len(sizeof(*idrs_arr), nelems));
}

#endif
