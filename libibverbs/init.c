/*
 * Copyright (c) 2004, 2005 Topspin Communications.  All rights reserved.
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
#define _GNU_SOURCE
#include <config.h>

#include <stdlib.h>
#include <string.h>
#include <glob.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <assert.h>
#include <fnmatch.h>
#include <sys/sysmacros.h>

#include <rdma/rdma_netlink.h>

#include <util/util.h>
#include "driver.h"
#include "ibverbs.h"
#include <infiniband/cmd_write.h>

int abi_ver;

/*verbs日志级别，通过环境变量‘VERBS_LOG_LEVEL’，‘VERBS_LOG_FILE’可以控制*/
static uint32_t verbs_log_level;
/*verbs日志输出文件*/
static FILE *verbs_log_fp;

__attribute__((format(printf, 3, 4)))
void __verbs_log(struct verbs_context *ctx, uint32_t level,
		 const char *fmt, ...)
{
	va_list args;

	if (level <= verbs_log_level) {
		int tmp = errno;
		va_start(args, fmt);
		vfprintf(verbs_log_fp, fmt, args);
		va_end(args);
		errno = tmp;
	}
}

struct ibv_driver {
	struct list_node	entry;
	const struct verbs_device_ops *ops;/*驱动操作集*/
};

/*记录系统用户态driver list*/
static LIST_HEAD(driver_list);

//尝试访问指定设备文件，设备必须存在,例如/dev/infiniband/uverbs13
int try_access_device(const struct verbs_sysfs_dev *sysfs_dev)
{
	struct stat cdev_stat;
	char *devpath;
	int ret;

	if (asprintf(&devpath, RDMA_CDEV_DIR"/%s",
		     sysfs_dev->sysfs_name) < 0)
		return ENOMEM;

	ret = stat(devpath, &cdev_stat);
	free(devpath);
	return ret;
}

enum ibv_node_type decode_knode_type(unsigned int knode_type)
{
	switch (knode_type) {
	case RDMA_NODE_IB_CA:
		return IBV_NODE_CA;
	case RDMA_NODE_IB_SWITCH:
		return IBV_NODE_SWITCH;
	case RDMA_NODE_IB_ROUTER:
		return IBV_NODE_ROUTER;
	case RDMA_NODE_RNIC:
		return IBV_NODE_RNIC;
	case RDMA_NODE_USNIC:
		return IBV_NODE_USNIC;
	case RDMA_NODE_USNIC_UDP:
		return IBV_NODE_USNIC_UDP;
	case RDMA_NODE_UNSPECIFIED:
		return IBV_NODE_UNSPECIFIED;
	}
	return IBV_NODE_UNKNOWN;
}

int setup_sysfs_uverbs(int uv_dirfd, const char *uverbs,
		       struct verbs_sysfs_dev *sysfs_dev)
{
	unsigned int major;
	unsigned int minor;
	struct stat buf;
	char value[32];

	//构造设备名称
	if (!check_snprintf(sysfs_dev->sysfs_name,
			    sizeof(sysfs_dev->sysfs_name), "%s", uverbs))
		return -1;

	if (stat(sysfs_dev->ibdev_path, &buf))
		return -1;
	sysfs_dev->time_created = buf.st_mtim;

	//读取dev文件
	//root@host:/sys/class/infiniband/mlx5_0/device/infiniband_verbs/uverbs0# cat dev
	//231:192
	if (ibv_read_sysfs_file_at(uv_dirfd, "dev", value,
				   sizeof(value)) < 0)
		return -1;
	if (sscanf(value, "%u:%u", &major, &minor) != 2)
		return -1;
	sysfs_dev->sysfs_cdev = makedev(major, minor);

	//读取abi版本
	if (ibv_read_sysfs_file_at(uv_dirfd, "abi_version", value,
				   sizeof(value)) > 0)
		sysfs_dev->abi_ver = strtoul(value, NULL, 10);

	return 0;
}

static int setup_sysfs_dev(int dirfd, const char *uverbs,
			   struct list_head *tmp_sysfs_dev_list)
{
	struct verbs_sysfs_dev *sysfs_dev = NULL;
	char value[32];
	int uv_dirfd;

	sysfs_dev = calloc(1, sizeof(*sysfs_dev));
	if (!sysfs_dev)
		return ENOMEM;

	sysfs_dev->ibdev_idx = -1;

	//打开dirfd中的文件uverbs
	uv_dirfd = openat(dirfd, uverbs, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (uv_dirfd == -1)
		goto err_alloc;

	//打开uv_dirfd目录fd,并读取'ibdev'文件（例如：/sys/class/infiniband_verbs/uverbs0/ibdev)
	//将获取到的内容存放到sysfs_dev->ibdev_name中
	//例如读取到'mlx5_0'
	if (ibv_read_sysfs_file_at(uv_dirfd, "ibdev", sysfs_dev->ibdev_name,
				   sizeof(sysfs_dev->ibdev_name)) < 0)
		goto err_fd;

	//构造infiniband文件
	if (!check_snprintf(
		    sysfs_dev->ibdev_path, sizeof(sysfs_dev->ibdev_path),
		    "%s/class/infiniband/%s", ibv_get_sysfs_path(),
		    sysfs_dev->ibdev_name))
		goto err_fd;

	//填充sysfs_dev
	if (setup_sysfs_uverbs(uv_dirfd, uverbs, sysfs_dev))
		goto err_fd;

	//读取/sys/class/infiniband/%s/node_type
	if (ibv_read_ibdev_sysfs_file(value, sizeof(value), sysfs_dev,
				      "node_type") <= 0)
		sysfs_dev->node_type = IBV_NODE_UNKNOWN;
	else
		sysfs_dev->node_type =
			decode_knode_type(strtoul(value, NULL, 10));

	//确保设备存在
	if (try_access_device(sysfs_dev))
		goto err_fd;

	close(uv_dirfd);
	//记录sysfs_dev
	list_add(tmp_sysfs_dev_list, &sysfs_dev->entry);
	return 0;

err_fd:
	close(uv_dirfd);
err_alloc:
	free(sysfs_dev);
	return 0;
}

static int find_sysfs_devs(struct list_head *tmp_sysfs_dev_list)
{
	struct verbs_sysfs_dev *dev, *dev_tmp;
	char class_path[IBV_SYSFS_PATH_MAX];
	DIR *class_dir;
	struct dirent *dent;
	int ret = 0;

	//构造infiniband_verbs目录路径
	if (!check_snprintf(class_path, sizeof(class_path),
			    "%s/class/infiniband_verbs", ibv_get_sysfs_path()))
		return ENOMEM;

	class_dir = opendir(class_path);
	if (!class_dir)
		return ENOSYS;

	//遍历infiniband_verbs目录
	while ((dent = readdir(class_dir))) {
		if (dent->d_name[0] == '.')
			continue;//跳过'.','..'

		//填充sysfs_dev
		ret = setup_sysfs_dev(dirfd(class_dir), dent->d_name,
				      tmp_sysfs_dev_list);
		if (ret)
			break;
	}
	closedir(class_dir);

	//如果出错，则移除设备
	if (ret) {
		list_for_each_safe (tmp_sysfs_dev_list, dev, dev_tmp, entry) {
			list_del(&dev->entry);
			free(dev);
		}
	}
	return ret;
}

//注册verbs设备driver
void verbs_register_driver(const struct verbs_device_ops *ops)
{
	struct ibv_driver *driver;

	driver = malloc(sizeof *driver);
	if (!driver) {
		fprintf(stderr,
			PFX "Warning: couldn't allocate driver for %s\n",
			ops->name);
		return;
	}

	/*此driver对应的ops*/
	driver->ops = ops;

	list_add_tail(&driver_list, &driver->entry);/*注册驱动*/
}

/* Match a single modalias value */
static bool match_modalias(const struct verbs_match_ent *ent, const char *value)
{
	char pci_ma[100];

	switch (ent->kind) {
	case VERBS_MATCH_MODALIAS:
		return fnmatch(ent->u.modalias, value, 0) == 0;
	case VERBS_MATCH_PCI:
		snprintf(pci_ma, sizeof(pci_ma), "pci:v%08Xd%08Xsv*",
			 ent->vendor, ent->device);
		return fnmatch(pci_ma, value, 0) == 0;
	default:
		return false;
	}
}

/* Search a null terminated table of verbs_match_ent's and return the one
 * that matches the device the verbs sysfs device is bound to or NULL.
 */
static const struct verbs_match_ent *
match_modalias_device(const struct verbs_device_ops *ops,
		      struct verbs_sysfs_dev *sysfs_dev)
{
	const struct verbs_match_ent *i;

	if (!(sysfs_dev->flags & VSYSFS_READ_MODALIAS)) {
		sysfs_dev->flags |= VSYSFS_READ_MODALIAS;
		if (ibv_read_ibdev_sysfs_file(
			    sysfs_dev->modalias, sizeof(sysfs_dev->modalias),
			    sysfs_dev, "device/modalias") <= 0) {
			sysfs_dev->modalias[0] = 0;
			return NULL;
		}
	}

	for (i = ops->match_table; i->kind != VERBS_MATCH_SENTINEL; i++)
		if (match_modalias(i, sysfs_dev->modalias))
			return i;

	return NULL;
}

/* Match the device name itself */
static const struct verbs_match_ent *
match_name(const struct verbs_device_ops *ops,
		      struct verbs_sysfs_dev *sysfs_dev)
{
	char name_ma[100];
	const struct verbs_match_ent *i;

	//构造匹配名称
	if (!check_snprintf(name_ma, sizeof(name_ma),
			    "rdma_device:N%s", sysfs_dev->ibdev_name))
		return NULL;

	//按名称进行匹配（例如pci地址，模块别名）
	for (i = ops->match_table; i->kind != VERBS_MATCH_SENTINEL; i++)
		if (match_modalias(i, name_ma))
			return i;

	return NULL;
}

/* Match the driver id we get from netlink */
//按driver_id方式匹配sysfs_dev
static const struct verbs_match_ent *
match_driver_id(const struct verbs_device_ops *ops,
		struct verbs_sysfs_dev *sysfs_dev)
{
	const struct verbs_match_ent *i;

	//如果未配置driver,则返回NULL
	if (sysfs_dev->driver_id == RDMA_DRIVER_UNKNOWN)
		return NULL;

	//遍历ops的匹配table,如果指明为driver id匹配方式，则比对driver_id，否则直接失配；若命中，返回i
	for (i = ops->match_table; i->kind != VERBS_MATCH_SENTINEL; i++)
		if (i->kind == VERBS_MATCH_DRIVER_ID &&
		    i->u.driver_id == sysfs_dev->driver_id)
			return i;
	return NULL;
}

/* True if the provider matches the selected rdma sysfs device */
static bool match_device(const struct verbs_device_ops *ops,
			 struct verbs_sysfs_dev *sysfs_dev)
{
	if (ops->match_table) {
	    //尝试driver_id方式匹配
		sysfs_dev->match = match_driver_id(ops, sysfs_dev);
		if (!sysfs_dev->match)
		    //尝试按名称进行匹配
			sysfs_dev->match = match_name(ops, sysfs_dev);
		if (!sysfs_dev->match)
		    //尝试模块别名匹配
			sysfs_dev->match =
			    match_modalias_device(ops, sysfs_dev);
	}

	if (ops->match_device) {
		/* If a matching function is provided then it is called
		 * unconditionally after the table match above, it is
		 * responsible for determining if the device matches based on
		 * the match pointer and any other internal information.
		 */
		if (!ops->match_device(sysfs_dev))
		    /*驱动不能匹配此设备，返回false*/
			return false;
	} else {
	    //未指供配置函数，但sysfs_dev仍未匹配，则返回false
		/* With no match function, we must have a table match */
		if (!sysfs_dev->match)
			return false;
	}

	//执行abi版本号检查
	if (sysfs_dev->abi_ver < ops->match_min_abi_version ||
	    sysfs_dev->abi_ver > ops->match_max_abi_version) {
		fprintf(stderr, PFX
			"Warning: Driver %s does not support the kernel ABI of %u (supports %u to %u) for device %s\n",
			ops->name, sysfs_dev->abi_ver,
			ops->match_min_abi_version,
			ops->match_max_abi_version,
			sysfs_dev->ibdev_path);
		return false;
	}
	return true;
}

/*创建sysfs_dev对应的verbs_device，并完成创建*/
static struct verbs_device *try_driver(const struct verbs_device_ops *ops,
				       struct verbs_sysfs_dev *sysfs_dev)
{
	struct verbs_device *vdev;
	struct ibv_device *dev;

	//尝试多种match方式，识别sysfs_dev的驱动，如果不匹配，直接返回NULL
	if (!match_device(ops, sysfs_dev))
		return NULL;

	//通过驱动，依据sysfs_dev创建verbs_device
	vdev = ops->alloc_device(sysfs_dev);
	if (!vdev) {
		fprintf(stderr, PFX "Fatal: couldn't allocate device for %s\n",
			sysfs_dev->ibdev_path);
		return NULL;
	}

	//设置device对应的ops
	vdev->ops = ops;

	atomic_init(&vdev->refcount, 1);
	dev = &vdev->device;
	assert(dev->_ops._dummy1 == NULL);
	assert(dev->_ops._dummy2 == NULL);

	//依据设备类型，确定传输层类型
	dev->node_type = sysfs_dev->node_type;
	switch (sysfs_dev->node_type) {
	case IBV_NODE_CA:
	case IBV_NODE_SWITCH:
	case IBV_NODE_ROUTER:
		/*协议为ib*/
		dev->transport_type = IBV_TRANSPORT_IB;
		break;
	case IBV_NODE_RNIC:
		/*协议为iwarp*/
		dev->transport_type = IBV_TRANSPORT_IWARP;
		break;
	case IBV_NODE_USNIC:
		dev->transport_type = IBV_TRANSPORT_USNIC;
		break;
	case IBV_NODE_USNIC_UDP:
		dev->transport_type = IBV_TRANSPORT_USNIC_UDP;
		break;
	case IBV_NODE_UNSPECIFIED:
		dev->transport_type = IBV_TRANSPORT_UNSPECIFIED;
		break;
	default:
		dev->transport_type = IBV_TRANSPORT_UNKNOWN;
		break;
	}

	/*填充设备名称*/
	strcpy(dev->dev_name,   sysfs_dev->sysfs_name);
	if (!check_snprintf(dev->dev_path, sizeof(dev->dev_path),
			    "%s/class/infiniband_verbs/%s",
			    ibv_get_sysfs_path(), sysfs_dev->sysfs_name))
		goto err;
	strcpy(dev->name,       sysfs_dev->ibdev_name);
	strcpy(dev->ibdev_path, sysfs_dev->ibdev_path);
	vdev->sysfs = sysfs_dev;

	return vdev;

err:
	ops->uninit_device(vdev);
	return NULL;
}

//查找sysfs_dev对应的驱动 ，并返回创建的verbs_device
static struct verbs_device *try_drivers(struct verbs_sysfs_dev *sysfs_dev)
{
	struct ibv_driver *driver;
	struct verbs_device *dev;

	/*
	 * Matching by driver_id takes priority over other match types, do it
	 * first.
	 */
	if (sysfs_dev->driver_id != RDMA_DRIVER_UNKNOWN) {
	    /*kernel为设备指明了driver_id,按driver_id匹配，
	     * 如果可匹配，则依据sysfs_dev创建verbs_devices*/
		list_for_each (&driver_list, driver, entry) {
			if (match_driver_id(driver->ops, sysfs_dev)) {
				dev = try_driver(driver->ops, sysfs_dev);
				if (dev)
					return dev;
			}
		}
	}

	/*设备没有指明driver_id,遍历所有driver,多方检查驱动能否可匹配,
	如果可匹配，则创建verbs_devices*/
	list_for_each(&driver_list, driver, entry) {
		dev = try_driver(driver->ops, sysfs_dev);
		if (dev)
			return dev;
	}

	return NULL;
}

static int check_abi_version(void)
{
	char value[8];

	if (abi_ver)
		return 0;

	/*读取verbs的abi版本*/
	if (ibv_read_sysfs_file(ibv_get_sysfs_path(),
				"class/infiniband_verbs/abi_version", value,
				sizeof(value)) < 0) {
		return ENOSYS;
	}

	abi_ver = strtol(value, NULL, 10);

	if (abi_ver < IB_USER_VERBS_MIN_ABI_VERSION ||
	    abi_ver > IB_USER_VERBS_MAX_ABI_VERSION) {
	    /*abi版本在当前软件支持范围以外，报错*/
		fprintf(stderr, PFX "Fatal: kernel ABI version %d "
			"doesn't match library version %d.\n",
			abi_ver, IB_USER_VERBS_MAX_ABI_VERSION);
		return ENOSYS;
	}

	return 0;
}

static void check_memlock_limit(void)
{
	struct rlimit rlim;

	if (!geteuid())
		return;

	if (getrlimit(RLIMIT_MEMLOCK, &rlim)) {
		fprintf(stderr, PFX "Warning: getrlimit(RLIMIT_MEMLOCK) failed.");
		return;
	}

	if (rlim.rlim_cur <= 32768)
		fprintf(stderr, PFX "Warning: RLIMIT_MEMLOCK is %llu bytes.\n"
			"    This will severely limit memory registrations.\n",
			(unsigned long long)rlim.rlim_cur);
}

static int same_sysfs_dev(struct verbs_sysfs_dev *sysfs1,
			  struct verbs_sysfs_dev *sysfs2)
{
	if (strcmp(sysfs1->sysfs_name, sysfs2->sysfs_name) != 0)
		return 0;

	/* In netlink mode the idx is a globally unique ID */
	if (sysfs1->ibdev_idx != sysfs2->ibdev_idx)
		return 0;

	if (sysfs1->ibdev_idx == -1 &&
	    ts_cmp(&sysfs1->time_created, &sysfs2->time_created, !=))
		return 0;

	return 1;
}

/* Match every ibv_sysfs_dev in the sysfs_list to a driver and add a new entry
 * to device_list. Once matched to a driver the entry in sysfs_list is
 * removed.
 */
static void try_all_drivers(struct list_head *sysfs_list/*新增的verbs_device设备列表*/,
			    struct list_head *device_list/*入出参，sysfs_dev对应的verbs_device*/,
			    unsigned int *num_devices/*出参，verbs_device设备数目*/)
{
	struct verbs_sysfs_dev *sysfs_dev;
	struct verbs_sysfs_dev *tmp;
	struct verbs_device *vdev;

	//遍历sysfs_list,针对自sysfs中获得的每个dev
	list_for_each_safe(sysfs_list, sysfs_dev, tmp, entry) {
		//尝试创建其对应的verbs_device
		vdev = try_drivers(sysfs_dev);
		if (vdev) {
		    /*创建成功，自sysfs_list中移除*/
			list_del(&sysfs_dev->entry);
			/* Ownership of sysfs_dev moves into vdev->sysfs */
			//将其加入到识别的device_list中
			list_add(device_list, &vdev->entry);
			(*num_devices)++;
		}
	}
}

//收集所有ib设备,创建verbs_device,并返回设备数目（非线程安全）
int ibverbs_get_device_list(struct list_head *device_list/*入出参，识别出来的设备verbs_device*/)
{
	LIST_HEAD(sysfs_list);
	struct verbs_sysfs_dev *sysfs_dev, *next_dev;
	struct verbs_device *vdev, *tmp;
	static int drivers_loaded;
	unsigned int num_devices = 0;
	int ret;

	//通过netlink socket列出系统可用ib设备
	ret = find_sysfs_devs_nl(&sysfs_list);
	if (ret) {
	    //通过netlink获取仅失败时，才通过sysfs进行获取
		ret = find_sysfs_devs(&sysfs_list);
		if (ret)
			return -ret;
	}

	if (!list_empty(&sysfs_list)) {
	    /*检查abi版本是否本lib支持*/
		ret = check_abi_version();
		if (ret)
			return -ret;
	}

	/* Remove entries from the sysfs_list that are already preset in the
	 * device_list, and remove entries from the device_list that are not
	 * present in the sysfs_list.
	 */
	list_for_each_safe(device_list/*上一次已识别的设备*/, vdev, tmp, entry) {
		struct verbs_sysfs_dev *old_sysfs = NULL;

		list_for_each(&sysfs_list/*本次识别出来的设备*/, sysfs_dev, entry) {
			if (same_sysfs_dev(vdev->sysfs, sysfs_dev)) {
			    /*跳过已识别出来的设备*/
				old_sysfs = sysfs_dev;
				break;
			}
		}

		if (old_sysfs) {
		    /*设备在device_list与sysfs_list中同时存在，自sysfs_list中移除，设备数增加*/
			list_del(&old_sysfs->entry);
			free(old_sysfs);
			num_devices++;
		} else {
		    /*设备仅在device_list中存在（现在不存在了，自device_list中移除），设备数不增加*/
			list_del(&vdev->entry);
			ibverbs_device_put(&vdev->device);/*引用计数减1，如果无应用引用，则释放*/
		}
	}

	/*此时sysfs_list上存放的是本次新增的设备，且device_list上本次删除设备已移除*/
	try_all_drivers(&sysfs_list, device_list, &num_devices/*device_list链表长度*/);

	/* 如果sysfs_list为空，则所有设备均完成创建并加入到device_list
	 * 如果drivers_loaded为真，则上次已完成driver_list收集，跳过后面处理*/
	if (list_empty(&sysfs_list) || drivers_loaded)
		goto out;

	/*由于存在未被识别的sysfs_list,故尝试加载驱动，重新尝试一次,并构造device_list*/
	load_drivers();
	drivers_loaded = 1;

	try_all_drivers(&sysfs_list, device_list, &num_devices);/*驱动已加载，再尝试一次*/

out:
	/* Anything left in sysfs_list was not assoicated with a
	 * driver.
	 */
    //如果仍存在未识别的sysfs_list（内核态认识，但用户态不认识），告警表示哪些sysfs_dev未识别到驱动，并释放这些sysfs_dev
	list_for_each_safe(&sysfs_list, sysfs_dev, next_dev, entry) {
		if (getenv("IBV_SHOW_WARNINGS")) {
			fprintf(stderr, PFX
				"Warning: no userspace device-specific driver found for %s\n",
				sysfs_dev->ibdev_name);
		}
		free(sysfs_dev);
	}

	/*返回获得的device数目*/
	return num_devices;
}

/*设置verbs日志级别*/
static void verbs_set_log_level(void)
{
	char *env;

	env = getenv("VERBS_LOG_LEVEL");
	if (env)
		verbs_log_level = strtol(env, NULL, 0);
}

/*
 * Fallback in case log file is not provided or can't be opened.
 * Release mode: disable debug prints.
 * Debug mode: Use stderr instead of a file.
 */
static void verbs_log_file_fallback(void)
{
#ifdef VERBS_DEBUG
	verbs_log_fp = stderr;
#else
	verbs_log_level = VERBS_LOG_LEVEL_NONE;
#endif
}

/*verbs日志文件设置*/
static void verbs_set_log_file(void)
{
	char *env;

	if (verbs_log_level == VERBS_LOG_LEVEL_NONE)
		return;

	env = getenv("VERBS_LOG_FILE");
	if (!env) {
	    /*未设置此环境变量情况下，可以会回退日志level到不生效*/
		verbs_log_file_fallback();
		return;
	}

	/*打开指定的verbs日志文件*/
	verbs_log_fp = fopen(env, "aw+");
	if (!verbs_log_fp) {
		verbs_log_file_fallback();
		return;
	}
}

/*verbs初始化函数*/
int ibverbs_init(void)
{
	if (check_env("RDMAV_FORK_SAFE") || check_env("IBV_FORK_SAFE"))
		if (ibv_fork_init())
		    /*告警,初始化失败，kernel不支持fork调用*/
			fprintf(stderr, PFX "Warning: fork()-safety requested "
				"but init failed\n");

	verbs_allow_disassociate_destroy = check_env("RDMAV_ALLOW_DISASSOC_DESTROY")
		/* Backward compatibility for the mlx4 driver env */
		|| check_env("MLX4_DEVICE_FATAL_CLEANUP");

	/*高级置sysfs前缀路径*/
	if (!ibv_get_sysfs_path())
		return -errno;

	//？？？？
	check_memlock_limit();

	/*日志级别及日志文件处理*/
	verbs_set_log_level();
	verbs_set_log_file();

	return 0;
}

//增加ibv_device设备引用计数
void ibverbs_device_hold(struct ibv_device *dev)
{
	struct verbs_device *verbs_device = verbs_get_device(dev);

	atomic_fetch_add(&verbs_device->refcount, 1);
}

void ibverbs_device_put(struct ibv_device *dev)
{
    /*先转换为verbs_device,并进行引用计数减少，如果减为0，则调用uninit_device进行释放*/
	struct verbs_device *verbs_device = verbs_get_device(dev);

	if (atomic_fetch_sub(&verbs_device->refcount, 1) == 1) {
		/*无应用引用此值*/
		free(verbs_device->sysfs);
		if (verbs_device->ops->uninit_device)
			verbs_device->ops->uninit_device(verbs_device);
	}
}
