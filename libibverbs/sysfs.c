/*
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdarg.h>

#include "ibverbs.h"

/*记录sysfs的路径前缀，默认为"/sys"*/
static const char *sysfs_path;

//取ib设备sysfs路径前缀，默认为"/sys"
const char *ibv_get_sysfs_path(void)
{
	const char *env = NULL;

	//已设置，则直接返回
	if (sysfs_path)
		return sysfs_path;

	/*
	 * Only follow use path passed in through the calling user's
	 * environment if we're not running SUID.
	 */
	if (getuid() == geteuid())
		env = getenv("SYSFS_PATH");

	if (env) {
		int len;
		char *dup;

		/*移除掉path结尾的'/'符*/
		sysfs_path = dup = strndup(env, IBV_SYSFS_PATH_MAX);
		len = strlen(dup);
		while (len > 0 && dup[len - 1] == '/') {
			--len;
			dup[len] = '\0';
		}
	} else
	    //默认使用/sys
		sysfs_path = "/sys";

	return sysfs_path;
}

//例如读取文件dirfd=/sys/class/infiniband_verbs/ file=uverbs0
int ibv_read_sysfs_file_at(int dirfd, const char *file, char *buf, size_t size)
{
	ssize_t len;
	int fd;

	fd = openat(dirfd, file, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;

	len = read(fd, buf, size);

	close(fd);

	if (len > 0) {
		if (buf[len - 1] == '\n')
			buf[--len] = '\0';
		else if (len < size)
			buf[len] = '\0';
		else
			/* We would have to truncate the contents to NULL
			 * terminate, so we are going to fail no matter
			 * what we do, either right now or later when
			 * we pass around an unterminated string.  Fail now.
			 */
			return -1;
	}

	return len;
}

int ibv_read_sysfs_file(const char *dir, const char *file,
			char *buf, size_t size)
{
	char *path;
	int res;

	if (asprintf(&path, "%s/%s", dir, file) < 0)
		return -1;

	res = ibv_read_sysfs_file_at(AT_FDCWD, path, buf, size);
	free(path);
	return res;
}

//读取sysfs_dev->ibdev_path的指定文件
int ibv_read_ibdev_sysfs_file(char *buf/*待填充buffer*/, size_t size,
			      struct verbs_sysfs_dev *sysfs_dev,
			      const char *fnfmt/*文件路径格式串*/, ...)
{
	char *path;
	va_list va;
	int res;

	if (!sysfs_dev) {
		errno = EINVAL;
		return -1;
	}

	va_start(va, fnfmt);
	if (vasprintf(&path, fnfmt, va) < 0) {
		va_end(va);
		return -1;
	}
	va_end(va);

	res = ibv_read_sysfs_file(sysfs_dev->ibdev_path, path, buf, size);
	free(path);
	return res;
}
