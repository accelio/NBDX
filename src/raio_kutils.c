/*
 * Copyright (c) 2013 Mellanox Technologies®. All rights reserved.
 *
 * This software is available to you under a choice of one of two licenses.
 * You may choose to be licensed under the terms of the GNU General Public
 * License (GPL) Version 2, available from the file COPYING in the main
 * directory of this source tree, or the Mellanox Technologies® BSD license
 * below:
 *
 *      - Redistribution and use in source and binary forms, with or without
 *        modification, are permitted provided that the following conditions
 *        are met:
 *
 *      - Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 *      - Neither the name of the Mellanox Technologies® nor the names of its
 *        contributors may be used to endorse or promote products derived from
 *        this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "raio_kbuffer.h"
#include "raio_kutils.h"


/*---------------------------------------------------------------------------*/
/* unpack_stat64				                             */
/*---------------------------------------------------------------------------*/
const char *unpack_stat64(struct r_stat64 *result, const char *buffer)
{
	uint64_t dev		= 0;
	uint64_t ino		= 0;
	uint32_t mode		= 0;
	uint32_t nlink		= 0;
	uint64_t uid		= 0;
	uint64_t gid		= 0;
	uint64_t rdev		= 0;
	uint64_t size		= 0;
	uint32_t blksize	= 0;
	uint32_t blocks		= 0;
	uint64_t atime		= 0;
	uint64_t mtime		= 0;
	uint64_t ctime		= 0;


	unpack_u64(&ctime,
	unpack_u64(&mtime,
	unpack_u64(&atime,
	unpack_u32(&blocks,
	unpack_u32(&blksize,
	unpack_u64(&size,
	unpack_u64(&rdev,
	unpack_u64(&gid,
	unpack_u64(&uid,
	unpack_u32(&nlink,
	unpack_u32(&mode,
	unpack_u64(&ino,
	unpack_u64(&dev, buffer
	)))))))))))));

	result->st_dev		= dev;
	result->st_ino		= ino;
	result->st_mode		= mode;
	result->st_nlink	= nlink;
	result->st_uid		= uid;
	result->st_gid		= gid;
	result->st_rdev		= rdev;
	result->st_size		= size;
	result->st_blksize	= blksize;
	result->st_blocks	= blocks;
	result->st_atime	= atime;
	result->st_mtime	= mtime;
	result->st_ctime	= ctime;

	return buffer + STAT_BLOCK_SIZE;
}

/*---------------------------------------------------------------------------*/
/* pack_open_command				                             */
/*---------------------------------------------------------------------------*/
void pack_open_command(const char *pathname, int flags, void *buf, size_t *len)
{
	unsigned int	path_len = strlen(pathname) + 1;
	char		*buffer = buf;
	unsigned int	overall_size = sizeof(flags) + path_len;
	struct raio_command cmd = { RAIO_CMD_OPEN, overall_size };

	pack_mem(pathname, path_len,
	pack_u32((uint32_t *)&flags,
	pack_u32(&cmd.data_len,
	pack_u32(&cmd.command,
		 buffer))));

	*len = sizeof(cmd) + overall_size;
}

/*---------------------------------------------------------------------------*/
/* pack_close_command				                             */
/*---------------------------------------------------------------------------*/
void pack_close_command(int fd, void *buf, size_t *len)
{
	char		*buffer = buf;
	unsigned int	overall_size = sizeof(fd);
	struct raio_command cmd = { RAIO_CMD_CLOSE, overall_size };

	pack_u32((uint32_t *)&fd,
	pack_u32(&cmd.data_len,
	pack_u32(&cmd.command,
		 buffer)));

	*len = sizeof(cmd) + overall_size;
}

/*---------------------------------------------------------------------------*/
/* pack_fstat_command				                             */
/*---------------------------------------------------------------------------*/
void pack_fstat_command(int fd, void *buf, size_t *len)
{
	char		*buffer = buf;
	unsigned int	overall_size = sizeof(fd);
	struct raio_command cmd = { RAIO_CMD_FSTAT, overall_size };

	pack_u32((uint32_t *)&fd,
	pack_u32(&cmd.data_len,
	pack_u32(&cmd.command,
		 buffer)));

	*len = sizeof(cmd) + overall_size;
}

/*---------------------------------------------------------------------------*/
/* pack_destroy_command				                             */
/*---------------------------------------------------------------------------*/
void pack_destroy_command(void *buf, size_t *len)
{
	char		*buffer = buf;
	unsigned int	overall_size = 0;
	struct raio_command cmd = { RAIO_CMD_IO_DESTROY, overall_size };

	pack_u32(&cmd.data_len,
	pack_u32(&cmd.command,
		 buffer));

	*len = sizeof(cmd) + overall_size;
}

/*---------------------------------------------------------------------------*/
/* unpack_open_answer				                             */
/*---------------------------------------------------------------------------*/
int unpack_open_answer(char *buf, size_t len, int *fd)
{
	struct raio_answer ans;

	const char *buffer = unpack_u32((uint32_t *)&ans.ret_errno,
			  unpack_u32((uint32_t *)&ans.ret,
			  unpack_u32(&ans.data_len,
			  unpack_u32(&ans.command,
			  buf))));
	if ((ans.command != RAIO_CMD_OPEN) ||
	    ((ans.ret_errno == 0) && (sizeof(*fd) != ans.data_len))) {
		return -EINVAL;
	}
	if (ans.ret_errno) {
		return -ans.ret_errno;
	}
	unpack_u32((uint32_t *)fd, buffer);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* unpac_close_answer				                             */
/*---------------------------------------------------------------------------*/
int unpack_close_answer(char *buf, size_t len)
{
	struct raio_answer ans;

	unpack_u32((uint32_t *)&ans.ret_errno,
		  unpack_u32((uint32_t *)&ans.ret,
		  unpack_u32(&ans.data_len,
		  unpack_u32(&ans.command,
		  buf))));
	if ((ans.command != RAIO_CMD_CLOSE) ||
	    (0 != ans.data_len)) {
		return -EINVAL;
	}
	if (ans.ret_errno) {
		return -ans.ret_errno;
	}

	return 0;
}

/*---------------------------------------------------------------------------*/
/* unpack_fstat_answer				                             */
/*---------------------------------------------------------------------------*/
int unpack_fstat_answer(char *buf, size_t len, struct r_stat64 *stbuf)
{
	struct raio_answer ans;
	const char *buffer;

	buffer = unpack_u32((uint32_t *)&ans.ret_errno,
		 unpack_u32((uint32_t *)&ans.ret,
		 unpack_u32(&ans.data_len,
		 unpack_u32(&ans.command,
		 buf))));
	if ((ans.command != RAIO_CMD_FSTAT) ||
	    (STAT_BLOCK_SIZE != ans.data_len)) {
		return -EINVAL;
	}
	if (ans.ret_errno) {
		return -ans.ret_errno;
	}

	buffer = unpack_stat64(stbuf, buffer);

	return 0;
}

/*---------------------------------------------------------------------------*/
/* upack_setup_answer				                             */
/*---------------------------------------------------------------------------*/
int unpack_setup_answer(char *buf, size_t len)
{
	struct raio_answer ans;

	unpack_u32((uint32_t *)&ans.ret_errno,
	unpack_u32((uint32_t *)&ans.ret,
	unpack_u32(&ans.data_len,
	unpack_u32(&ans.command,
		   buf))));

	if ((ans.command != RAIO_CMD_IO_SETUP) ||
	    (0 != ans.data_len)) {
		return -EINVAL;
	}
	if (ans.ret_errno) {
		return -ans.ret_errno;
	}

	return 0;
}


/*---------------------------------------------------------------------------*/
/* pack_iocb								     */
/*---------------------------------------------------------------------------*/
char *pack_iocb(struct raio_iocb *iocb, char *buffer)
{
	pack_u64((uint64_t *)&iocb->u.c.offset,
	pack_u64((uint64_t *)&iocb->u.c.nbytes,
	pack_u32((uint32_t *)&iocb->raio_lio_opcode,
	pack_u32((uint32_t *)&iocb->raio_fildes,
		   buffer))));

	return buffer + SUBMIT_BLOCK_SIZE;
}

void pack_submit_command(struct raio_iocb *iocb, int is_last_in_batch,
			 void *buf, size_t *len)
{
	char	*buffer = buf;
	unsigned overall_size = SUBMIT_BLOCK_SIZE + sizeof(uint32_t);

	struct raio_command cmd = { RAIO_CMD_IO_SUBMIT, overall_size };

	pack_iocb(iocb,
	pack_u32((uint32_t *)&is_last_in_batch,
	pack_u32(&cmd.data_len,
	pack_u32(&cmd.command,
		 buffer))));

	*len = sizeof(cmd) + overall_size;
}

/*---------------------------------------------------------------------------*/
/* pack_setup_command				                             */
/*---------------------------------------------------------------------------*/
void pack_setup_command(int maxevents, void *buf, size_t *len)
{
	char		*buffer = buf;
	unsigned int	overall_size = sizeof(maxevents);
	struct raio_command cmd = { RAIO_CMD_IO_SETUP, overall_size };

	pack_u32((uint32_t *)&maxevents,
	pack_u32(&cmd.data_len,
	pack_u32(&cmd.command,
		 buffer)));

	*len = sizeof(cmd) + overall_size;
}

/*---------------------------------------------------------------------------*/
/* upack_destroy_answer				                             */
/*---------------------------------------------------------------------------*/
int unpack_destroy_answer(char *buf, size_t len)
{
	struct raio_answer ans;

	unpack_u32((uint32_t *)&ans.ret_errno,
	unpack_u32((uint32_t *)&ans.ret,
	unpack_u32(&ans.data_len,
	unpack_u32(&ans.command,
		   buf))));

	if ((ans.command != RAIO_CMD_IO_DESTROY) ||
	    (0 != ans.data_len)) {
		return -EINVAL;
	}
	if (ans.ret_errno) {
		return -ans.ret_errno;;
	}

	return 0;
}
