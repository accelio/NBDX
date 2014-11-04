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
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "libnbdx.h"
#include "nbdx_bs.h"


/*---------------------------------------------------------------------------*/
/* preprocessor directives                                                   */
/*---------------------------------------------------------------------------*/
#define NULL_BS_DEV_SIZE        (1ULL << 32)

/*---------------------------------------------------------------------------*/
/* nbdx_bs_null_cmd_submit						     */
/*---------------------------------------------------------------------------*/
int nbdx_bs_null_cmd_submit(struct nbdx_bs *dev,
		       struct nbdx_io_cmd *cmd)
{
	cmd->res = cmd->bcount;
	cmd->res2 = 0;
	if (cmd->comp_cb)
		cmd->comp_cb(cmd);
	return 0;
}

/*---------------------------------------------------------------------------*/
/* nbdx_bs_null_open							     */
/*---------------------------------------------------------------------------*/
static int nbdx_bs_null_open(struct nbdx_bs *dev, int fd)
{
	dev->stbuf.st_size = NULL_BS_DEV_SIZE;
	return 0;
}

/*---------------------------------------------------------------------------*/
/* nbdx_bs_null_close							     */
/*---------------------------------------------------------------------------*/
static inline void nbdx_bs_null_close(struct nbdx_bs *dev)
{
}

/*---------------------------------------------------------------------------*/
/* nbdx_null_bst							     */
/*---------------------------------------------------------------------------*/
static struct backingstore_template nbdx_null_bst = {
	.bs_name		= "null",
	.bs_datasize		= 0,
	.bs_open		= nbdx_bs_null_open,
	.bs_close		= nbdx_bs_null_close,
	.bs_cmd_submit		= nbdx_bs_null_cmd_submit,
};

/*---------------------------------------------------------------------------*/
/* nbdx_bs_null_constructor						     */
/*---------------------------------------------------------------------------*/
void nbdx_bs_null_constructor(void)
{
	register_backingstore_template(&nbdx_null_bst);
}

