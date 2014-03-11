#ifndef XNBD_BS_H
#define XNBD_BS_H

#include <sys/queue.h>
#include <stdint.h>

struct xnbd_io_cmd;
struct xnbd_bs;

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
typedef int (*xnbd_completion_cb_t)(struct xnbd_io_cmd *cmd);


/*---------------------------------------------------------------------------*/
/* forward declarations	                                                     */
/*---------------------------------------------------------------------------*/
struct xnbd_io_cmd {
	int				fd;
	int				op;
	void				*buf;
	uint64_t			bcount;
	void				*mr;
	uint64_t			fsize;
	int64_t				offset;
	int				is_last_in_batch;
	int				res;
	int				res2;
	int				pad;
	void				*user_context;
	xnbd_completion_cb_t		comp_cb;

	TAILQ_ENTRY(xnbd_io_cmd)	xnbd_list;
};


/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct backingstore_template {
	const char *bs_name;
	size_t bs_datasize;
	int (*bs_open)(struct xnbd_bs *dev, int fd);
	void (*bs_close)(struct xnbd_bs *dev);
	int (*bs_init)(struct xnbd_bs *dev);
	void (*bs_exit)(struct xnbd_bs *dev);
	int (*bs_cmd_submit)(struct xnbd_bs *dev, struct xnbd_io_cmd *cmd);

	SLIST_ENTRY(backingstore_template)   backingstore_siblings;
};

struct xnbd_bs {
	void				*ctx;
	int				fd;
	int				reserved;
	struct backingstore_template	*bst;
	void				*dd;
};

/*---------------------------------------------------------------------------*/
/* xnbd_bs_init								     */
/*---------------------------------------------------------------------------*/
struct xnbd_bs *xnbd_bs_init(void *ctx, const char *name);

/*---------------------------------------------------------------------------*/
/* xnbd_bs_exit								     */
/*---------------------------------------------------------------------------*/
void xnbd_bs_exit(struct xnbd_bs *dev);

/*---------------------------------------------------------------------------*/
/* xnbd_bs_open								     */
/*---------------------------------------------------------------------------*/
int xnbd_bs_open(struct xnbd_bs *dev, int fd);

/*---------------------------------------------------------------------------*/
/* xnbd_bs_close							     */
/*---------------------------------------------------------------------------*/
void  xnbd_bs_close(struct xnbd_bs *dev);

/*---------------------------------------------------------------------------*/
/* xnbd_bs_cmd_submit	                                                     */
/*---------------------------------------------------------------------------*/
int xnbd_bs_cmd_submit(struct xnbd_bs *dev, struct xnbd_io_cmd *cmd);

/*---------------------------------------------------------------------------*/
/* register_backingstore_template					     */
/*---------------------------------------------------------------------------*/
int register_backingstore_template(struct backingstore_template *bst);

/*---------------------------------------------------------------------------*/
/* get_backingstore_template	                                             */
/*---------------------------------------------------------------------------*/
struct backingstore_template *get_backingstore_template(const char *name);

#endif  /* #define XNBD_BS_H */
