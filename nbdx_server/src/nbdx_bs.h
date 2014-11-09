#ifndef NBDX_BS_H
#define NBDX_BS_H

#include <sys/queue.h>
#include <sys/stat.h>
#include <stdint.h>

struct nbdx_io_cmd;
struct nbdx_bs;

/*---------------------------------------------------------------------------*/
/* typedefs								     */
/*---------------------------------------------------------------------------*/
typedef int (*nbdx_completion_cb_t)(struct nbdx_io_cmd *cmd);


/*---------------------------------------------------------------------------*/
/* forward declarations	                                                     */
/*---------------------------------------------------------------------------*/
struct nbdx_io_cmd {
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
	nbdx_completion_cb_t		comp_cb;

	TAILQ_ENTRY(nbdx_io_cmd)	nbdx_list;
};


/*---------------------------------------------------------------------------*/
/* structs								     */
/*---------------------------------------------------------------------------*/
struct backingstore_template {
	const char *bs_name;
	size_t bs_datasize;
	int (*bs_open)(struct nbdx_bs *dev, int fd);
	void (*bs_close)(struct nbdx_bs *dev);
	int (*bs_init)(struct nbdx_bs *dev);
	void (*bs_exit)(struct nbdx_bs *dev);
	int (*bs_cmd_submit)(struct nbdx_bs *dev, struct nbdx_io_cmd *cmd);

	SLIST_ENTRY(backingstore_template)   backingstore_siblings;
};

struct nbdx_bs {
	void				*ctx;
	int				fd;
	int				is_null;
	struct stat64   stbuf;
	struct backingstore_template	*bst;
	void				*dd;
	TAILQ_ENTRY(nbdx_bs)        list;
};

/*---------------------------------------------------------------------------*/
/* nbdx_bs_init								     */
/*---------------------------------------------------------------------------*/
struct nbdx_bs *nbdx_bs_init(void *ctx, const char *name);

/*---------------------------------------------------------------------------*/
/* nbdx_bs_exit								     */
/*---------------------------------------------------------------------------*/
void nbdx_bs_exit(struct nbdx_bs *dev);

/*---------------------------------------------------------------------------*/
/* nbdx_bs_open								     */
/*---------------------------------------------------------------------------*/
int nbdx_bs_open(struct nbdx_bs *dev, int fd);

/*---------------------------------------------------------------------------*/
/* nbdx_bs_close							     */
/*---------------------------------------------------------------------------*/
void  nbdx_bs_close(struct nbdx_bs *dev);

/*---------------------------------------------------------------------------*/
/* nbdx_bs_cmd_submit	                                                     */
/*---------------------------------------------------------------------------*/
int nbdx_bs_cmd_submit(struct nbdx_bs *dev, struct nbdx_io_cmd *cmd);

/*---------------------------------------------------------------------------*/
/* register_backingstore_template					     */
/*---------------------------------------------------------------------------*/
int register_backingstore_template(struct backingstore_template *bst);

/*---------------------------------------------------------------------------*/
/* get_backingstore_template	                                             */
/*---------------------------------------------------------------------------*/
struct backingstore_template *get_backingstore_template(const char *name);

#endif  /* #define NBDX_BS_H */
