#ifndef	_DRAW_H
#define	_DRAW_H

#include "bool.h"
#include "main.h"
#include "conn_info.h"
#include <curses.h>
#include <linux/inet_diag.h>

extern int window_init(struct nm_ctx *n);
extern void window_exit(struct nm_ctx *n);
extern void window_erase(struct nm_ctx *n);
extern void window_resize(struct nm_ctx *n);
extern void window_refresh(void);
extern void nm_error(struct nm_ctx *n, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));
extern void nm_perror(struct nm_ctx *n, const char *s, int err);
extern void
nm_mvwprintw(WINDOW *win, int cols, int y, int x, const char *fmt, ...)
	__attribute__((format(printf, 5, 6)));
extern void draw_connections(struct nm_ctx *n);
extern void draw_summary(struct nm_ctx *n);

struct field {
	const char	*header;
	const char	*desc;
	unsigned char	enabled;
	unsigned char	pinned;
#define	INET_DIAG_ADDRESS	(__INET_DIAG_MAX + 0)
#define INET_DIAG_PROC		(__INET_DIAG_MAX + 1)
	unsigned char	ext_req;
	unsigned char	ext_rcv;
	int		width;
	int		type;
	size_t		offset;
	void		(*draw_row)(WINDOW *, int, int, int,
				    const struct field *, const void *);
	int		(*sort_func)(const struct field *, const void *,
				     const void*);
};

static inline void ext_set(unsigned int *ext, int flag)
{
	*ext |= 1 << (flag - 1);
}

static inline int ext_is_set(unsigned int ext, int flag)
{
	return ext & (1 << (flag - 1));
}

extern struct field tcp_fields[];
extern const int nr_tcp_fields;
extern void draw_field_header(struct nm_ctx *n);
extern void draw_help(struct nm_ctx *n);
extern void add_conn_info(struct nm_ctx *n, struct conn_info *ci);

#endif	/* _DRAW_H */
