#ifndef	_DRAW_H
#define	_DRAW_H

#include "main.h"
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
	bool		enabled;
	bool		pinned;
#define	INET_DIAG_ADDRESS	(__INET_DIAG_MAX)
	unsigned char	ext_req;
	unsigned char	ext_rcv;
	int		width;
	int		type;
	size_t		offset;
	void		(*draw_row)(WINDOW *, int, int, int,
				    const struct field *, const void *);
};

extern struct field tcp_fields[];
extern const int nr_tcp_fields;
extern void draw_field_header(struct nm_ctx *n);
extern void draw_help(struct nm_ctx *n);

#endif	/* _DRAW_H */
