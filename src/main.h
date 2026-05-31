#ifndef _MAIN_H
#define _MAIN_H

#include "list.h"
#include <stdbool.h>
#include <curses.h>

enum screen_mode {
	SCREEN_MAIN,
	SCREEN_FIELD,
	SCREEN_HELP,
	SCREEN_MAX
};

enum {
	WINDOW_MAIN,
	WINDOW_SUMMARY,
	WINDOW_INTERACTIVE,
	WINDOW_CONN_INFO,
	WINDOW_MAX
};

struct position {
	int	y;
	int	x;
};

struct nm_ctx {
	WINDOW			*win[WINDOW_MAX];
	struct position		pos[SCREEN_MAX];
	struct field		*sel_field;
	enum screen_mode	cur_screen;
	int			lines;
	int			cols;
	int			delay;
	bool			should_stop;
	bool			we_called;
	unsigned char		family;
	unsigned char		protocol;
	unsigned char		ext_req;
	unsigned int		ext_rcv;
	int			nr_conns;
	struct list_head	conn_list;
};

#endif	/* _MAIN_H */
