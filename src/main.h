#ifndef _MAIN_H
#define _MAIN_H

#include "bool.h"
#include "list.h"
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
	WINDOW_FILTER,
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
	struct field		*sort_key;
	enum screen_mode	cur_screen;
	int			lines;
	int			cols;
	int			delay;
	unsigned char		should_stop;
	unsigned char		we_called;
	unsigned char		sort_ascending;
	unsigned char		family;
	unsigned char		protocol;
	unsigned int		ext_req;
	unsigned int		ext_rcv;
	int			sk;
	int			nr_conns;
	struct list_head	conn_list;
};

#endif	/* _MAIN_H */
