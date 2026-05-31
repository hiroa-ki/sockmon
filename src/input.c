#include "input.h"
#include "util.h"
#include "draw.h"
#include <arpa/inet.h>

static void main_ip_handler(struct nm_ctx *n)
{
	if (n->family != AF_INET)
		n->family = AF_INET;
}

static void main_ip6_handler(struct nm_ctx *n)
{
	if (n->family != AF_INET6)
		n->family = AF_INET6;
}

static void main_delay_handler(struct nm_ctx *n)
{
	int ch, delay;
	bool seen_nl;
	WINDOW *win;

	win = n->win[WINDOW_INTERACTIVE];

	curs_set(1);
	noraw();
	echo();

	nm_mvwprintw(win, n->cols, 0, 0,
		     "Enter delay (current: %d, 0.1s units): ", n->delay);
	wrefresh(win);

	delay = 0;
	seen_nl = false;
	do {
		ch = wgetch(win);
		if ('0' <= ch && ch <= '9') {
			delay = (delay * 10) + (ch - '0');
		} else if (ch == '\r' || ch == '\n') {
			seen_nl = true;
			break;
		} else {
			goto out;
		}
	} while (1);

	if (1 <= delay && delay <= 255) {
		if (n->delay != delay)
			n->delay = delay;
	} else {
out:
		werase(win);
		nm_mvwprintw(win, n->cols, 0, 0, "Enter a value from 1 to 255");
		wrefresh(win);
		napms(3000);	/* Show the message for 3 seconds. */
	}

	while (!seen_nl) {
		ch = wgetch(win);
		if (ch == '\r' || ch == '\n')
			seen_nl = true;
	}

	werase(win);

	noecho();
	raw();
	halfdelay(n->delay);
	curs_set(0);
}

static void main_field_handler(struct nm_ctx *n)
{
	draw_field_header(n);
}

static void main_help_handler(struct nm_ctx *n)
{
	draw_help(n);
}

static void main_quit_handler(struct nm_ctx *n)
{
	n->should_stop = true;
}

static void main_tcp_handler(struct nm_ctx *n)
{
	if (n->protocol != IPPROTO_TCP)
		n->protocol = IPPROTO_TCP;
}

static void main_udp_handler(struct nm_ctx *n)
{
	if (n->protocol != IPPROTO_UDP)
		n->protocol = IPPROTO_UDP;
}

static void main_key_down_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_MAIN];

	++pos->y;
}

static void main_key_up_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_MAIN];

	if (pos->y <= 0)
		return;

	--pos->y;
}

static void main_key_left_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_MAIN];

	if (pos->x <= 0)
		return;

	--pos->x;
}

static void main_key_right_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_MAIN];

	++pos->x;
}

static void main_key_pgdn_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_MAIN];

	pos->y += (n->lines - 4) / 2;
}

static void main_key_pgup_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_MAIN];

	if (pos->y <= 0)
		return;

	pos->y -= (n->lines - 4) / 2;
	if (pos->y < 0)
		pos->y = 0;
}

static void common_quit_handler(struct nm_ctx *n)
{
	werase(n->win[WINDOW_MAIN]);
	n->cur_screen = SCREEN_MAIN;
}

static void field_space_handler(struct nm_ctx *n)
{
	const struct position *pos;
	struct field *f;

	pos = &n->pos[SCREEN_FIELD];
	f = &tcp_fields[pos->y];

	if (!f->draw_row)
		return;

	f->enabled = !f->enabled;
	draw_field_header(n);
}

static void field_pin_handler(struct nm_ctx *n)
{
	const struct position *pos;
	struct field *f;

	pos = &n->pos[SCREEN_FIELD];
	f = &tcp_fields[pos->y];

	if (!f->draw_row)
		return;

	f->pinned = !f->pinned;
	draw_field_header(n);
}

static void ext_set(unsigned char *ext, int flag)
{
	/* idiag_ext has only 8 bits. */
	if (flag <= 8)
		*ext |= 1 << (flag - 1);
}

static void field_quit_handler(struct nm_ctx *n)
{
	unsigned char ext_req;
	int i;

	ext_req = 0;

	for (i = 0; i < nr_tcp_fields; ++i) {
		const struct field *f;

		f = &tcp_fields[i];

		if (f->enabled && f->ext_req)
			ext_set(&ext_req, f->ext_req);
	}

	if (n->ext_req != ext_req)
		n->ext_req = ext_req;
	if (n->sel_field)
		n->sel_field = NULL;

	common_quit_handler(n);
}

static void field_key_down_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_FIELD];

	if (pos->y >= nr_tcp_fields - 1)
		return;

	++pos->y;
	draw_field_header(n);
}

static void field_key_up_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_FIELD];

	if (pos->y <= 0)
		return;

	--pos->y;
	draw_field_header(n);
}

static void swap_field(struct field *a, struct field *b)
{
	struct field tmp;

	tmp = *a;
	*a = *b;
	*b = tmp;
}

static void field_key_left_handler(struct nm_ctx *n)
{
	const struct position *pos;
	struct field *f;

	if (!n->sel_field)
		return;

	pos = &n->pos[SCREEN_FIELD];
	f = &tcp_fields[pos->y];

	if (!f->draw_row)
		return;

	if (n->sel_field == f)
		return;

	f = &tcp_fields[n->sel_field - &tcp_fields[0]];
	if (n->sel_field < &tcp_fields[pos->y]) {
		do {
			swap_field(f, f + 1);
		} while (++f < &tcp_fields[pos->y]);
	} else if (n->sel_field > &tcp_fields[pos->y]) {
		do {
			swap_field(f, f - 1);
		} while (--f > &tcp_fields[pos->y]);
	}

	n->sel_field = NULL;
}

static void field_key_right_handler(struct nm_ctx *n)
{
	const struct position *pos;
	struct field *f;

	if (n->sel_field)
		return;

	pos = &n->pos[SCREEN_FIELD];
	f = &tcp_fields[pos->y];

	if (!f->draw_row)
		return;

	n->sel_field = f;
}

static void field_pgdn_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_FIELD];

	if (pos->y >= nr_tcp_fields - 1)
		return;

	pos->y += (n->lines - 4) / 2;
	if (pos->y > nr_tcp_fields - 1)
		pos->y = nr_tcp_fields - 1;
	draw_field_header(n);
}

static void field_pgup_handler(struct nm_ctx *n)
{
	struct position *pos;

	pos = &n->pos[SCREEN_FIELD];

	if (pos->y <= 0)
		return;

	pos->y -= (n->lines - 4) / 2;
	if (pos->y < 0)
		pos->y = 0;
	draw_field_header(n);
}

static void help_quit_handler(struct nm_ctx *n)
{
	common_quit_handler(n);
}

struct key_handler {
	int	key_code;
	void	(*handler)(struct nm_ctx *);
};

#define DEFINE_KEY_HANDLER(key_code, handler)	\
	{key_code, handler}

#define KEY_ESC	'\033'
#define CTRL(x)	((x) & 0x1f)

static const struct key_handler main_key_handler[] = {
	DEFINE_KEY_HANDLER(CTRL('C'), main_quit_handler),
	DEFINE_KEY_HANDLER('4', main_ip_handler),
	DEFINE_KEY_HANDLER('6', main_ip6_handler),
	DEFINE_KEY_HANDLER('d', main_delay_handler),
	DEFINE_KEY_HANDLER('f', main_field_handler),
	DEFINE_KEY_HANDLER('h', main_help_handler),
	DEFINE_KEY_HANDLER('q', main_quit_handler),
	DEFINE_KEY_HANDLER('t', main_tcp_handler),
	DEFINE_KEY_HANDLER('u', main_udp_handler),
	DEFINE_KEY_HANDLER(KEY_DOWN, main_key_down_handler),
	DEFINE_KEY_HANDLER(KEY_UP, main_key_up_handler),
	DEFINE_KEY_HANDLER(KEY_LEFT, main_key_left_handler),
	DEFINE_KEY_HANDLER(KEY_RIGHT, main_key_right_handler),
	DEFINE_KEY_HANDLER(KEY_NPAGE, main_key_pgdn_handler),
	DEFINE_KEY_HANDLER(KEY_PPAGE, main_key_pgup_handler)
};

static const struct key_handler field_key_handler[] = {
	DEFINE_KEY_HANDLER(KEY_ESC, field_quit_handler),
	DEFINE_KEY_HANDLER(' ', field_space_handler),
	DEFINE_KEY_HANDLER('p', field_pin_handler),
	DEFINE_KEY_HANDLER('q', field_quit_handler),
	DEFINE_KEY_HANDLER(KEY_DOWN, field_key_down_handler),
	DEFINE_KEY_HANDLER(KEY_UP, field_key_up_handler),
	DEFINE_KEY_HANDLER(KEY_LEFT, field_key_left_handler),
	DEFINE_KEY_HANDLER(KEY_RIGHT, field_key_right_handler),
	DEFINE_KEY_HANDLER(KEY_NPAGE, field_pgdn_handler),
	DEFINE_KEY_HANDLER(KEY_PPAGE, field_pgup_handler)
};

static const struct key_handler help_key_handler[] = {
	DEFINE_KEY_HANDLER(KEY_ESC, help_quit_handler),
	DEFINE_KEY_HANDLER('q', help_quit_handler)
};

struct key_handlers {
	int				nr_keys;
	const struct key_handler	*key_handlers;
};

static const struct key_handlers key_handlers[] = {
#define DEFINE_KEY_HANDLERS(screen, key_handler)	\
	[screen]	= {ARRAY_SIZE(key_handler), key_handler}
	DEFINE_KEY_HANDLERS(SCREEN_MAIN, main_key_handler),
	DEFINE_KEY_HANDLERS(SCREEN_FIELD, field_key_handler),
	DEFINE_KEY_HANDLERS(SCREEN_HELP, help_key_handler)
};

bool should_stop(struct nm_ctx *n)
{
	WINDOW *win;
	int ch;

	win = n->win[WINDOW_MAIN];

	/* Wait at most n->delay tenths of a second for input. If no input 
	 * occurs, ERR is returned.
	 */
	ch = wgetch(win);

	if (ch == ERR) {
		/* Do nothing. */
	} else if (ch == KEY_RESIZE) {
		window_resize(n);
	} else {
		const struct key_handler *kh;
		int i, nr_keys;

		nr_keys = key_handlers[n->cur_screen].nr_keys;
		kh = key_handlers[n->cur_screen].key_handlers;

		for (i = 0; i < nr_keys; ++i) {
			if (ch != kh[i].key_code)
				continue;

			kh[i].handler(n);
			doupdate();
			break;
		}
	}

	return n->should_stop;
}
