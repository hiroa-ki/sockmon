#include "draw.h"
#include "version.h"
#include "util.h"
#include "conn_info.h"
#include "nl.h"
#include <stdio.h>
#include <errno.h>
#include <curses.h>
#include <arpa/inet.h>
#include <time.h>

int window_init(struct nm_ctx *n)
{
	int i, err, lines, cols;
	WINDOW *win;

	err = 1;

	win = initscr();

	/* Disable echoing. */
	noecho();

	/* Disable line buffering. And also control characters (e.g. Ctrl-C)
	 * are passed to the program without generating signals.
	 */
	raw();

	halfdelay(n->delay);

	/* Enable ternimal's function keys (e.g. F1, arrow keys). */
	keypad(stdscr, TRUE);

	/* Make cursor invisible. */
	curs_set(0);

	getmaxyx(win, lines, cols);
	n->lines = lines;
	n->cols = cols;

	n->win[WINDOW_MAIN] = win;
	n->win[WINDOW_SUMMARY] = newwin(1, cols, 0, 0);
	n->win[WINDOW_INTERACTIVE] = newwin(1, cols, 1, 0);
	n->win[WINDOW_CONN_INFO] = newwin(1, cols, 2, 0);

	for (i = 0; i < WINDOW_MAX; ++i) {
		win = n->win[i];
		if (!win)
			goto out;

		leaveok(win, TRUE);
	}

	err = 0;
out:
	return err;
}

void window_exit(struct nm_ctx *n)
{
	int i;

	if (n->we_called)
		return;

	for (i = 0; i < WINDOW_MAX; ++i) {
		WINDOW *w;

		w = n->win[i];
		if (w)
			delwin(w);
	}
	endwin();

	n->we_called = TRUE;
}

void window_erase(struct nm_ctx *n)
{
	WINDOW *win;

	win = n->win[WINDOW_MAIN];

	werase(win);
	wnoutrefresh(win);
}

void window_refresh(void)
{
	doupdate();
}

void window_resize(struct nm_ctx *n)
{
	getmaxyx(n->win[WINDOW_MAIN], n->lines, n->cols);
}

void nm_error(struct nm_ctx *n, const char *fmt, ...)
{
	va_list ap;

	window_exit(n);

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}

void nm_perror(struct nm_ctx *n, const char *s, int err)
{
	window_exit(n);
	errno = err;
	perror(s);
}

void nm_mvwprintw(WINDOW *win, int cols, int y, int x, const char *fmt, ...)
{
	static char buf[4096];
	int cols_left, w;
	va_list ap;

	cols_left = cols - x;
	if (cols_left <= 0)
		return;

	va_start(ap, fmt);
	w = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (w > cols_left)
		w = cols_left;

	mvwprintw(win, y, x, "%.*s", w, buf);
}

static void draw_protocol(struct nm_ctx *n, int y, const struct conn_info *ci)
{
	unsigned char drawn;
	int i, x, skip_x;
	WINDOW *win;

	win = n->win[WINDOW_CONN_INFO];
	x = 0;
	drawn = FALSE;
	skip_x = n->pos[SCREEN_MAIN].x;

	for (i = 0; i < nr_tcp_fields && x < n->cols; ++i) {
		const struct field *f;
		const void *p;
		int width;

		f = &tcp_fields[i];

		if (!f->enabled)
			continue;

		if (!f->draw_row)
			continue;

		if (!(n->ext_rcv & (1U << f->ext_rcv)))
			continue;

		if (skip_x > 0 && !f->pinned) {
			--skip_x;
			continue;
		}

		if (drawn)
			nm_mvwprintw(win, n->cols, y, x++, " ");

		p = (char *)ci + f->offset;
		width = f->width;
		if (f->ext_rcv == INET_DIAG_ADDRESS) {
			int shift;

			shift = (n->family == AF_INET) ? 8 : 0;
			width = (width >> shift) & 0xff;
		}

		if (ci->ext & (1U << f->ext_rcv))
			f->draw_row(win, n->cols, y, x, f, p);
		else
			nm_mvwprintw(win, n->cols, y, x, "%*s", width, "");

		x += width;

		if (!drawn)
			drawn = TRUE;
	}
}

void draw_connections(struct nm_ctx *n)
{
	int i, y, x, skip_y, skip_x;
	struct conn_info *ci, *p;
	struct position *pos;
	unsigned char drawn;
	WINDOW *win;

	win = n->win[WINDOW_CONN_INFO];
	pos = &n->pos[SCREEN_MAIN];
	y = 0;
	x = 0;
	drawn = FALSE;
	skip_x = pos->x;

	if (n->nr_conns > 0) {
		if (pos->y > n->nr_conns - 1)
			pos->y = n->nr_conns - 1;
	} else {
		if (pos->y > 0)
			pos->y = 0;
	}
	skip_y = pos->y;

	wresize(win, n->nr_conns + 1, n->cols);
	wnoutrefresh(win);

	wattron(win, A_REVERSE);
	for (i = 0; i < nr_tcp_fields && x < n->cols; ++i) {
		const struct field *f;
		int width;

		f = &tcp_fields[i];

		if (!f->enabled)
			continue;

		if (!f->draw_row)
			continue;

		if (!(n->ext_rcv & (1U << f->ext_rcv)))
			continue;

		if (skip_x > 0 && !f->pinned) {
			--skip_x;
			continue;
		}

		width = f->width;
		if (f->ext_rcv == INET_DIAG_ADDRESS) {
			int shift;

			shift = (n->family == AF_INET) ? 8 : 0;
			width = (width >> shift) & 0xff;
		}

		if (drawn)
			nm_mvwprintw(win, n->cols, y, x++, " ");

		nm_mvwprintw(win, n->cols, y, x, "%-*s", width, f->header);
		x += width;

		if (!drawn)
			drawn = TRUE;
	}
	wattroff(win, A_REVERSE);
	++y;

	list_for_each_entry_safe(ci, p, &n->conn_list, list) {
		if (skip_y > 0)
			--skip_y;
		else
			draw_protocol(n, y++, ci);

		list_del(&ci->list);
		conn_info_free(ci);
		--n->nr_conns;
	}

	wnoutrefresh(win);
}

void draw_summary(struct nm_ctx *n)
{
	const char *protocol, *family;
	struct tm *tm;
	WINDOW *win;
	time_t t;

	win = n->win[WINDOW_SUMMARY];

	t = time(NULL);
	if (t == (time_t)-1)
		return;

	tm = localtime(&t);

	if (n->family == AF_INET)
		family = "IPv4";
	else if (n->family == AF_INET6)
		family = "IPv6";
	else
		family = "?";

	if (n->protocol == IPPROTO_TCP)
		protocol = "TCP";
	else if (n->protocol == IPPROTO_UDP)
		protocol = "UDP";
	else
		protocol = "?";

	nm_mvwprintw(win, n->cols, 0, 0, "%s - %02d:%02d:%02d | %s/%s: %d",
		     COMMAND_NAME, tm->tm_hour, tm->tm_min, tm->tm_sec,
		     protocol, family, n->nr_conns);
	wnoutrefresh(win);
}

enum {
	TYPE_S8,
	TYPE_U8,
	TYPE_S16,
	TYPE_U16,
	TYPE_S32,
	TYPE_U32,
	TYPE_S64,
	TYPE_U64,
	TYPE_STRING,
	TYPE_BOOL_U8,
	TYPE_BOOL_U16,
	TYPE_BOOL_U32,
	TYPE_BIT_U8,
	TYPE_MAX	= 255,
	TYPE_OTHER	= TYPE_MAX
};

static int field_type(const struct field *f)
{
	return f->type & 0xff;
}

static void dr_common(WINDOW *win, int cols, int y, int x,
		      const struct field *f, const void *p)
{
	union {
		signed char		sc;
		unsigned char		uc;
		signed short		sh;
		unsigned short		uh;
		signed int		sd;
		unsigned int		ud;
		signed long long	sl;
		unsigned long long	ul;
		const char		*str;
	} data;
	const char *fmt, *s;
	int width, nr;

	width = f->width;

	switch (field_type(f)) {
	case TYPE_S8:
		fmt = "%*hhd";
		data.sc = *(signed char *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.sc);
		break;

	case TYPE_U8:
		fmt = "%*hhu";
		data.uc = *(unsigned char *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.uc);
		break;

	case TYPE_S16:
		fmt = "%*hd";
		data.sh = *(signed short *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.sh);
		break;

	case TYPE_U16:
		fmt = "%*hu";
		data.uh = *(unsigned short *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.uh);
		break;

	case TYPE_S32:
		fmt = "%*d";
		data.sd = *(signed int *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.sd);
		break;

	case TYPE_U32:
		fmt = "%*u";
		data.ud = *(unsigned int *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.ud);
		break;

	case TYPE_S64:
		fmt = "%*lld";
		data.sl = *(signed long long *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.sl);
		break;

	case TYPE_U64:
		fmt = "%*llu";
		data.ul = *(unsigned long long *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.ul);
		break;

	case TYPE_STRING:
		fmt = "%*s";
		data.str = (const char *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width, data.str);
		break;

	case TYPE_BOOL_U8:
		fmt = "%*s";
		data.uc = *(unsigned short *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width,
			     (data.uc) ? "true" : "false");
		break;

	case TYPE_BOOL_U16:
		fmt = "%*s";
		data.uh = *(unsigned short *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width,
			     (data.uh) ? "true" : "false");
		break;

	case TYPE_BOOL_U32:
		fmt = "%*s";
		data.ud = *(unsigned int *)p;
		nm_mvwprintw(win, cols, y, x, fmt, width,
			     (data.ud) ? "true" : "false");
		break;

	case TYPE_BIT_U8:
		struct bfield {
			unsigned char	d0:1,d1:1,d2:1,d3:1,d4:1,d5:1,d6:1,d7:1;
		} v;
		unsigned char d;

		fmt = "%*s";
		v = *(struct bfield *)p;

		nr = f->type >> 8;
		if (nr < 0 || nr > 7) {
			s = "?";
		} else {
			switch (nr) {
			case 0: d = v.d0; break;
			case 1: d = v.d1; break;
			case 2: d = v.d2; break;
			case 3: d = v.d3; break;
			case 4: d = v.d4; break;
			case 5: d = v.d5; break;
			case 6: d = v.d6; break;
			case 7: d = v.d7; break;
			}
			s = (d) ? "true" : "false";
		}

		nm_mvwprintw(win, cols, y, x, fmt, width, s);
		break;

	default:
		nm_mvwprintw(win, cols, y, x, "%*s", width, "");
		break;
	}
}

static void dr_addr(WINDOW *win, int cols, int y, int x, int width,
		    unsigned char family, const unsigned int *addr)
{
	char buf[INET6_ADDRSTRLEN];
	int shift;

	if (!inet_ntop(family, addr, buf, sizeof(buf))) {
		buf[0] = '?';
		buf[1] = '\0';
	}

	shift = (family == AF_INET) ? 8 : 0;
	width = (width >> shift) & 0xff;

	nm_mvwprintw(win, cols, y, x, "%*s", width, buf);
}

static void dr_src(WINDOW *win, int cols, int y, int x, const struct field *f,
		   const void *p)
{
	const struct inet_diag_msg *r;

	r = p;

	dr_addr(win, cols, y, x, f->width, r->idiag_family, r->id.idiag_src);
}

static void dr_dst(WINDOW *win, int cols, int y, int x, const struct field *f,
		   const void *p)
{
	const struct inet_diag_msg *r;

	r = p;

	dr_addr(win, cols, y, x, f->width, r->idiag_family, r->id.idiag_dst);
}

static void dr_port(WINDOW *win, int cols, int y, int x, const struct field *f,
		    const void *p)
{
	unsigned short port;

	port = *(unsigned short *)p;

	nm_mvwprintw(win, cols, y, x, "%*hu", f->width, ntohs(port));
}

static void dr_state_common(WINDOW *win, int cols, int y, int x, int width,
			    unsigned char state)
{
	static const char * const state_str[] = {
		"?",
		[TCP_ESTABLISHED]	= "ESTABLISHED",
		[TCP_SYN_SENT]		= "SYN_SENT",
		[TCP_SYN_RECV]		= "SYN_RECV",
		[TCP_FIN_WAIT1]		= "FIN_WAIT1",
		[TCP_FIN_WAIT2]		= "FIN_WAIT2",
		[TCP_TIME_WAIT]		= "TIME_WAIT",
		[TCP_CLOSE]		= "CLOSE",
		[TCP_CLOSE_WAIT]	= "CLOSE_WAIT",
		[TCP_LAST_ACK]		= "LAST_ACK",
		[TCP_LISTEN]		= "LISTEN",
		[TCP_CLOSING]		= "CLOSING"
	};
	const char *s;

	s = (state < ARRAY_SIZE(state_str)) ? state_str[state] : state_str[0];

	nm_mvwprintw(win, cols, y, x, "%*s", width, s);
}

static void dr_state(WINDOW *win, int cols, int y, int x, const struct field *f,
		     const void *p)
{
	unsigned char state;

	state = *(unsigned char *)p;

	dr_state_common(win, cols, y, x, f->width, state);
}

static void dr_timer(WINDOW *win, int cols, int y, int x, const struct field *f,
		     const void *p)
{
	static const char * const timer_str[] = {
		"Off", "On", "Keepalive", "Timewait", "Probe0", "Delack"
	};
	unsigned char timer;
	const char *s;

	timer = *(unsigned char *)p;

	s = (timer < ARRAY_SIZE(timer_str)) ? timer_str[timer] : "?";

	nm_mvwprintw(win, cols, y, x, "%*s", f->width, s);
}

static void dr_shutdown(WINDOW *win, int cols, int y, int x,
			const struct field *f, const void *p)
{
	unsigned char shutdown;
	const char *s;

	shutdown = *(const char *)p & SHUTDOWN_MASK;

	if (shutdown == (SEND_SHUTDOWN | RCV_SHUTDOWN))
		s = "RDWR";
	else if (shutdown == SEND_SHUTDOWN)
		s = "  WR";
	else if (shutdown == RCV_SHUTDOWN)
		s = "RD  ";
	else
		s = "    ";

	nm_mvwprintw(win, cols, y, x, "%*s", f->width, s);
}

static void dr_ca_state(WINDOW *win, int cols, int y, int x,
			const struct field *f, const void *p)
{
	static const char *const ca_state_str[] = {
		"Open", "Disorder", "CWR", "Recover", "Loss"
	};
	unsigned char ca_state;
	const char *s;

	ca_state = *(unsigned char *)p;

	if (ca_state >= ARRAY_SIZE(ca_state_str))
		s = "?";
	else
		s = ca_state_str[ca_state];

	nm_mvwprintw(win, cols, y, x, "%*s", f->width, s);
}

static void dr_options(WINDOW *win, int cols, int y, int x,
		       const struct field *f, const void *p)
{
	unsigned char options;

	options = *(unsigned char *)p;

	nm_mvwprintw(win, cols, y, x, "%s %s %s %s %s %s %s %s",
		     (options & TCPI_OPT_TIMESTAMPS) ? "TS" : "  ",	/* 2 */
		     (options & TCPI_OPT_SACK) ? "SACK" : "    ",	/* 4 */
		     (options & TCPI_OPT_WSCALE) ? "WS" : "  ",		/* 2 */
		     (options & TCPI_OPT_ECN) ? "ECN" : "   ",		/* 3 */
		     (options & TCPI_OPT_ECN_SEEN) ? "ESEEN" : "     ",	/* 5 */
		     (options & TCPI_OPT_SYN_DATA) ? "SYND" : "    ",	/* 4 */
		     (options & TCPI_OPT_USEC_TS) ? "UTS" : "   ",	/* 3 */
		     (options & TCPI_OPT_TFO_CHILD) ? "TFOC": "    ");	/* 4 */
}

static void dr_snd_wscale(WINDOW *win, int cols, int y, int x,
			  const struct field *f, const void *p)
{
	struct bfield {
		unsigned char	snd_wscale:4, dummy:4;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*u", f->width, v.snd_wscale);
}

static void dr_rcv_wscale(WINDOW *win, int cols, int y, int x,
			  const struct field *f, const void *p)
{
	struct bfield {
		unsigned char	dummy:4, rcv_wscale:4;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*u", f->width, v.rcv_wscale);
}

static void dr_delivery_rate_app_limited(WINDOW *win, int cols, int y, int x,
					 const struct field *f, const void *p)
{
	struct bfield {
		unsigned char	delivery_rate_app_limited:1, dummy:2;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*s", f->width,
		     (v.delivery_rate_app_limited) ? "true" : "false");
}

static void dr_fastopen_client_fail(WINDOW *win, int cols, int y, int x,
				    const struct field *f, const void *p)
{
	static const char * const fastopen_client_fail_str[] = {
		"status_unspec",
		"cookie_unavailable",
		"data_not_acked",
		"syn_retransmitted"
	};
	struct bfield {
		unsigned char	dummy:1, fastopen_client_fail:2;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*s", f->width,
		     fastopen_client_fail_str[v.fastopen_client_fail]);
}
static void dr_ecn_mode(WINDOW *win, int cols, int y, int x,
			const struct field *f, const void *p)
{
	static const char * const ecn_mode_str[] = {
		"disabled", "rfc3168", "accenc", "pending"
	};
	struct bfield {
		unsigned int	tcpi_ecn_mode:2, d1:2, d2:4, d3:24;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*s", f->width,
		     ecn_mode_str[v.tcpi_ecn_mode]);
}

static void dr_accecn_opt_seen(WINDOW *win, int cols, int y, int x,
			       const struct field *f, const void *p)
{
	static const char * const accecn_opt_seen_str[] = {
		"not_seen", "empty_seen", "counter_seen", "fail_seen"
	};
	struct bfield {
		unsigned int	d1:2, accecn_opt_seen:2, d2:4, d3:24;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*s", f->width,
		     accecn_opt_seen_str[v.accecn_opt_seen]);
}

static void dr_accecn_fail_mode(WINDOW *win, int cols, int y, int x,
				const struct field *f, const void *p)
{
	struct bfield {
		unsigned int	d1:2, d2:2, tcpi_accecn_fail_mode:4, d3:24;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*x", f->width, v.tcpi_accecn_fail_mode);
}

static void dr_bbr_bw(WINDOW *win, int cols, int y, int x,
		      const struct field *f, const void *p)
{
	const unsigned int *bbr_bw_lo, *bbr_bw_hi;
	unsigned long long bw;

	bbr_bw_lo = p;
	bbr_bw_hi = p + 4;

	bw = ((unsigned long long)*bbr_bw_hi << 32) | *bbr_bw_lo;

	nm_mvwprintw(win, cols, y, x, "%*llu", f->width, bw);
}

static void dr_bind_address_no_port(WINDOW *win, int cols, int y, int x,
				    const struct field *f, const void *p)
{
	struct bfield {
		unsigned char	bind_address_no_port:1, d1:1, d2:1, d3:5;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*s", f->width,
		     (v.bind_address_no_port) ? "true" : "false");
}

static void dr_recverr_rfc4884(WINDOW *win, int cols, int y, int x,
			       const struct field *f, const void *p)
{
	struct bfield {
		unsigned char	d1:1, recverr_rfc4884:1, d2:1, d3:5;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*s", f->width,
		     (v.recverr_rfc4884) ? "true" : "false");
}

static void dr_defer_connect(WINDOW *win, int cols, int y, int x,
			     const struct field *f, const void *p)
{
	struct bfield {
		unsigned char	d1:1, d2:1, defer_connect:1, d3:5;
	} v;

	v = *(struct bfield *)p;

	nm_mvwprintw(win, cols, y, x, "%*s", f->width,
		     (v.defer_connect) ? "true" : "false");
}

static int sort_common(const struct field *f, const void *p1, const void *p2)
{
	union {
		unsigned char		uc;
		unsigned short		uh;
		unsigned int		ud;
		unsigned long long	ul;
	} d1, d2;
	int ret;

	switch (field_type(f)) {
	case TYPE_U8:
	case TYPE_BOOL_U8:
		d1.uc = *(unsigned char *)p1;
		d2.uc = *(unsigned char *)p2;
		ret = (d1.uc < d2.uc) ? -1 : (d1.uc > d2.uc);
		break;

	case TYPE_U16:
	case TYPE_BOOL_U16:
		d1.uh = *(unsigned short *)p1;
		d2.uh = *(unsigned short *)p2;
		ret = (d1.uh < d2.uh) ? -1 : (d1.uh > d2.uh);
		break;

	case TYPE_U32:
	case TYPE_BOOL_U32:
		d1.ud = *(unsigned int *)p1;
		d2.ud = *(unsigned int *)p2;
		ret = (d1.ud < d2.ud) ? -1 : (d1.ud > d2.ud);
		break;

	case TYPE_U64:
		d1.ul = *(unsigned long long *)p1;
		d2.ul = *(unsigned long long *)p2;
		ret = (d1.ul < d2.ul) ? -1 : (d1.ul > d2.ul);
		break;

	case TYPE_STRING: {
		const char *cp1, *cp2;
		char c1, c2;

		cp1 = p1, cp2 = p2;

		c1 = *cp1, c2 = *cp2;

		while (c1 != '\0' && c2 != '\0' && c1 == c2)
			c1 = *++cp1, c2 = *++cp2;

		ret = (c1 < c2) ? -1 : (c1 > c2);
		}
		break;

	case TYPE_BIT_U8: {
		struct bfield {
			unsigned char   d0:1,d1:1,d2:1,d3:1,d4:1,d5:1,d6:1,d7:1;
		} d1, d2;
		int v1, v2, nr;

		d1 = *(struct bfield *)p1;
		d2 = *(struct bfield *)p2;

		v1 = v2 = 0;

		nr = f->type >> 8;
		switch (nr) {
		case 0: v1 = d1.d0, v2 = d2.d0; break;
		case 1: v1 = d1.d1, v2 = d2.d1; break;
		case 2: v1 = d1.d2, v2 = d2.d2; break;
		case 3: v1 = d1.d3, v2 = d2.d3; break;
		case 4: v1 = d1.d4, v2 = d2.d4; break;
		case 5: v1 = d1.d5, v2 = d2.d5; break;
		case 6: v1 = d1.d6, v2 = d2.d6; break;
		case 7: v1 = d1.d7, v2 = d2.d7; break;
		}
		ret = (v1 < v2) ? -1 : (v1 > v2);
		break;
	}

	default:
		ret = 0;
		break;
	}
	
	return ret;
}

static int sort_address(unsigned char family, const unsigned int *a1,
			const unsigned int *a2)
{
	unsigned int d1, d2;
	int i, ret;

	d1 = ntohl(*a1);
	d2 = ntohl(*a2);

	ret = (d1 < d2) ? -1 : (d1 > d2);

	if (family == AF_INET || ret)
		goto out;

	/* AF_INET6 */
	for (i = 1; i < 4; ++i) {
		d1 = ntohl(*++a1);
		d2 = ntohl(*++a2);

		ret = (d1 < d2) ? -1 : (d1 > d2);
		if (ret)
			break;
	}
out:
	return ret;
}

static int sort_src(const struct field *f, const void *p1, const void *p2)
{
	const struct inet_diag_msg *r1, *r2;

	r1 = p1;
	r2 = p2;

	return sort_address(r1->idiag_family, r1->id.idiag_src,
			    r2->id.idiag_src);
}

static int sort_dst(const struct field *f, const void *p1, const void *p2)
{
	const struct inet_diag_msg *r1, *r2;

	r1 = p1;
	r2 = p2;

	return sort_address(r1->idiag_family, r1->id.idiag_dst,
			    r2->id.idiag_dst);
}

static int sort_port(const struct field *f, const void *p1, const void *p2)
{
	unsigned short port1, port2;

	port1 = ntohs(*(unsigned short *)p1);
	port2 = ntohs(*(unsigned short *)p2);

	return (port1 < port2) ? -1 : (port1 > port2);
}

static int
sort_snd_wscale(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned char	snd_wscale:4, dummy:4;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.snd_wscale < v2.snd_wscale) ? -1 :
	       (v1.snd_wscale > v2.snd_wscale);
}

static int
sort_rcv_wscale(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned char	dummy:4, rcv_wscale:4;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.rcv_wscale < v2.rcv_wscale) ? -1 :
	       (v1.rcv_wscale > v2.rcv_wscale);
}

static int sort_delivery_rate_app_limited(const struct field *f, const void *p1,
					  const void *p2)
{
	struct bfield {
		unsigned char	delivery_rate_app_limited:1, dummy:2;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.delivery_rate_app_limited < v2.delivery_rate_app_limited) ?
		-1 :
	       (v1.delivery_rate_app_limited > v2.delivery_rate_app_limited);
}

static int
sort_fastopen_client_fail(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned char	dummy:1, fastopen_client_fail:2;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.fastopen_client_fail < v2.fastopen_client_fail) ? -1 :
	       (v1.fastopen_client_fail > v2.fastopen_client_fail);
}

static int sort_ecn_mode(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned int	ecn_mode:2, d1:2, d2:4, d3:24;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.ecn_mode < v2.ecn_mode) ? -1 : (v1.ecn_mode > v2.ecn_mode);
}

static int
sort_accecn_opt_seen(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned int	d1:2, accecn_opt_seen:2, d2:4, d3:24;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.accecn_opt_seen < v2.accecn_opt_seen) ? -1 :
	       (v1.accecn_opt_seen > v2.accecn_opt_seen);
}

static int
sort_accecn_fail_mode(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned int	d1:2, d2:2, accecn_fail_mode:4, d3:24;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.accecn_fail_mode < v2.accecn_fail_mode) ? -1 :
	       (v1.accecn_fail_mode > v2.accecn_fail_mode);
}

static int sort_bbr_bw(const struct field *f, const void *p1, const void *p2)
{
	const unsigned int *bw_lo, *bw_hi;
	unsigned long long bw1, bw2;

	bw_lo = p1;
	bw_hi = p1 + 4;
	bw1 = ((unsigned long long)*bw_hi << 32) | *bw_lo;

	bw_lo = p2;
	bw_hi = p2 + 4;
	bw2 = ((unsigned long long)*bw_hi << 32) | *bw_lo;

	return (bw1 < bw2) ? -1 : (bw1 > bw2);
}

static int
sort_bind_address_no_port(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned int	bind_address_no_port:1, d1:1, d2:1, d3:5;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.bind_address_no_port < v2.bind_address_no_port) ? -1 :
	       (v1.bind_address_no_port > v2.bind_address_no_port);
}

static int
sort_recverr_rfc4884(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned int	d1:1, recverr_rfc4884:1, d2:1, d3:5;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.recverr_rfc4884 < v2.recverr_rfc4884) ? -1 :
	       (v1.recverr_rfc4884 > v2.recverr_rfc4884);
}

static int
sort_defer_connect(const struct field *f, const void *p1, const void *p2)
{
	struct bfield {
		unsigned int	d1:1, d2:1, defer_connect:1, d3:5;
	} v1, v2;

	v1 = *(struct bfield *)p1;
	v2 = *(struct bfield *)p2;

	return (v1.defer_connect < v2.defer_connect) ? -1 :
	       (v1.defer_connect > v2.defer_connect);
}

struct field tcp_fields[] = {
#define DEFINE_FIELD(header, desc, enabled, ext, width, type, offset, draw_row, sort_func)	\
	{header, desc, enabled, FALSE, ext, ext, width, type, offset, draw_row, sort_func}
	DEFINE_FIELD("inet_diag:",
		     "",
		     FALSE, INET_DIAG_NONE, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
#define DEFINE_FIELD2(header, desc, enabled, ext_req, ext_rcv, width, type, offset, draw_row, sort_func)	\
	{header, desc, enabled, FALSE, ext_req, ext_rcv, width, type, offset, draw_row, sort_func}
	DEFINE_FIELD2("src",
		      "Local IP address",
		      TRUE, INET_DIAG_NONE, INET_DIAG_ADDRESS, 15 << 8 | 45,
		      TYPE_OTHER, offsetof(struct conn_info, r),
		      dr_src, sort_src),
	DEFINE_FIELD("sport",
		     "Local Port",
		     TRUE, INET_DIAG_NONE, 5, TYPE_U16,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, id) +
		     offsetof(struct inet_diag_sockid, idiag_sport),
		     dr_port, sort_port),
	DEFINE_FIELD2("dst",
		      "Remote IP address",
		      TRUE, INET_DIAG_NONE, INET_DIAG_ADDRESS, 15 << 8 | 45,
		      TYPE_OTHER, offsetof(struct conn_info, r),
		      dr_dst, sort_dst),
	DEFINE_FIELD("dport",
		     "Remote Port",
		     TRUE, INET_DIAG_NONE, 5, TYPE_U16,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, id) +
		     offsetof(struct inet_diag_sockid, idiag_dport),
		     dr_port, sort_port),
	DEFINE_FIELD("state",
		     "Connection state",
		     TRUE, INET_DIAG_NONE, 11, TYPE_U8,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, idiag_state),
		     dr_state, sort_common),
	DEFINE_FIELD("rqueue",
		     "",
		     TRUE, INET_DIAG_NONE, 6, TYPE_U32,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, idiag_rqueue),
		     dr_common, sort_common),
	DEFINE_FIELD("wqueue",
		     "",
		     TRUE, INET_DIAG_NONE, 6, TYPE_U32,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, idiag_wqueue),
		     dr_common, sort_common),
	DEFINE_FIELD("timer",
		     "",
		     FALSE, INET_DIAG_NONE, 9, TYPE_U8,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, idiag_timer),
		     dr_timer, sort_common),
	DEFINE_FIELD("retrans",
		     "",
		     FALSE, INET_DIAG_NONE, 7, TYPE_U8,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, idiag_retrans),
		     dr_common, sort_common),
	DEFINE_FIELD("if",
		     "",
		     FALSE, INET_DIAG_NONE, 2, TYPE_U32,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, id.idiag_if),
		     dr_common, sort_common),
	DEFINE_FIELD("expires",
		     "",
		     FALSE, INET_DIAG_NONE, 7, TYPE_U32,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, idiag_expires),
		     dr_common, sort_common),
	DEFINE_FIELD("uid",
		     "",
		     FALSE, INET_DIAG_NONE, 6, TYPE_U32,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, idiag_uid),
		     dr_common, sort_common),
	DEFINE_FIELD("inode",
		     "",
		     FALSE, INET_DIAG_NONE, 7, TYPE_U32,
		     offsetof(struct conn_info, r) +
		     offsetof(struct inet_diag_msg, idiag_inode),
		     dr_common, sort_common),
	DEFINE_FIELD("tos",
		     "",
		     FALSE, INET_DIAG_TOS, 3, TYPE_U8,
		     offsetof(struct conn_info, tos),
		     dr_common, sort_common),
	DEFINE_FIELD("tclass",
		     "",
		     FALSE, INET_DIAG_TCLASS, 6, TYPE_U8,
		     offsetof(struct conn_info, tclass),
		     dr_common, sort_common),
	DEFINE_FIELD("shutdown",
		     "",
		     FALSE, INET_DIAG_SHUTDOWN, 8, TYPE_U8,
		     offsetof(struct conn_info, shutdown),
		     dr_shutdown, sort_common),
	DEFINE_FIELD("ipv6only",
		     "",
		     FALSE, INET_DIAG_SKV6ONLY, 8, TYPE_BOOL_U8,
		     offsetof(struct conn_info, ipv6only),
		     dr_common, sort_common),
	DEFINE_FIELD("classid",
		     "",
		     FALSE, INET_DIAG_CLASS_ID, 7, TYPE_U32,
		     offsetof(struct conn_info, classid),
		     dr_common, sort_common),
	DEFINE_FIELD("cgroup_id",
		     "",
		     FALSE, INET_DIAG_CGROUP_ID, 9, TYPE_U64,
		     offsetof(struct conn_info, cgroup_id),
		     dr_common, sort_common),
	DEFINE_FIELD("meminfo:",
		     "",
		     FALSE, INET_DIAG_MEMINFO, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
	DEFINE_FIELD("rmem",
		     "",
		     FALSE, INET_DIAG_MEMINFO, 6, TYPE_U32,
		     offsetof(struct conn_info, minfo) +
		     offsetof(struct inet_diag_meminfo, idiag_rmem),
		     dr_common, sort_common),
	DEFINE_FIELD("wmem",
		     "",
		     FALSE, INET_DIAG_MEMINFO, 6, TYPE_U32,
		     offsetof(struct conn_info, minfo) +
		     offsetof(struct inet_diag_meminfo, idiag_wmem),
		     dr_common, sort_common),
	DEFINE_FIELD("fmem",
		     "",
		     FALSE, INET_DIAG_MEMINFO, 6, TYPE_U32,
		     offsetof(struct conn_info, minfo) +
		     offsetof(struct inet_diag_meminfo, idiag_fmem),
		     dr_common, sort_common),
	DEFINE_FIELD("tmem",
		     "",
		     FALSE, INET_DIAG_MEMINFO, 6, TYPE_U32,
		     offsetof(struct conn_info, minfo) +
		     offsetof(struct inet_diag_meminfo, idiag_tmem),
		     dr_common, sort_common),
	DEFINE_FIELD("tcp_info:",
		     "",
		     FALSE, INET_DIAG_INFO, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
	DEFINE_FIELD("state",
		     "",
		     FALSE, INET_DIAG_INFO, 11, TYPE_U8,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_state),
		     dr_state, sort_common),
	DEFINE_FIELD("ca_state",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U8,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_ca_state),
		     dr_ca_state, sort_common),
	DEFINE_FIELD("retransmits",
		     "",
		     FALSE, INET_DIAG_INFO, 11, TYPE_U8,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_retransmits),
		     dr_common, sort_common),
	DEFINE_FIELD("probes",
		     "",
		     FALSE, INET_DIAG_INFO, 6, TYPE_U8,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_probes),
		     dr_common, sort_common),
	DEFINE_FIELD("backoff",
		     "",
		     FALSE, INET_DIAG_INFO, 7, TYPE_U8,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_backoff),
		     dr_common, sort_common),
	DEFINE_FIELD("options",
		     "",
		     FALSE, INET_DIAG_INFO, 34, TYPE_U8,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_options),
		     dr_options, sort_common),
	DEFINE_FIELD("snd_wscale",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_OTHER,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_options) +
		     sizeof(unsigned char),
		     dr_snd_wscale, sort_snd_wscale),
	DEFINE_FIELD("rcv_wscale",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_OTHER,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_options) +
		     sizeof(unsigned char),
		     dr_rcv_wscale, sort_rcv_wscale),
	DEFINE_FIELD("delivery_rate_app_limited",
		     "",
		     FALSE, INET_DIAG_INFO, 25, TYPE_OTHER,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_options) +
		     sizeof(unsigned char) + sizeof(unsigned char),
		     dr_delivery_rate_app_limited,
		     sort_delivery_rate_app_limited),
	DEFINE_FIELD("fastopen_client_fail",
		     "",
		     FALSE, INET_DIAG_INFO, 20, TYPE_OTHER,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_options) +
		     sizeof(unsigned char) + sizeof(unsigned char),
		     dr_fastopen_client_fail, sort_fastopen_client_fail),
	DEFINE_FIELD("rto",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rto),
		     dr_common, sort_common),
	DEFINE_FIELD("ato",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_ato),
		     dr_common, sort_common),
	DEFINE_FIELD("snd_mss",
		     "",
		     FALSE, INET_DIAG_INFO, 7, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_snd_mss),
		     dr_common, sort_common),
	DEFINE_FIELD("rcv_mss",
		     "",
		     FALSE, INET_DIAG_INFO, 7, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rcv_mss),
		     dr_common, sort_common),
	DEFINE_FIELD("unacked",
		     "",
		     FALSE, INET_DIAG_INFO, 7, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_unacked),
		     dr_common, sort_common),
	DEFINE_FIELD("sacked",
		     "",
		     FALSE, INET_DIAG_INFO, 6, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_sacked),
		     dr_common, sort_common),
	DEFINE_FIELD("lost",
		     "",
		     FALSE, INET_DIAG_INFO, 4, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_lost),
		     dr_common, sort_common),
	DEFINE_FIELD("retrans",
		     "",
		     FALSE, INET_DIAG_INFO, 7, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_retrans),
		     dr_common, sort_common),
	DEFINE_FIELD("fackets",
		     "",
		     FALSE, INET_DIAG_INFO, 7, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_fackets),
		     dr_common, sort_common),
	DEFINE_FIELD("last_data_sent",
		     "",
		     FALSE, INET_DIAG_INFO, 14, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_last_data_sent),
		     dr_common, sort_common),
	DEFINE_FIELD("last_ack_sent",
		     "",
		     FALSE, INET_DIAG_INFO, 13, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_last_ack_sent),
		     dr_common, sort_common),
	DEFINE_FIELD("last_data_recv",
		     "",
		     FALSE, INET_DIAG_INFO, 14, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_last_data_recv),
		     dr_common, sort_common),
	DEFINE_FIELD("last_ack_recv",
		     "",
		     FALSE, INET_DIAG_INFO, 13, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_last_ack_recv),
		     dr_common, sort_common),
	DEFINE_FIELD("pmtu",
		     "",
		     FALSE, INET_DIAG_INFO, 6, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_pmtu),
		     dr_common, sort_common),
	DEFINE_FIELD("rcv_ssthresh",
		     "",
		     FALSE, INET_DIAG_INFO, 12, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rcv_ssthresh),
		     dr_common, sort_common),
	DEFINE_FIELD("rtt",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rtt),
		     dr_common, sort_common),
	DEFINE_FIELD("rttvar",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rttvar),
		     dr_common, sort_common),
	DEFINE_FIELD("snd_ssthresh",
		     "",
		     FALSE, INET_DIAG_INFO, 12, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_snd_ssthresh),
		     dr_common, sort_common),
	DEFINE_FIELD("snd_cwnd",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_snd_cwnd),
		     dr_common, sort_common),
	DEFINE_FIELD("advmss",
		     "",
		     FALSE, INET_DIAG_INFO, 6, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_advmss),
		     dr_common, sort_common),
	DEFINE_FIELD("reordering",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_reordering),
		     dr_common, sort_common),
	DEFINE_FIELD("rcv_rtt",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rcv_rtt),
		     dr_common, sort_common),
	DEFINE_FIELD("rcv_space",
		     "",
		     FALSE, INET_DIAG_INFO, 9, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rcv_space),
		     dr_common, sort_common),
	DEFINE_FIELD("total_retrans",
		     "",
		     FALSE, INET_DIAG_INFO, 13, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_total_retrans),
		     dr_common, sort_common),
	DEFINE_FIELD("pacing_rate",
		     "",
		     FALSE, INET_DIAG_INFO, 11, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_pacing_rate),
		     dr_common, sort_common),
	DEFINE_FIELD("max_pacing_rate",
		     "",
		     FALSE, INET_DIAG_INFO, 20, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_max_pacing_rate),
		     dr_common, sort_common),
	DEFINE_FIELD("bytes_acked",
		     "",
		     FALSE, INET_DIAG_INFO, 15, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_bytes_acked),
		     dr_common, sort_common),
	DEFINE_FIELD("bytes_received",
		     "",
		     FALSE, INET_DIAG_INFO, 15, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_bytes_received),
		     dr_common, sort_common),
	DEFINE_FIELD("segs_out",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_segs_out),
		     dr_common, sort_common),
	DEFINE_FIELD("segs_in",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_segs_in),
		     dr_common, sort_common),
	DEFINE_FIELD("notsent_bytes",
		     "",
		     FALSE, INET_DIAG_INFO, 13, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_notsent_bytes),
		     dr_common, sort_common),
	DEFINE_FIELD("min_rtt",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_min_rtt),
		     dr_common, sort_common),
	DEFINE_FIELD("data_segs_in",
		     "",
		     FALSE, INET_DIAG_INFO, 12, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_data_segs_in),
		     dr_common, sort_common),
	DEFINE_FIELD("data_segs_out",
		     "",
		     FALSE, INET_DIAG_INFO, 13, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_data_segs_out),
		     dr_common, sort_common),
	DEFINE_FIELD("delivery_rate",
		     "",
		     FALSE, INET_DIAG_INFO, 13, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_delivery_rate),
		     dr_common, sort_common),
	DEFINE_FIELD("busy_time",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_busy_time),
		     dr_common, sort_common),
	DEFINE_FIELD("rwnd_limited",
		     "",
		     FALSE, INET_DIAG_INFO, 12, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rwnd_limited),
		     dr_common, sort_common),
	DEFINE_FIELD("sndbuf_limited",
		     "",
		     FALSE, INET_DIAG_INFO, 14, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_sndbuf_limited),
		     dr_common, sort_common),
	DEFINE_FIELD("delivered",
		     "",
		     FALSE, INET_DIAG_INFO, 9, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_delivered),
		     dr_common, sort_common),
	DEFINE_FIELD("delivered_ce",
		     "",
		     FALSE, INET_DIAG_INFO, 12, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_delivered_ce),
		     dr_common, sort_common),
	DEFINE_FIELD("bytes_sent",
		     "",
		     FALSE, INET_DIAG_INFO, 15, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_bytes_sent),
		     dr_common, sort_common),
	DEFINE_FIELD("bytes_retrans",
		     "",
		     FALSE, INET_DIAG_INFO, 13, TYPE_U64,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_bytes_retrans),
		     dr_common, sort_common),
	DEFINE_FIELD("dsack_dups",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_dsack_dups),
		     dr_common, sort_common),
	DEFINE_FIELD("reord_seen",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_reord_seen),
		     dr_common, sort_common),
	DEFINE_FIELD("rcv_ooopack",
		     "",
		     FALSE, INET_DIAG_INFO, 11, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rcv_ooopack),
		     dr_common, sort_common),
	DEFINE_FIELD("snd_wnd",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_snd_wnd),
		     dr_common, sort_common),
	DEFINE_FIELD("rcv_wnd",
		     "",
		     FALSE, INET_DIAG_INFO, 10, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rcv_wnd),
		     dr_common, sort_common),
	DEFINE_FIELD("rehash",
		     "",
		     FALSE, INET_DIAG_INFO, 6, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_rehash),
		     dr_common, sort_common),
	DEFINE_FIELD("total_rto",
		     "",
		     FALSE, INET_DIAG_INFO, 9, TYPE_U16,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_total_rto),
		     dr_common, sort_common),
	DEFINE_FIELD("total_rto_recoveries",
		     "",
		     FALSE, INET_DIAG_INFO, 20, TYPE_U16,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_total_rto_recoveries),
		     dr_common, sort_common),
	DEFINE_FIELD("total_rto_time",
		     "",
		     FALSE, INET_DIAG_INFO, 14, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_total_rto_time),
		     dr_common, sort_common),
	DEFINE_FIELD("received_ce",
		     "",
		     FALSE, INET_DIAG_INFO, 11, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_received_ce),
		     dr_common, sort_common),
	DEFINE_FIELD("delivered_e1_bytes",
		     "",
		     FALSE, INET_DIAG_INFO, 18, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_delivered_e1_bytes),
		     dr_common, sort_common),
	DEFINE_FIELD("delivered_e0_bytes",
		     "",
		     FALSE, INET_DIAG_INFO, 18, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_delivered_e0_bytes),
		     dr_common, sort_common),
	DEFINE_FIELD("delivered_ce_bytes",
		     "",
		     FALSE, INET_DIAG_INFO, 18, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_delivered_ce_bytes),
		     dr_common, sort_common),
	DEFINE_FIELD("received_e1_bytes",
		     "",
		     FALSE, INET_DIAG_INFO, 17, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_received_e1_bytes),
		     dr_common, sort_common),
	DEFINE_FIELD("received_e0_bytes",
		     "",
		     FALSE, INET_DIAG_INFO, 17, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_received_e0_bytes),
		     dr_common, sort_common),
	DEFINE_FIELD("received_ce_bytes",
		     "",
		     FALSE, INET_DIAG_INFO, 17, TYPE_U32,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_received_ce_bytes),
		     dr_common, sort_common),
	DEFINE_FIELD("ecn_mode",
		     "",
		     FALSE, INET_DIAG_INFO, 8, TYPE_OTHER,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_received_ce_bytes) +
		     sizeof(unsigned int),
		     dr_ecn_mode, sort_ecn_mode),
	DEFINE_FIELD("accecn_opt_seen",
		     "",
		     FALSE, INET_DIAG_INFO, 15, TYPE_OTHER,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_received_ce_bytes) +
		     sizeof(unsigned int),
		     dr_accecn_opt_seen, sort_accecn_opt_seen),
	DEFINE_FIELD("accecn_fail_mode",
		     "",
		     FALSE, INET_DIAG_INFO, 16, TYPE_OTHER,
		     offsetof(struct conn_info, info) +
		     offsetof(struct tcp_info, tcpi_received_ce_bytes) +
		     sizeof(unsigned int),
		     dr_accecn_fail_mode, sort_accecn_fail_mode),
	DEFINE_FIELD("Congestion control:",
		     "",
		     FALSE, INET_DIAG_CONG, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
	DEFINE_FIELD("Module",
		     "",
		     FALSE, INET_DIAG_CONG, 16, TYPE_STRING,
		     offsetof(struct conn_info, ca_name),
		     dr_common, sort_common),
	DEFINE_FIELD("Vegas info:",
		     "",
		     FALSE, INET_DIAG_VEGASINFO, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
	DEFINE_FIELD("enabled",
		     "",
		     FALSE, INET_DIAG_VEGASINFO, 7, TYPE_BOOL_U32,
		     offsetof(struct conn_info, cc_info) +
		     offsetof(struct tcpvegas_info, tcpv_enabled),
		     dr_common, sort_common),
	DEFINE_FIELD("rttcnt",
		     "",
		     FALSE, INET_DIAG_VEGASINFO, 6, TYPE_U32,
		     offsetof(struct conn_info, cc_info) +
		     offsetof(struct tcpvegas_info, tcpv_rttcnt),
		     dr_common, sort_common),
	DEFINE_FIELD("rtt",
		     "",
		     FALSE, INET_DIAG_VEGASINFO, 8, TYPE_U32,
		     offsetof(struct conn_info, cc_info) +
		     offsetof(struct tcpvegas_info, tcpv_rtt),
		     dr_common, sort_common),
	DEFINE_FIELD("minrtt",
		     "",
		     FALSE, INET_DIAG_VEGASINFO, 10, TYPE_U32,
		     offsetof(struct conn_info, cc_info) +
		     offsetof(struct tcpvegas_info, tcpv_minrtt),
		     dr_common, sort_common),
	DEFINE_FIELD("DCTCP info:",
		     "",
		     FALSE, INET_DIAG_DCTCPINFO, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
	DEFINE_FIELD2("enabled",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_DCTCPINFO,
		      7, TYPE_BOOL_U16,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_dctcp_info, dctcp_enabled),
		      dr_common, sort_common),
	DEFINE_FIELD2("ce_state",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_DCTCPINFO,
		      8, TYPE_U16,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_dctcp_info, dctcp_ce_state),
		      dr_common, sort_common),
	DEFINE_FIELD2("alpha",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_DCTCPINFO,
		      5, TYPE_U32,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_dctcp_info, dctcp_alpha),
		      dr_common, sort_common),
	DEFINE_FIELD2("ab_ecn",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_DCTCPINFO,
		      6, TYPE_U32,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_dctcp_info, dctcp_ab_ecn),
		      dr_common, sort_common),
	DEFINE_FIELD2("ab_tot",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_DCTCPINFO,
		      6, TYPE_U32,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_dctcp_info, dctcp_ab_tot),
		      dr_common, sort_common),
	DEFINE_FIELD("BBR info:",
		     "",
		     FALSE, INET_DIAG_BBRINFO, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
	DEFINE_FIELD2("bw",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_BBRINFO,
		      10, TYPE_OTHER,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_bbr_info, bbr_bw_lo),
		      dr_bbr_bw, sort_bbr_bw),
	DEFINE_FIELD2("min_rtt",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_BBRINFO,
		      7, TYPE_U32,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_bbr_info, bbr_min_rtt),
		      dr_common, sort_common),
	DEFINE_FIELD2("pacing_gain",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_BBRINFO,
		      11, TYPE_U32,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_bbr_info, bbr_pacing_gain),
		      dr_common, sort_common),
	DEFINE_FIELD2("cwnd_gain",
		      "",
		      FALSE, INET_DIAG_VEGASINFO, INET_DIAG_BBRINFO,
		      9, TYPE_U32,
		      offsetof(struct conn_info, cc_info) +
		      offsetof(struct tcp_bbr_info, bbr_cwnd_gain),
		      dr_common, sort_common),
	DEFINE_FIELD("skmeminfo:",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
	DEFINE_FIELD("rmem_alloc",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 10, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_RMEM_ALLOC,
		     dr_common, sort_common),
	DEFINE_FIELD("rcvbuf",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 8, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_RCVBUF,
		     dr_common, sort_common),
	DEFINE_FIELD("wmem_alloc",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 10, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_WMEM_ALLOC,
		     dr_common, sort_common),
	DEFINE_FIELD("sndbuf",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 8, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_SNDBUF,
		     dr_common, sort_common),
	DEFINE_FIELD("fwd_alloc",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 9, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_FWD_ALLOC,
		     dr_common, sort_common),
	DEFINE_FIELD("wmem_queued",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 11, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_WMEM_QUEUED,
		     dr_common, sort_common),
	DEFINE_FIELD("optmem",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 6, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_OPTMEM,
		     dr_common, sort_common),
	DEFINE_FIELD("backlog",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 7, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_BACKLOG,
		     dr_common, sort_common),
	DEFINE_FIELD("drops",
		     "",
		     FALSE, INET_DIAG_SKMEMINFO, 5, TYPE_U32,
		     offsetof(struct conn_info, mem) +
		     sizeof(unsigned int) * SK_MEMINFO_DROPS,
		     dr_common, sort_common),
	DEFINE_FIELD("sockopt:",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 0, TYPE_OTHER,
		     0,
		     NULL, NULL),
	DEFINE_FIELD("recverr",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 7, TYPE_BIT_U8 | 0 << 8,
		     offsetof(struct conn_info, inet_sockopt) + 0,
		     dr_common, sort_common),
	DEFINE_FIELD("is_icsk",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 7, TYPE_BIT_U8 | 1 << 8,
		     offsetof(struct conn_info, inet_sockopt) + 0,
		     dr_common, sort_common),
	DEFINE_FIELD("freebind",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 8, TYPE_BIT_U8 | 2 << 8,
		     offsetof(struct conn_info, inet_sockopt) + 0,
		     dr_common, sort_common),
	DEFINE_FIELD("hdrincl",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 7, TYPE_BIT_U8 | 3 << 8,
		     offsetof(struct conn_info, inet_sockopt) + 0,
		     dr_common, sort_common),
	DEFINE_FIELD("mc_loop",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 7, TYPE_BIT_U8 | 4 << 8,
		     offsetof(struct conn_info, inet_sockopt) + 0,
		     dr_common, sort_common),
	DEFINE_FIELD("transparent",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 11, TYPE_BIT_U8 | 5 << 8,
		     offsetof(struct conn_info, inet_sockopt) + 0,
		     dr_common, sort_common),
	DEFINE_FIELD("mc_all",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 6, TYPE_BIT_U8 | 6 << 8,
		     offsetof(struct conn_info, inet_sockopt) + 0,
		     dr_common, sort_common),
	DEFINE_FIELD("nodefrag",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 8, TYPE_BIT_U8 | 7 << 8,
		     offsetof(struct conn_info, inet_sockopt) + 0,
		     dr_common, sort_common),
	DEFINE_FIELD("bind_address_no_port",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 20, TYPE_OTHER,
		     offsetof(struct conn_info, inet_sockopt) +
		     sizeof(unsigned char),
		     dr_bind_address_no_port, sort_bind_address_no_port),
	DEFINE_FIELD("recverr_rfc4884",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 15, TYPE_OTHER,
		     offsetof(struct conn_info, inet_sockopt) +
		     sizeof(unsigned char),
		     dr_recverr_rfc4884, sort_recverr_rfc4884),
	DEFINE_FIELD("defer_connect",
		     "",
		     FALSE, INET_DIAG_SOCKOPT, 13, TYPE_OTHER,
		     offsetof(struct conn_info, inet_sockopt) +
		     sizeof(unsigned char),
		     dr_defer_connect, sort_defer_connect)
};

const int nr_tcp_fields = ARRAY_SIZE(tcp_fields);

static void draw_header(struct nm_ctx *n, WINDOW *win, int y, int x,
			bool reverse, const struct field *f)
{
	const char *fmt;
	int attrs;

	attrs = 0;
	if (f->draw_row) {
		fmt = "%25s %c %c %s";
		if (f->enabled)
			attrs |= A_BOLD;
	} else {
		fmt = "%-25s %c %c %s";
		attrs |= A_UNDERLINE;
	}
	if (reverse)
		attrs |= A_REVERSE;

	if (attrs)
		wattron(win, attrs);
	nm_mvwprintw(win, n->cols, y, x, fmt, f->header,
		     (f->pinned) ? 'P' : ' ',
		     (f == n->sort_key) ? (n->sort_ascending) ? 'A' : 'D' : ' ',
		     f->desc);
	if (attrs)
		wattroff(win, attrs);
}

void draw_field_header(struct nm_ctx *n)
{
	const struct position *pos;
	int i, y, skip;
	WINDOW *win;

	win = n->win[WINDOW_MAIN];
	pos = &n->pos[SCREEN_FIELD];
	y = 0;

	skip = pos->y - ((n->lines - 4) / 2);
	if (skip < 0)
		skip = 0;
	if ((nr_tcp_fields - skip) < (n->lines - 4))
		skip = nr_tcp_fields - (n->lines - 4);

	werase(win);
	nm_mvwprintw(win, n->cols, y++, 0,
		     "Fields:");
	nm_mvwprintw(win, n->cols, y++, 0,
		     "   Right: Select, Up/Down: Move, Left: Done, s: Set sort key,");
	nm_mvwprintw(win, n->cols, y++, 0,
		     "   Space: Toggle display, p: Toggle pinning, q: Quit");

	++y;

	for (i = 0; i < nr_tcp_fields && y < n->lines; ++i) {
		const struct field *f;

		if (skip > 0) {
			--skip;
			continue;
		}

		f = &tcp_fields[i];

		if (!n->sel_field)
			goto draw;

		if (n->sel_field < &tcp_fields[pos->y]) {
			if (n->sel_field <= f && f < &tcp_fields[pos->y])
				++f;
			else if (f == &tcp_fields[pos->y])
				f = n->sel_field;
		} else if (n->sel_field > &tcp_fields[pos->y]) {
			if (f == &tcp_fields[pos->y])
				f = n->sel_field;
			else if (&tcp_fields[pos->y] < f && f <= n->sel_field)
				--f;
		}
draw:
		draw_header(n, win, y++, 0, (i == pos->y), f);
	}

	if (n->cur_screen != SCREEN_FIELD)
		n->cur_screen = SCREEN_FIELD;
	wnoutrefresh(win);
}

void draw_help(struct nm_ctx *n)
{
	WINDOW *win;
	int y;

	win = n->win[WINDOW_MAIN];
	y = 0;

	werase(win);
	nm_mvwprintw(win, n->cols, y++, 0,
		     "Command Help - %s %s",
		     COMMAND_NAME, VERSION_STR);
	nm_mvwprintw(win, n->cols, y++, 0, "Delay %d (0.1s)", n->delay);
	++y;
	nm_mvwprintw(win, n->cols, y++, 2, "d: Change delay");
	nm_mvwprintw(win, n->cols, y++, 2, "f: Edit fields");
	nm_mvwprintw(win, n->cols, y++, 2, "4: Show IPv4 connections");
	nm_mvwprintw(win, n->cols, y++, 2, "6: Show IPv6 connections");
	nm_mvwprintw(win, n->cols, y++, 2, "t: Show TCP connections");
	nm_mvwprintw(win, n->cols, y++, 2, "u: Show UDP connections");
	nm_mvwprintw(win, n->cols, y++, 2, "q: Quit");
	++y;
	nm_mvwprintw(win, n->cols, y++, 0, "Type 'q' to continue");

	n->cur_screen = SCREEN_HELP;
}

void add_conn_info(struct nm_ctx *n, struct conn_info *ci)
{
	const struct field *sort_key;
	struct conn_info *pos;
	unsigned int ext;
	size_t offset;
	void *p1;

	sort_key = n->sort_key;
	if (sort_key)
		ext = 1U << sort_key->ext_rcv;

	if (!sort_key || !(ci->ext & ext) || list_empty(&n->conn_list)) {
		list_add_tail(&ci->list, &n->conn_list);
		return;
	}

	offset = sort_key->offset;
	p1 = (char *)ci + offset;

	list_for_each_entry(pos, &n->conn_list, list) {
		void *p2;
		int ret;

		if (!(pos->ext & ext))
			break;

		p2 = (char *)pos + offset;

		ret = sort_key->sort_func(sort_key, p1, p2);
		if (n->sort_ascending) {
			if (ret < 0)
				break;
		} else {	/* descending */
			if (ret > 0)
				break;
		}
	}

	list_add_tail(&ci->list, &pos->list);
}
