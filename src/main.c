#include "main.h"
#include "nl.h"
#include "draw.h"
#include "input.h"
#include "conn_info.h"
#include <netinet/in.h>
#include <string.h>

static void nm_ctx_init(struct nm_ctx *n)
{
	memset(n , 0, sizeof(*n));

	n->cur_screen = SCREEN_MAIN;
	n->delay = 30;	/* 30 tenths of a second */
	n->should_stop = false;
	n->we_called = false;
	n->family = AF_INET;
	n->protocol = IPPROTO_TCP;
	INIT_LIST_HEAD(&n->conn_list);
}

static void nm_ctx_exit(struct nm_ctx *n)
{
	struct conn_info *ci, *p;

	list_for_each_entry_safe(ci, p, &n->conn_list, list) {
		list_del(&ci->list);
		conn_info_free(ci);
		--n->nr_conns;
	}
}

int main(int argc, char **argv)
{
	struct nm_ctx n;
	int err;

	err = 1;

	nm_ctx_init(&n);

	if (window_init(&n))
		goto out;

	if (nl_init(&n))
		goto out;

	do {
		if (n.cur_screen != SCREEN_MAIN)
			continue;

		err = connections_dump(&n);
		if (err)
			break;

		window_erase(&n);
		draw_summary(&n);
		draw_connections(&n);
		window_refresh();
	} while (!should_stop(&n));

	nl_exit(&n);
out:
	window_exit(&n);

	nm_ctx_exit(&n);

	return err;
}
