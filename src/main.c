#include "main.h"
#include "nl.h"
#include "draw.h"
#include "input.h"
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

int main(int argc, char **argv)
{
	struct nm_ctx n;
	int err;

	err = 1;

	nm_ctx_init(&n);

	if (window_init(&n))
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
out:
	window_exit(&n);

	return err;
}
