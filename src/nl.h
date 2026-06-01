#ifndef	_NL_H
#define	_NL_H

#include "main.h"

enum {
	TCP_ESTABLISHED	= 1,
	TCP_SYN_SENT,
	TCP_SYN_RECV,
	TCP_FIN_WAIT1,
	TCP_FIN_WAIT2,
	TCP_TIME_WAIT,
	TCP_CLOSE,
	TCP_CLOSE_WAIT,
	TCP_LAST_ACK,
	TCP_LISTEN,
	TCP_CLOSING
};

extern int connections_dump(struct nm_ctx *n);
extern int nl_init(struct nm_ctx *n);
extern void nl_exit(struct nm_ctx *n);

#endif	/* _NL_H */

