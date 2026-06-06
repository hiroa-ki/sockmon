#ifndef	_CONN_INFO_H
#define _CONN_INFO_H

#include "bool.h"
#include "list.h"
#include "proc.h"
#include <linux/inet_diag.h>
#include <linux/sock_diag.h>
#include <linux/tcp.h>

struct conn_info {
	struct list_head		list;
	unsigned char			tos;
	unsigned char			tclass;
#define SHUTDOWN_MASK	3
#define RCV_SHUTDOWN	1
#define SEND_SHUTDOWN	2
	unsigned char			shutdown;
	unsigned char			ipv6only;
	unsigned int			classid;
	struct inet_diag_msg		r;
	struct inet_diag_meminfo	minfo;
	struct tcp_info			info;
	union tcp_cc_info		cc_info;
#define TCP_CA_NAME_MAX	16
	char				ca_name[TCP_CA_NAME_MAX];
	unsigned int			ext;
	unsigned int			mem[SK_MEMINFO_VARS];
	unsigned long long		cgroup_id;
	struct inet_diag_sockopt	inet_sockopt;
	pid_t				pid;
	char				comm[TASK_COMM_LEN];
};

extern struct conn_info* conn_info_alloc(void);
extern void conn_info_free(struct conn_info *ci);

#endif	/* _CONN_INFO_H */
