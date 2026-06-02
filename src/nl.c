#include "nl.h"
#include "conn_info.h"
#include "draw.h"
#include <errno.h>
#include <string.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

#define TCPF_ALL	((1 << TCP_ESTABLISHED)	|	\
			 (1 << TCP_SYN_SENT)	|	\
			 (1 << TCP_SYN_RECV)	|	\
			 (1 << TCP_FIN_WAIT1)	|	\
			 (1 << TCP_FIN_WAIT2)	|	\
			 (1 << TCP_TIME_WAIT)	|	\
			 (1 << TCP_CLOSE)	|	\
			 (1 << TCP_CLOSE_WAIT)	|	\
			 (1 << TCP_LAST_ACK)	|	\
			 (1 << TCP_LISTEN)	|	\
			 (1 << TCP_CLOSING))

static size_t build_nlmsg(void *p, struct nm_ctx *n)
{
	struct inet_diag_req_v2 *r;
	struct nlmsghdr *nlh;

	nlh = (struct nlmsghdr *)p;
	r = NLMSG_DATA(nlh);

	*nlh = (struct nlmsghdr){
		.nlmsg_len	= NLMSG_SPACE(sizeof(*r)),
		.nlmsg_type	= SOCK_DIAG_BY_FAMILY,
		.nlmsg_flags	= NLM_F_REQUEST | NLM_F_DUMP,
		.nlmsg_seq	= 0,
		.nlmsg_pid	= 0	/* kernel */
	};

	*r = (struct inet_diag_req_v2){
		.sdiag_family	= n->family,
		.sdiag_protocol	= n->protocol,
		.idiag_ext	= n->ext_req,
		.idiag_states	= TCPF_ALL,
		.id		= {
			.idiag_sport	= 0,
			.idiag_dport	= 0,
			.idiag_src	= {},
			.idiag_dst	= {},
			.idiag_if	= 0,
			.idiag_cookie	= {}
		}
	};

	return nlh->nlmsg_len;
}

static void copy_void(struct conn_info *ci, const void *p)
{
}

static void copy_meminfo(struct conn_info *ci, const void *p)
{
	const struct inet_diag_meminfo *minfo;

	minfo = p;

	ci->minfo = *minfo;
}

static void copy_info(struct conn_info *ci, const void *p)
{
	const struct tcp_info *info;

	info = p;

	ci->info = *info;
}

static void copy_vegasinfo(struct conn_info *ci, const void *p)
{
	const struct tcpvegas_info *vegas;

	vegas = p;

	ci->cc_info.vegas = *vegas;
}

static void copy_cong(struct conn_info *ci, const void *p)
{
	const char *name;

	name = p;

	strncpy(ci->ca_name, name, sizeof(ci->ca_name));
	ci->ca_name[TCP_CA_NAME_MAX - 1] = '\0';
}

static void copy_tos(struct conn_info *ci, const void *p)
{
	const unsigned char *tos;

	tos = p;

	ci->tos = *tos;
}

static void copy_tclass(struct conn_info *ci, const void *p)
{
	const unsigned char *tclass;

	tclass = p;

	ci->tclass = *tclass;
}

static void copy_skmeminfo(struct conn_info *ci, const void *p)
{
	const unsigned int *mem;

	mem = p;

	memcpy(ci->mem, mem, sizeof(ci->mem));
}

static void copy_shutdown(struct conn_info *ci, const void *p)
{
	const unsigned char *shutdown;

	shutdown = p;

	ci->shutdown = *shutdown;
}

static void copy_dctcpinfo(struct conn_info *ci, const void *p)
{
	const struct tcp_dctcp_info *dctcp;

	dctcp = p;

	ci->cc_info.dctcp = *dctcp;
}

static void copy_skv6only(struct conn_info *ci, const void *p)
{
	const unsigned char *ipv6only;

	ipv6only = p;

	ci->ipv6only = *ipv6only;
}

static void copy_bbrinfo(struct conn_info *ci, const void *p)
{
	const struct tcp_bbr_info *bbr;

	bbr = p;

	ci->cc_info.bbr = *bbr;
}

static void copy_class_id(struct conn_info *ci, const void *p)
{
	const unsigned int *classid;

	classid = p;

	ci->classid = *classid;
}

static void copy_cgroup_id(struct conn_info *ci, const void *p)
{
	const unsigned long long *cgroup_id;

	cgroup_id = p;

	ci->cgroup_id = *cgroup_id;
}

static void copy_sockopt(struct conn_info *ci, const void *p)
{
	const struct inet_diag_sockopt *inet_sockopt;

	inet_sockopt = p;

	ci->inet_sockopt = *inet_sockopt;
}

static int diag_dump(struct nm_ctx *n, const struct nlmsghdr *nlh)
{
	static const void (* const copy_func[])(struct conn_info *,
						const void *) = {
		[INET_DIAG_NONE]		= copy_void,
		[INET_DIAG_MEMINFO]		= copy_meminfo,
		[INET_DIAG_INFO]		= copy_info,
		[INET_DIAG_VEGASINFO]		= copy_vegasinfo,
		[INET_DIAG_CONG]		= copy_cong,
		[INET_DIAG_TOS]			= copy_tos,
		[INET_DIAG_TCLASS]		= copy_tclass,
		[INET_DIAG_SKMEMINFO]		= copy_skmeminfo,
		[INET_DIAG_SHUTDOWN]		= copy_shutdown,
		[INET_DIAG_DCTCPINFO]		= copy_dctcpinfo,
		[INET_DIAG_PROTOCOL]		= copy_void,
		[INET_DIAG_SKV6ONLY]		= copy_skv6only,
		[INET_DIAG_LOCALS]		= copy_void,
		[INET_DIAG_PEERS]		= copy_void,
		[INET_DIAG_PAD]			= copy_void,
		[INET_DIAG_MARK]		= copy_void,
		[INET_DIAG_BBRINFO]		= copy_bbrinfo,
		[INET_DIAG_CLASS_ID]		= copy_class_id,
		[INET_DIAG_MD5SIG]		= copy_void,
		[INET_DIAG_ULP_INFO]		= copy_void,
		[INET_DIAG_SK_BPF_STORAGES]	= copy_void,
		[INET_DIAG_CGROUP_ID]		= copy_cgroup_id,
		[INET_DIAG_SOCKOPT]		= copy_sockopt,
		[__INET_DIAG_MAX]		= copy_void
	};
	const struct inet_diag_msg *r;
	unsigned int rta_len, ext;
	struct conn_info *ci;
	struct rtattr *rta;
	int err;

	err = 1;
	ext = (1U << INET_DIAG_NONE) | (1U << INET_DIAG_ADDRESS);
	r = NLMSG_DATA(nlh);
	rta_len = nlh->nlmsg_len - NLMSG_LENGTH(sizeof(*r));

	ci = conn_info_alloc();
	if (!ci)
		goto out;

	ci->r = *r;

	for (rta = (struct rtattr *)(r + 1); RTA_OK(rta, rta_len);
	     rta = RTA_NEXT(rta, rta_len)) {
		if (rta->rta_type >= __INET_DIAG_MAX) {
			nm_error(n, "Unsupported inet_diag extension: %hu\n",
				 rta->rta_type);
			goto free_ci;
		}

		copy_func[rta->rta_type](ci, RTA_DATA(rta));
		ext |= 1U << rta->rta_type;
	}

	ci->ext = ext;
	n->ext_rcv |= ext;

	list_add_tail(&ci->list, &n->conn_list);
	n->nr_conns++;

	err = 0;
out:
	return err;
free_ci:
	conn_info_free(ci);
	goto out;
}

int connections_dump(struct nm_ctx *n)
{
	struct sockaddr_nl nladdr;
	static char buf[32768];
	struct msghdr msg;
	struct iovec iov;
	int err, sk;
	ssize_t sz;
	size_t len;

	err = 1;
	sk = n->sk;

	nladdr = (struct sockaddr_nl){
		.nl_family	= AF_NETLINK,
		.nl_pid		= 0,	/* kernel */
		.nl_groups	= 0
	};

	len = build_nlmsg(buf, n);

	iov = (struct iovec){
		.iov_base	= buf,
		.iov_len	= len
	};

	msg = (struct msghdr){
		.msg_name	= (void *)&nladdr,
		.msg_namelen	= sizeof(nladdr),
		.msg_iov	= &iov,
		.msg_iovlen	= 1,
		.msg_control	= NULL,
		.msg_controllen	= 0,
		.msg_flags	= 0
	};

	sz = sendmsg(sk, &msg, 0);
	if (sz == -1) {
		nm_perror(n, "sendmsg", errno);
		goto out;
	}

	/* We always receive INET_DIAG_NONE anyway. */
	n->ext_rcv = 1U << INET_DIAG_NONE;
	/* IP addresses are in INET_DIAG_NONE, but handled as
	 * INET_DIAG_ADDRESS.
	 */
	n->ext_rcv |= 1U << INET_DIAG_ADDRESS;
	iov.iov_len = sizeof(buf);
	for (;;) {
		struct nlmsghdr *nlh;

		sz = recvmsg(sk, &msg, 0);
		if (sz == -1) {
			nm_perror(n, "recvmsg", errno);
			goto out;
		}

		for (nlh = (struct nlmsghdr *)buf; NLMSG_OK(nlh, sz);
		     nlh = NLMSG_NEXT(nlh, sz)) {
			if (nlh->nlmsg_type == NLMSG_DONE)
				goto done;
			if (nlh->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *err = NLMSG_DATA(nlh);

				if (nlh->nlmsg_len <
				    NLMSG_LENGTH(sizeof(*err)))
					nm_error(n, "NLMSG_ERROR\n");
				else
					nm_perror(n, "NLMSG_ERROR",
						  -err->error);

				goto out;
			}

			if (diag_dump(n, nlh))
				goto out;
		}
	}
done:
	err = 0;
out:
	return err;
}

int nl_init(struct nm_ctx *n)
{
	struct sockaddr_nl nladdr;
	int err, ret, sk;

	err = 1;

	sk = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_SOCK_DIAG);
	if (sk == -1) {
		nm_perror(n, "socket", errno);
		goto out;
	}

	nladdr = (struct sockaddr_nl){
		.nl_family	= AF_NETLINK,
		.nl_pid		= 0,	/* kernel */
		.nl_groups	= 0
	};

	ret = bind(sk, (const struct sockaddr *)&nladdr, sizeof(nladdr));
	if (ret == -1) {
		nm_perror(n, "bind", errno);
		close(sk);
		goto out;
	}

	n->sk = sk;
	err = 0;
out:
	return err;
}

void nl_exit(struct nm_ctx *n)
{
	close(n->sk);
}
