#include "proc.h"
#include "draw.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <mntent.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>

struct sk_owner {
	struct sk_owner		*next;
	unsigned int		sk_ino;
	pid_t			pid;
	char			comm[TASK_COMM_LEN];
};

static char proc_path[256];
static size_t proc_path_len;
static DIR *dp_proc;

static unsigned int map_hash_sz = 1024;
static int map_hash_shift = 10;
static struct sk_owner **sk_ino_hb;
static int nr_sockets;

static int get_proc_mount_path(struct nm_ctx *n, char *proc_path, size_t len)
{
	struct mntent *me;
	FILE *fp;
	int err;

	err = 1;

	fp = setmntent(MOUNTED, "r");
	if (!fp) {
		nm_error(n, "setmntent failed\n");
		goto out;
	}

	for (;;) {
		me = getmntent(fp);
		if (!me)
			break;

		if (!strcmp(me->mnt_type, "proc"))
			break;
	}

	if (!me) {
		nm_error(n, "Failed to find proc mount point.\n");
	} else {
		char *p;

		p = stpncpy(proc_path, me->mnt_dir, len - 1);
		if (*p != '\0')
			nm_error(n, "proc mount point path is too long.\n");
		else
			err = 0;
	}

	endmntent(fp);
out:
	return err;
}

static unsigned int sk_ino_hash(unsigned int inode)
{
#define HASH_MULTIPLIER	2654435761U	/* Knuth's multiplicative hash */
	return (inode * HASH_MULTIPLIER) >> (32 - map_hash_shift);
}

int lookup_socket_owner(unsigned int inode, pid_t *pid, char *comm)
{
	struct sk_owner *o;
	int found;

	found = FALSE;

	if (!inode)
		goto out;

	o = sk_ino_hb[sk_ino_hash(inode)];
	while (o) {
		if (o->sk_ino == inode) {
			if (pid)
				*pid = o->pid;
			if (comm)
				memcpy(comm, o->comm, sizeof(o->comm));
			found = TRUE;
			break;
		}

		o = o->next;
	}
out:
	return found;
}

static int get_comm(struct nm_ctx *n, char *p, char *comm)
{
	char buf[32], *s, *end;
	FILE *fp;
	int err;

	err = 1;

	*(p + 0) = '/';
	*(p + 1) = 'c';
	*(p + 2) = 'o';
	*(p + 3) = 'm';
	*(p + 4) = 'm';
	*(p + 5) = '\0';

	fp = fopen(proc_path, "r");
	if (!fp)
		goto out;

	s = fgets(buf, sizeof(buf), fp);
	if (s != buf)
		goto err_out;

	end = comm + TASK_COMM_LEN;
	while (*s != '\0' && comm < end) {
		if (*s == '\n') {
			*comm = '\0';
			break;
		}
		*comm++ = *s++;
	}

	if (*comm == '\0' && comm < end)
		err = 0;
err_out:
	fclose(fp);
out:
	return err;
}

static int
add_sk_ino(struct nm_ctx *n, unsigned int inode, pid_t pid, const char *comm)
{
	struct sk_owner *o, *pos;
	unsigned int h;
	int err, found;

	err = 1;

	found = lookup_socket_owner(inode, NULL, NULL);
	if (found)
		goto out;

	o = calloc(1, sizeof(*o));
	if (!o) {
		nm_perror(n, "add_sk: calloc", errno);
		goto err_out;
	}

	o->sk_ino = inode;
	o->pid = pid;
	memcpy(o->comm, comm, sizeof(o->comm));

	h = sk_ino_hash(inode);
	if (!(pos = sk_ino_hb[h])) {
		sk_ino_hb[h] = o;
	} else {
		while (pos->next)
			pos = pos->next;
		pos->next = o;
	}
	++nr_sockets;
out:
	err = 0;
err_out:
	return err;
}

static
int sk_ino_make_map(struct nm_ctx *n, DIR *dp, pid_t pid, const char *comm)
{
	int err, dfd;

	err = 1;

	dfd = dirfd(dp);
	if (dfd < 0)
		goto out;

	for (;;) {
		char buf[80], *endp;
		unsigned int inode;
		struct dirent *d;
		int ret;

		errno = 0;
		d = readdir(dp);
		if (!d) {
			if (errno)
				continue;
			break;
		}
		if (d->d_type != DT_LNK)
			continue;

		ret = readlinkat(dfd, d->d_name, buf, sizeof(buf));
		if (ret == -1)
			continue;
		if (strncmp(buf, "socket:[", 8))
			continue;
		inode = strtol(buf + 8, &endp, 10);
		if (*endp != ']')
			continue;

		ret = add_sk_ino(n, inode, pid, comm);
		if (ret)
			goto out;
	}

	err = 0;
out:
	return err;
}

int build_sk_proc_map(struct nm_ctx *n)
{
	int err;

	err = 1;

	if (!ext_is_set(n->ext_req, INET_DIAG_PROC))
		goto out;

	rewinddir(dp_proc);

	for (;;) {
		char ch, *p1, *p2, comm[TASK_COMM_LEN];
		struct dirent *d;
		DIR *dp_pid;
		pid_t pid;
		int ret;

		errno = 0;
		d = readdir(dp_proc);
		if (!d) {
			if (errno)
				continue;
			break;
		}
		if (d->d_type != DT_DIR)
			continue;

		/* Could the procfs mount point path be too long?
		 * Do we need to handle it?
		 */
		p1 = d->d_name;
		p2 = proc_path + proc_path_len;
		pid = 0;
		while (isdigit((ch = *p1))) {
			*p2++ = ch;
			++p1;
			pid = pid * 10 + ch - '0';
		}
		if (*p1 != '\0')
			continue;

		*(p2 + 0) = '/';
		*(p2 + 1) = 'f';
		*(p2 + 2) = 'd';
		*(p2 + 3) = '\0';

		dp_pid = opendir(proc_path);
		if (!dp_pid)
			/* opendir() may fail because of permissions. */
			continue;

		memset(comm, 0, sizeof(comm));

		ret = get_comm(n, p2, comm) ||
		      sk_ino_make_map(n, dp_pid, pid, comm);
		closedir(dp_pid);
		if (ret)
			goto err_out;
	}

	n->ext_rcv |= 1U << INET_DIAG_PROC;
out:
	err = 0;
err_out:
	return err;
}

int free_sk_proc_map(struct nm_ctx *n, int resize)
{
	int err, i, new_map_hash_shift;
	unsigned int new_map_hash_sz;

	err = 1;

	if (!ext_is_set(n->ext_req, INET_DIAG_PROC))
		goto out;

	for (i = 0; (1U << i) < nr_sockets; ++i)
		;
	new_map_hash_sz = 1U << i;
	new_map_hash_shift = i;

	for (i = 0; i < map_hash_sz; ++i) {
		struct sk_owner *o, *n;

		if (!(o = sk_ino_hb[i]))
			continue;

		do {
			n = o->next;
			free(o);
			--nr_sockets;
			o = n;
		} while (o);

		sk_ino_hb[i] = NULL;
	}

	if (resize && map_hash_sz != new_map_hash_sz) {
		free(sk_ino_hb);
		sk_ino_hb = calloc(new_map_hash_sz, sizeof(struct sk_owner *));
		if (!sk_ino_hb) {
			nm_perror(n, "sk_ino_hb: calloc", errno);
			goto err_out;
		}
		map_hash_sz = new_map_hash_sz;
		map_hash_shift = new_map_hash_shift;
	}
out:
	err = 0;
err_out:
	return err;
}

int proc_init(struct nm_ctx *n)
{
	int err;

	err = 1;

	if (get_proc_mount_path(n, proc_path, sizeof(proc_path)))
		goto out;

	dp_proc = opendir(proc_path);
	if (!dp_proc) {
		nm_perror(n, "proc: opendir", errno);
		goto out;
	}

	proc_path_len = strlen(proc_path);
	if (proc_path[proc_path_len - 1] != '/') {
		proc_path[proc_path_len] = '/';
		++proc_path_len;
	}

	sk_ino_hb = calloc(map_hash_sz, sizeof(struct sk_owner *));
	if (!sk_ino_hb) {
		nm_perror(n, "sk_ino_hb: calloc", errno);
		closedir(dp_proc);
		goto out;
	}

	err = 0;
out:
	return err;
}

void proc_exit(struct nm_ctx *n)
{
	int ret;

	ret = closedir(dp_proc);
	if (ret)
		nm_perror(n, "pric: closedir", errno);

	free_sk_proc_map(n, FALSE);
	free(sk_ino_hb);
}
