#ifndef _PROC_H
#define _PROC_H

#include "main.h"
#include <sys/types.h>

#define TASK_COMM_LEN	16

extern int lookup_socket_owner(unsigned int inode, pid_t *pid, char *comm);
extern int build_sk_proc_map(struct nm_ctx *n);
extern int free_sk_proc_map(struct nm_ctx *n);
extern int proc_init(struct nm_ctx *n);
extern void proc_exit(struct nm_ctx *n);

#endif	/* _PROC_H */
