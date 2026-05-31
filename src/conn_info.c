#include "conn_info.h"
#include <stdlib.h>

struct conn_info *conn_info_alloc(void)
{
	return calloc(1, sizeof(struct conn_info));
}

void conn_info_free(struct conn_info *ci)
{
	free(ci);
}
