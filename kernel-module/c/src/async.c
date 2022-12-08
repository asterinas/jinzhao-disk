/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#include "../include/async.h"

void closure_exec(struct work_struct *ws)
{
	struct closure *closure = container_of(ws, struct closure, work);

	closure->fn(closure->context);
	kfree(closure);
}
