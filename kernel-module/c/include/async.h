/*
 * Copyright (C) 2022 Ant Group CO., Ltd. All rights reserved.
 *
 * This file is released under the GPLv2.
 */

#ifndef __JINDISK_ASYNC_H__
#define __JINDISK_ASYNC_H__

#include <linux/slab.h>
#include <linux/workqueue.h>

typedef void (*async_func_t)(void *context);

struct closure {
	void *context;
	async_func_t fn;
	struct work_struct work;
};
void closure_exec(struct work_struct *ws);

#define go(_fn, _context)                                                      \
	do {                                                                   \
		struct closure *closure =                                      \
			kmalloc(sizeof(struct closure), GFP_KERNEL);           \
		if (!closure)                                                  \
			break;                                                 \
		closure->fn = _fn;                                             \
		closure->context = _context;                                   \
		INIT_WORK(&closure->work, closure_exec);                       \
		schedule_work(&closure->work);                                 \
	} while (0)

#endif
