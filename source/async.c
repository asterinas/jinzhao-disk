#include "../include/async.h"

void closure_exec(struct work_struct* ws) {
    struct closure* closure = container_of(ws, struct closure, work);

    closure->fn(closure->context);
    kfree(closure);
}

