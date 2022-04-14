#include "../include/dm_sworndisk.h"
#include "../include/lsm_tree.h"
#include "../include/segment_buffer.h"
#include "../include/memtable.h"

// block index table node implementaion
void bit_node_print(struct bit_node* bit_node) {
    size_t i;

    DMINFO("is leaf: %d", bit_node->is_leaf);
    if (bit_node->is_leaf) {
        DMINFO("key: %d", bit_node->leaf.key);
        DMINFO("value: %lld", bit_node->leaf.record.pba);
        DMINFO("next: %ld", bit_node->leaf.next.pos);
    } else {
        for (i = 0; i < bit_node->inner.nr_child; ++i) {
            DMINFO("child %ld", i);
            DMINFO("\tkey: %d", bit_node->inner.children[i].key);
            DMINFO("\tpos: %ld", bit_node->inner.children[i].pointer.pos);
        }
    }
}

// block index table builder implementaion
size_t __bit_height(size_t capacity, size_t nr_degree) {
    size_t height = 1, size = 1;

    if (!capacity)
        return 0;

    while(size < capacity) {
        height += 1;
        size *= nr_degree;
    }

    return height;
}

size_t __bit_array_len(size_t capacity, size_t nr_degree) {
    size_t len = 0, size = 1;

    if (!capacity)
        return 0;
    
    while (size < capacity) {
        len += size;
        size *= nr_degree;
    }

    return len + capacity;
}

struct bit_node __bit_inner(struct bit_builder_context* ctx) {
    size_t i;
    struct bit_node node = {
        .is_leaf = false,
        .inner.nr_child = ctx->nr
    };

    for (i = 0; i < ctx->nr; ++i) {
        node.inner.children[i].key = ctx->nodes[i].is_leaf ? ctx->nodes[i].leaf.key : ctx->nodes[i].inner.children[ctx->nodes[i].inner.nr_child - 1].key;
        node.inner.children[i].pointer = ctx->pointers[i];
    }

    return node;
}

void bit_builder_forward_cursor(struct bit_builder* this) {
    loff_t pos = this->begin;

    if (this->cur + this->height * sizeof(struct bit_node) > SEGMENT_BUFFER_SIZE) {
        kernel_write(this->file, this->buffer, this->cur, &pos);
        this->begin += this->cur;
        this->cur = 0;
    }

    this->cur += sizeof(struct bit_node);
}

int bit_builder_add_entry(struct lsm_file_builder* builder, struct entry* entry) {
    struct bit_node inner_node, leaf_node = {
        .is_leaf = true,
        .leaf.key = entry->key,
        .leaf.record = *(struct record*)(entry->val)
    };
    size_t h = 0, cur;
    struct bit_builder* this = container_of(builder, struct bit_builder, lsm_file_builder);
    struct bit_pointer pointer = {
        .pos = this->begin + this->cur
    };

    if (!this->has_first_key) {
        this->first_key = entry->key;
        this->has_first_key = true;
    } else 
        this->last_key = entry->key;

    this->ctx[h].nodes[this->ctx[h].nr] = leaf_node;
    this->ctx[h].pointers[this->ctx[h].nr]  = pointer;
    bit_builder_forward_cursor(this);
    cur = this->cur - sizeof(struct bit_node);

    this->ctx[h].nr += 1;
    while (this->ctx[h].nr == DEFAULT_BIT_DEGREE) {
        inner_node = __bit_inner(&this->ctx[h]);
        this->ctx[h+1].nodes[this->ctx[h+1].nr] = inner_node;
        this->ctx[h+1].pointers[this->ctx[h+1].nr].pos = this->begin + this->cur;
        memcpy(this->buffer + this->cur, &inner_node, sizeof(struct bit_node));
        bit_builder_forward_cursor(this);

        this->ctx[h+1].nr += 1;
        this->ctx[h].nr = 0;
        h += 1;
    }

    leaf_node.leaf.next.pos = this->begin + this->cur;
    memcpy(this->buffer + cur, &leaf_node, sizeof(struct bit_node));

    return 0;
}

struct lsm_file* bit_builder_complete(struct lsm_file_builder* builder) {
    struct bit_builder* this = container_of(builder, struct bit_builder, lsm_file_builder);
    size_t h = 0;
    loff_t pos = this->begin;
    struct bit_node inner_node;

    if (this->ctx[this->height-1].nr) 
        goto exit;

    while (h < this->height - 1) {
        inner_node = __bit_inner(&this->ctx[h]);
        this->ctx[h+1].nodes[this->ctx[h+1].nr] = inner_node;
        this->ctx[h+1].pointers[this->ctx[h+1].nr].pos = this->begin + this->cur;
        memcpy(this->buffer + this->cur, &inner_node, sizeof(struct bit_node));
        bit_builder_forward_cursor(this);

        this->ctx[h+1].nr += 1;
        this->ctx[h].nr = 0;
        h += 1;
    }

exit:
    kernel_write(this->file, this->buffer, this->cur, &pos);
    return bit_file_create(this->file, this->begin + this->cur - sizeof(struct bit_node), this->id, this->level, this->first_key, this->last_key);
}

void bit_builder_destroy(struct lsm_file_builder* builder) {
    struct bit_builder* this = container_of(builder, struct bit_builder, lsm_file_builder);
    
    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->ctx))
            kfree(this->ctx);
        if (!IS_ERR_OR_NULL(this->buffer))
            kfree(this->buffer);
        kfree(this);
    }
}

int bit_builder_init(struct bit_builder* this, struct file* file, size_t begin, size_t id, size_t level) {
    int err = 0;
    
    this->file = file;
    this->begin = begin;
    this->cur = 0;
    this->id = id;
    this->level = level;
    this->has_first_key = false;
    this->height = __bit_height(DEFAULT_LSM_FILE_CAPACITY, DEFAULT_BIT_DEGREE);

    this->buffer = kmalloc(SEGMENT_BUFFER_SIZE, GFP_KERNEL);
    if (!this->buffer) {
        err = -ENOMEM;
        goto bad;
    }

    this->ctx = kzalloc(this->height * sizeof(struct bit_builder_context), GFP_KERNEL);
    if (!this->ctx) {
        err = -ENOMEM;
        goto bad;
    }

    this->lsm_file_builder.add_entry = bit_builder_add_entry;
    this->lsm_file_builder.complete = bit_builder_complete;
    this->lsm_file_builder.destroy = bit_builder_destroy;

    return 0;
bad:
    if (this->buffer)
        kfree(this->buffer);
    if (this->ctx)
        kfree(this->ctx);
    return err;
}

struct lsm_file_builder* bit_builder_create(struct file* file, size_t begin, size_t id, size_t level) {
    int err = 0;
    struct bit_builder* this = NULL;

    this = kzalloc(sizeof(struct bit_builder), GFP_KERNEL);
    if (!this)
        goto bad;
    
    err = bit_builder_init(this, file, begin, id, level);
    if (err)
        goto bad;
    
    return &this->lsm_file_builder;
bad:
    if (this)
        kfree(this);
    return NULL;
}

// block index table file implementation

struct entry __entry(uint32_t key, void* val) {
    struct entry entry = {
        .key = key,
        .val = val
    };

    return entry;
}

int bit_file_search_leaf(struct bit_file* this, uint32_t key, struct bit_leaf* leaf) {
    size_t i;
    loff_t addr;
    struct bit_node bit_node;

    addr = this->root;
next:
    kernel_read(this->file, &bit_node, sizeof(struct bit_node), &addr);
    if (bit_node.is_leaf) {
        *leaf = bit_node.leaf;
        return 0;
    }

    for (i = 0; i < bit_node.inner.nr_child; ++i) {
        if (key <= bit_node.inner.children[i].key) {
            addr = bit_node.inner.children[i].pointer.pos;
            goto next;
        }
    }
    
    return -ENODATA;
}

int bit_file_first_leaf(struct bit_file* this, struct bit_leaf* leaf) {
    return bit_file_search_leaf(this, this->first_key, leaf);
}

int bit_file_search(struct lsm_file* lsm_file, uint32_t key, void* val) {
    int err = 0;
    struct bit_leaf leaf;
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    err = bit_file_search_leaf(this, key, &leaf);
    if (err)
        return err;

    *(struct record*)val = leaf.record;
    return err;
}

int bit_file_init(struct bit_file* this, struct file* file, loff_t root, size_t id, size_t level, uint32_t first_key, uint32_t last_key) {
    int err = 0;
    
    this->file = file;
    this->root = root;
    this->id = id;
    this->level = level;
    this->first_key = first_key;
    this->last_key = last_key;
    return err;
}

struct lsm_file* bit_file_create(struct file* file, loff_t root, size_t id, size_t level, uint32_t first_key, uint32_t last_key) {
    int err = 0;
    struct bit_file* this = NULL;

    this = kmalloc(sizeof(struct bit_file), GFP_KERNEL);
    if (!this) {
        err = -ENOMEM;
        goto bad;
    }

    err = bit_file_init(this, file, root, id, level, first_key, last_key);
    if (err) {
        err = -EAGAIN;
        goto bad;
    }

    return &this->lsm_file;
bad:
    if (this)
        kfree(this);
    return NULL;
}