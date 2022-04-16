#include <linux/bsearch.h>

#include "../include/dm_sworndisk.h"
#include "../include/lsm_tree.h"
#include "../include/segment_buffer.h"
#include "../include/memtable.h"
#include "../include/metadata.h"

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

void bit_builder_buffer_flush_if_full(struct bit_builder* this) {
    loff_t pos = this->begin;

    if (this->cur + this->height * sizeof(struct bit_node) > (SEGMENT_BUFFER_SIZE >> 1)) {
        kernel_write(this->file, this->buffer, this->cur, &pos);
        this->begin += this->cur;
        this->cur = 0;
    }
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
    bit_builder_buffer_flush_if_full(this);
    cur = this->cur;
    this->cur += sizeof(struct bit_node);

    this->ctx[h].nr += 1;
    while (this->ctx[h].nr == DEFAULT_BIT_DEGREE) {
        inner_node = __bit_inner(&this->ctx[h]);
        this->ctx[h+1].nodes[this->ctx[h+1].nr] = inner_node;
        this->ctx[h+1].pointers[this->ctx[h+1].nr].pos = this->begin + this->cur;
        memcpy(this->buffer + this->cur, &inner_node, sizeof(struct bit_node));
        this->cur += sizeof(struct bit_node);

        this->ctx[h+1].nr += 1;
        this->ctx[h].nr = 0;
        h += 1;
    }

    leaf_node.leaf.next.pos = this->begin + this->cur;
    memcpy(this->buffer + cur, &leaf_node, sizeof(struct bit_node));
    this->lsm_file_builder.size += 1;
    return 0;
}

struct lsm_file* bit_builder_complete(struct lsm_file_builder* builder) {
    struct bit_builder* this = container_of(builder, struct bit_builder, lsm_file_builder);
    size_t h = 0;
    loff_t pos = this->begin;
    struct bit_node inner_node;

    if (this->ctx[this->height-1].nr) 
        goto exit;

    bit_builder_buffer_flush_if_full(this);
    while (h < this->height - 1) {
        inner_node = __bit_inner(&this->ctx[h]);
        this->ctx[h+1].nodes[this->ctx[h+1].nr] = inner_node;
        this->ctx[h+1].pointers[this->ctx[h+1].nr].pos = this->begin + this->cur;
        memcpy(this->buffer + this->cur, &inner_node, sizeof(struct bit_node));
        this->cur += sizeof(struct bit_node);

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

    this->lsm_file_builder.size = 0;
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

// block index table iterator implementation
struct bit_iterator {
    struct iterator iterator;

    bool has_next;
    struct bit_file* bit_file;
    struct bit_leaf leaf;
};

bool bit_iterator_has_next(struct iterator* iter) {
    struct bit_iterator* this = container_of(iter, struct bit_iterator, iterator);

    return this->has_next;
}

int bit_iterator_next(struct iterator* iter, void* data) {
    loff_t pos;
    struct bit_node bit_node;
    struct bit_iterator* this = container_of(iter, struct bit_iterator, iterator);

    if (!iter->has_next(iter))
        return -ENODATA;
    
    // todo: record create

    *(struct entry*)data = __entry(this->leaf.key, record_copy(&this->leaf.record));
    if (this->leaf.key >= this->bit_file->last_key) {
        this->has_next = false;
        return 0;
    }

    pos = this->leaf.next.pos;
    kernel_read(this->bit_file->file, &bit_node, sizeof(struct bit_node), &pos);
    this->leaf = bit_node.leaf;
    return 0;
}

void bit_iterator_destroy(struct iterator* iter) {
    struct bit_iterator* this = container_of(iter, struct bit_iterator, iterator);

    if (!IS_ERR_OR_NULL(this)) 
        kfree(this);
}


int bit_iterator_init(struct bit_iterator* this, struct bit_file* bit_file) {
    int err = 0;

    this->has_next = true;
    this->bit_file = bit_file;
    err = bit_file_first_leaf(this->bit_file, &this->leaf);
    if (err)
        return err;

    this->iterator.has_next = bit_iterator_has_next;
    this->iterator.next = bit_iterator_next;
    this->iterator.destroy = bit_iterator_destroy;
    
    return 0;
}

struct iterator* bit_iterator_create(struct bit_file* bit_file) {
    int err = 0;
    struct bit_iterator* this;

    this = kmalloc(sizeof(struct bit_iterator), GFP_KERNEL);
    if (!this) 
        goto bad;

    err = bit_iterator_init(this, bit_file);
    if (err)
        goto bad;

    return &this->iterator;
bad:
    if (this)
        kfree(this);
    return NULL;
}

struct iterator* bit_file_iterator(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    return bit_iterator_create(this);
}

uint32_t bit_file_get_first_key(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    return this->first_key;
}

uint32_t bit_file_get_last_key(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    return this->last_key;
}

void* bit_file_get_stats(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);
    struct bit_info* stats = kmalloc(sizeof(struct bit_info), GFP_KERNEL);
    
    if (!stats)
        return NULL;
    stats->root = this->root;
    stats->first_key = this->first_key;
    stats->last_key = this->last_key;
    stats->id = this->lsm_file.id;
    stats->level = this->lsm_file.level;
    return stats;
}

void bit_file_destroy(struct lsm_file* lsm_file) {
    struct bit_file* this = container_of(lsm_file, struct bit_file, lsm_file);

    if (!IS_ERR_OR_NULL(this))
        kfree(this);
}

int bit_file_init(struct bit_file* this, struct file* file, loff_t root, size_t id, size_t level, uint32_t first_key, uint32_t last_key) {
    int err = 0;
    
    this->file = file;
    this->root = root;
    this->first_key = first_key;
    this->last_key = last_key;

    this->lsm_file.id = id;
    this->lsm_file.level = level;
    this->lsm_file.search = bit_file_search;
    this->lsm_file.iterator = bit_file_iterator;
    this->lsm_file.get_first_key = bit_file_get_first_key;
    this->lsm_file.get_last_key = bit_file_get_last_key;
    this->lsm_file.get_stats = bit_file_get_stats;
    this->lsm_file.destroy = bit_file_destroy;
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

// block index table level implementaion
bool bit_level_is_full(struct lsm_level* lsm_level) {
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    return this->size >= this->capacity;
}

int64_t bit_file_cmp(struct bit_file* file1, struct bit_file* file2) {
    if (file1->first_key == file2->first_key) 
        return (int64_t)(file1->last_key) - (int64_t)(file2->last_key);

    return (int64_t)(file1->first_key) - (int64_t)(file2->first_key);
}

size_t bit_level_search_file(struct bit_level* this, struct bit_file* file) {
    size_t low = 0, high = this->size - 1, mid;

    if (!this->size)
        return 0;

    if (bit_file_cmp(this->bit_files[low], file) >= 0)
        return low;

    if (bit_file_cmp(this->bit_files[high], file) <= 0)
        return high + 1;

    while (low < high) {
        mid = low + ((high - low) >> 1);
        if (bit_file_cmp(this->bit_files[mid], file) < 0)
            low = mid + 1;
        else 
            high = mid;
    }

    return low;
}

int bit_file_cmp_key(const void* p_key, const void* p_file) {
    uint32_t key = *(uint32_t*)p_key;
    const struct bit_file* file = *(struct bit_file**)p_file;

    if (key >= file->first_key && key <= file->last_key)
        return 0;
    
    if (key < file->first_key)
        return -1;

    return 1;
}

struct bit_file** bit_level_locate_file_pointer(struct bit_level* this, uint32_t key) {
    return bsearch(&key, this->bit_files, this->size, sizeof(struct bit_file*), bit_file_cmp_key);
}

struct bit_file* bit_level_locate_file(struct bit_level* this, uint32_t key) {
    struct bit_file** result = bit_level_locate_file_pointer(this, key);
    
    if (!result)
        return NULL;
    return *(struct bit_file**)result;
}

int bit_level_add_file(struct lsm_level* lsm_level, struct lsm_file* file) {
    size_t pos;
    struct bit_file* bit_file = container_of(file, struct bit_file, lsm_file);
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    if (this->size >= this->max_size)
        return -ENOSPC;

    pos = bit_level_search_file(this, bit_file);
    memcpy(this->bit_files + pos + 1, this->bit_files + pos, (this->size - pos) * sizeof(struct bit_file*));
    this->bit_files[pos] = bit_file;
    this->size += 1;
    return 0;
}

int bit_level_search(struct lsm_level* lsm_level, uint32_t key, void* val) {
    struct bit_file* file;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    file = bit_level_locate_file(this, key);
    if (!file)
        return -ENODATA;
    return bit_file_search(&file->lsm_file, key, val);
}

int bit_level_remove_file(struct lsm_level* lsm_level, size_t id) {
    size_t pos;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    for (pos = 0; pos < this->size; ++pos) {
        if (this->bit_files[pos]->lsm_file.id == id) {
            memcpy(this->bit_files + pos, this->bit_files + pos + 1, (this->size - pos - 1) * sizeof(struct bit_file*));
            this->size -= 1;
            return 0;
        }
    }

    return -EINVAL;
}

struct lsm_file* bit_level_pick_demoted_file(struct lsm_level* lsm_level) {
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    if (!this->size)
        return NULL;
    return &this->bit_files[0]->lsm_file;
}
 
// should carefully check bit level has files
uint32_t bit_level_get_first_key(struct bit_level* this) {
    return this->bit_files[0]->first_key;
}

uint32_t bit_level_get_last_key(struct bit_level* this) {
    return this->bit_files[this->size - 1]->last_key;
}

// assume there are no intersections between files
int bit_level_lower_bound(struct bit_level* this, uint32_t key) {
    int low = 0, high = this->size - 1, mid;

    while (low < high) {
        mid = low + ((high - low) >> 1);
        if (key >= this->bit_files[mid]->first_key && key <= this->bit_files[mid]->last_key)
            return mid;
        if (key < this->bit_files[mid]->first_key)
            high = mid - 1;
        else 
            low = mid + 1;
    }

    return low;
}

int bit_level_find_relative_files(struct lsm_level* lsm_level, struct lsm_file* file, struct list_head* relatives) {
    size_t pos;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    INIT_LIST_HEAD(relatives);
    if (!this->size)
        return -ENODATA;

    if (file->get_last_key(file) < bit_level_get_first_key(this) || 
      file->get_first_key(file) > bit_level_get_last_key(this)) 
        return -ENODATA;
    
    pos = bit_level_lower_bound(this, file->get_first_key(file));
    while(pos < this->size && this->bit_files[pos]->first_key <= file->get_last_key(file)) {
        list_add_tail(&this->bit_files[pos]->lsm_file.node, relatives);
        pos += 1;
    }

    return 0;
}

struct lsm_file_builder* bit_level_get_builder(struct lsm_level* lsm_level, struct file* file, size_t begin, size_t id, size_t level) {
    return bit_builder_create(file, begin, id, level);
}

void bit_level_destroy(struct lsm_level* lsm_level) {
    size_t i;
    struct bit_level* this = container_of(lsm_level, struct bit_level, lsm_level);

    if (!IS_ERR_OR_NULL(this)) {
        for (i = 0; i < this->size; ++i)
            bit_file_destroy(&this->bit_files[i]->lsm_file);
        kfree(this);
    }
}

int bit_level_init(struct bit_level* this, size_t level, size_t capacity) {
    int err = 0;

    this->size = 0;
    this->max_size = (capacity << 1);
    this->capacity = capacity;
    this->bit_files = kmalloc(this->max_size * sizeof(struct bit_file*), GFP_KERNEL);
    if (!this->bit_files) {
        err = -ENOMEM;
        goto bad;
    }

    this->lsm_level.level = level;
    this->lsm_level.add_file = bit_level_add_file;
    this->lsm_level.remove_file = bit_level_remove_file;
    this->lsm_level.search = bit_level_search;
    this->lsm_level.pick_demoted_file = bit_level_pick_demoted_file;
    this->lsm_level.find_relative_files = bit_level_find_relative_files;
    this->lsm_level.get_builder = bit_level_get_builder;
    this->lsm_level.destroy = bit_level_destroy;

    return 0;
bad:
    if (this->bit_files)
        kfree(this->bit_files);
    return err;
}

struct lsm_level* bit_level_create(size_t level, size_t capacity) {
    int err = 0;
    struct bit_level* this = NULL;

    this = kzalloc(sizeof(struct bit_level), GFP_KERNEL);
    if (!this)
        goto bad;

    err = bit_level_init(this, level, capacity);
    if (err)
        goto bad;

    return &this->lsm_level;
bad:
    if (this)
        kfree(this);
    return NULL;
}

// compaction job implementation
struct kway_merge_node {
    struct iterator* iter;
    struct entry entry;
};

struct kway_merge_node __kway_merge_node(struct iterator* iter, struct entry entry) {
    struct kway_merge_node node = {
        .iter = iter,
        .entry = entry
    };
    return node;
}

bool kway_merge_node_less(const void *lhs, const void *rhs) {
    const struct kway_merge_node *node1 = lhs, *node2 = rhs;

    return node1->entry.key < node2->entry.key;
}

void kway_merge_node_swap(void *lhs, void *rhs) {
    struct kway_merge_node *node1 = lhs, *node2 = rhs, temp;

    temp = *node1;
    *node1 = *node2;
    *node2 = temp;
}

int compaction_job_run(struct compaction_job* this) {
    int err = 0;
    size_t fd;
    struct min_heap heap = {
        .data = NULL,
        .nr = 0,
        .size = 0
    };
    struct min_heap_callbacks comparator = {
        .elem_size = sizeof(struct kway_merge_node),
        .less = kway_merge_node_less,
        .swp = kway_merge_node_swap
    };
    struct kway_merge_node kway_merge_node;
    struct entry entry, distinct, first;
    struct lsm_file *file, *demoted;
    struct iterator *iter;
    struct list_head files, iters;
    struct lsm_file_builder* builder = NULL;

    demoted = this->level1->pick_demoted_file(this->level1);
    this->level2->find_relative_files(this->level2, demoted, &files);

    // if (list_empty(&files)) {
    //     // write metadata
    //     demoted->level = this->level2->level;
    //     this->catalogue->set_file_stats(this->catalogue, demoted->id, demoted->get_stats(demoted));
    //     // move file between levels
    //     this->level2->add_file(this->level2, demoted);
    //     this->level1->remove_file(this->level1, demoted->id);
    //     return 0;
    // }

    INIT_LIST_HEAD(&iters);
    list_for_each_entry(file, &files, node) {
        list_add_tail(&file->iterator(file)->node, &iters);
        heap.size += 1;
    }
    list_add(&demoted->iterator(demoted)->node, &iters);
    heap.size += 1;

    heap.data = kmalloc(heap.size * sizeof(struct kway_merge_node), GFP_KERNEL);
    if (!heap.data) {
        err = -ENOMEM;
        goto exit;
    }

    list_for_each_entry(iter, &iters, node) {
        if (iter->has_next(iter)) {
            iter->next(iter, &entry);
            kway_merge_node = __kway_merge_node(iter, entry);
            min_heap_push(&heap, &kway_merge_node, &comparator);
        }
    }

    distinct = ((struct kway_merge_node*)heap.data)->entry;
    this->catalogue->alloc_file(this->catalogue, &fd);
    builder = this->level2->get_builder(this->level2, this->file, this->catalogue->start + fd * this->catalogue->file_size, fd, this->level2->level);
    while (heap.nr > 0) {
        iter = ((struct kway_merge_node*)heap.data)->iter;
        first = ((struct kway_merge_node*)heap.data)->entry;
        min_heap_pop(&heap, &comparator);

        if (iter->has_next(iter)) {
            iter->next(iter, &entry);
            kway_merge_node = __kway_merge_node(iter, entry);
            min_heap_push(&heap, &kway_merge_node, &comparator);
        }

        if (distinct.key == first.key) {
            distinct = first;
            continue;
        }
        builder->add_entry(builder, &distinct);
        record_destroy(distinct.val);
        distinct = first;

        if (builder->size >= DEFAULT_LSM_FILE_CAPACITY) {
            file = builder->complete(builder);
            this->catalogue->set_file_stats(this->catalogue, file->id, file->get_stats(file));
            this->level2->add_file(this->level2, file);

            this->catalogue->alloc_file(this->catalogue, &fd);
            builder->destroy(builder);
            builder = this->level2->get_builder(this->level2, this->file, this->catalogue->start + fd * this->catalogue->file_size, fd, this->level2->level);
        }
    }

    builder->add_entry(builder, &distinct);
    file = builder->complete(builder);
    this->catalogue->set_file_stats(this->catalogue, file->id, file->get_stats(file));
    this->level2->add_file(this->level2, file);

    this->catalogue->release_file(this->catalogue, demoted->id);
    this->level1->remove_file(this->level1, demoted->id);
    list_for_each_entry(file, &files, node) {
        this->catalogue->release_file(this->catalogue, file->id);
        this->level2->remove_file(this->level2, file->id);
    }

exit:
    if (heap.data)
        kfree(heap.data);
    if (builder)
        builder->destroy(builder);
    return err;   
}

void compaction_job_destroy(struct compaction_job* this) {
    if (!IS_ERR_OR_NULL(this))
        kfree(this);
}

int compaction_job_init(struct compaction_job* this, struct file* file, struct lsm_catalogue* catalogue, struct lsm_level* level1, struct lsm_level* level2) {
    this->file = file;
    this->catalogue = catalogue;
    this->level1 = level1;
    this->level2 = level2;
    this->run = compaction_job_run;
    this->destroy = compaction_job_destroy;
    return 0;
}

struct compaction_job* compaction_job_create(struct file* file, struct lsm_catalogue* catalogue, struct lsm_level* level1, struct lsm_level* level2) {
    int err = 0;
    struct compaction_job* this;

    this = kzalloc(sizeof(struct compaction_job), GFP_KERNEL);
    if (!this)
        goto bad;

    err = compaction_job_init(this, file, catalogue, level1, level2);
    if (err)
        goto bad;

    return this;
bad:
    if (this)
        kfree(this);
    return NULL;
}