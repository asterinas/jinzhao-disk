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

// block index table iterator implementaion
bool bit_iterator_has_next(struct iterator* iterator) {
    struct bit_iterator* this = container_of(iterator, struct bit_iterator, iterator);

    return this->node != NULL;
}

struct entry* __entry(uint32_t key, void* val) {
    struct entry* entry;

    entry = kmalloc(sizeof(struct entry), GFP_KERNEL);
    if (!entry)
        return NULL;
    
    entry->key = key;
    entry->val = val;
    return entry;
}

void* bit_iterator_next(struct iterator* iterator) {
    struct entry* entry = NULL;
    struct bit_node* bit_node = NULL;
    struct bit_iterator* this = container_of(iterator, struct bit_iterator, iterator);

    entry = __entry(this->node->key, &this->node->record);
    if (this->node->next.pos == 0) {
        this->node = NULL;
        return entry;
    }

    bit_node = this->bit->bit_nodes->get(this->bit->bit_nodes, this->node->next.pos);
    if (!bit_node)
        return NULL;
    
    *this->node = bit_node->leaf;
    kfree(bit_node);
    return entry;
}

void bit_iterator_destroy(struct iterator* iterator) {
    struct bit_iterator* this = container_of(iterator, struct bit_iterator, iterator);

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->node))
            kfree(this->node);
        kfree(this);
    }
}

int bit_iterator_init(struct bit_iterator* this, struct block_index_table* bit, struct bit_leaf* first) {
    this->bit = bit;
    this->node = first;
    this->iterator.has_next = bit_iterator_has_next;
    this->iterator.next = bit_iterator_next;
    this->iterator.destroy = bit_iterator_destroy;

    return 0;
}

struct iterator* bit_iterator_create(struct block_index_table* bit, struct bit_leaf* first) {
    int r;
    struct bit_iterator* this;

    this = kmalloc(sizeof(struct bit_iterator), GFP_KERNEL);
    if (!this)
        return NULL;
    
    r = bit_iterator_init(this, bit, first);
    if (r)
        return NULL;
    
    return &this->iterator;
}

size_t __bit_height(size_t capacity, size_t nr_degree) {
    size_t height = 0, size = capacity;

    while(size) {
        height += 1;
        size /= nr_degree;
    }

    if (capacity % nr_degree)
        height += 1;

    return height;
}

struct bit_node __bit_leaf(struct bit_leaf* leaf) {
    struct bit_node bit_node = {
        .is_leaf = true,
        .leaf = *leaf
    };

    return bit_node;
}

struct bit_node __bit_inner_node(struct bit_generator_slot* slot) {
    size_t i;
    struct bit_node bit_node = {
        .is_leaf = false
    };

    memset(&bit_node, 0, sizeof(bit_node));
    for (i = 0; i < slot->nr; ++i) {
        bit_node.inner.children[i].key = slot->nodes[i].is_leaf ? 
          slot->nodes[i].leaf.key : slot->nodes[i].inner.children[slot->nodes[i].inner.nr_child-1].key;
        bit_node.inner.children[i].pointer.pos = slot->pointers[i].pos;
    }

    bit_node.inner.nr_child = slot->nr;
    return bit_node;
}

struct bit_pointer __bit_pointer(size_t pos, char* key, char* iv, char* mac) {
    struct bit_pointer bit_pointer = {
        .pos = pos
    };

    if (key)
        memcpy(bit_pointer.key, key, AES_GCM_KEY_SIZE);
    if (iv)
        memcpy(bit_pointer.iv, iv, AES_GCM_IV_SIZE);
    if (mac)
        memcpy(bit_pointer.mac, mac, AES_GCM_AUTH_SIZE);

    return bit_pointer;
}

// block index table generator implementation
int bit_generator_select_root(struct bit_generator* this) {
    int h = 0, err = 0;
    struct bit_node bit_node;

    if (this->slots[this->height - 1].nr) {
        this->bit->root = this->slots[this->height - 1].pointers[0].pos;
        return 0;
    }

    while (h < this->height - 1) {
        if (!this->slots[h].nr) {
            h += 1;
            continue;
        }

        bit_node = __bit_inner_node(&this->slots[h]);
        err = this->bit->bit_nodes->set(this->bit->bit_nodes, this->pos, &bit_node);
        if (err)
            return err;
        this->slots[h+1].pointers[this->slots[h+1].nr].pos = this->pos;
        this->slots[h+1].nodes[this->slots[h+1].nr] =  bit_node;

        this->pos += 1;
        this->slots[h+1].nr += 1;
        h += 1;
    }

    this->bit->root = this->pos - 1;
    return 0;
}

int bit_generator_add(struct lsm_level_generator* lsm_level_generator, struct entry* entry) {
    int err = 0;
    size_t h = 0, cur;
    struct bit_node leaf_node, bit_node;
    struct bit_leaf leaf = {
        .key = entry->key,
        .record = *((struct record*)entry->val),
        .next.pos = 0
    };
    struct bit_generator* this = container_of(lsm_level_generator, struct bit_generator, lsm_level_generator);

    cur = this->pos;
    this->slots[h].pointers[this->slots[h].nr] = __bit_pointer(cur, NULL, NULL, NULL);
    leaf_node = __bit_leaf(&leaf);
    this->slots[h].nodes[this->slots[h].nr] = leaf_node;
    
    this->pos += 1;
    this->slots[h].nr += 1;
    while(this->slots[h].nr == this->bit->nr_degree) {
        bit_node = __bit_inner_node(&this->slots[h]);
        err = this->bit->bit_nodes->set(this->bit->bit_nodes, this->pos, &bit_node);
        if (err)
            return err;
        this->slots[h+1].pointers[this->slots[h+1].nr].pos = this->pos;
        this->slots[h+1].nodes[this->slots[h+1].nr] =  bit_node;

        this->pos += 1;
        this->slots[h+1].nr += 1;
        this->slots[h].nr = 0;
        h += 1;
    }


    this->nr += 1;
    if (this->nr != this->size)
        leaf_node.leaf.next.pos = this->pos;
    err = this->bit->bit_nodes->set(this->bit->bit_nodes, cur, &leaf_node);
    if (err)
        return err;

    if (this->nr == this->size)
        return bit_generator_select_root(this);
    
    return 0;
}

void bit_generator_destroy(struct lsm_level_generator* lsm_level_generator) {
    struct bit_generator* this = container_of(lsm_level_generator, struct bit_generator, lsm_level_generator);

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->slots))
            kfree(this->slots);
        kfree(this);
    }
}

int bit_generator_init(struct bit_generator* this, struct block_index_table* bit, size_t size) {
    int err = 0;
    
    this->bit = bit;
    this->nr = 0;
    this->size = size;
    this->pos = 0;
    this->height = __bit_height(this->size, bit->nr_degree);
    this->slots = kzalloc(this->height * sizeof(struct bit_generator_slot), GFP_KERNEL);
    if (!this->slots) {
        err = -ENOMEM;
        goto bad;
    }

    this->lsm_level_generator.add = bit_generator_add;
    this->lsm_level_generator.destroy = bit_generator_destroy;
    return 0;

bad:
    if (this->slots)
        kfree(this->slots);
    return err;
}

struct lsm_level_generator* bit_generator_create(struct block_index_table* bit, size_t size) {
    int err;
    struct bit_generator* this;

    this = kzalloc(sizeof(struct bit_generator), GFP_KERNEL);
    if (!this)
        return NULL;
    
    err = bit_generator_init(this, bit, size);
    if (err)
        return NULL;
    
    return &this->lsm_level_generator;
}

// block index table lsm level implementaion
struct bit_leaf* block_index_table_first(struct block_index_table* this) {
    size_t cur;
    struct bit_leaf* first = NULL;
    struct bit_node* bit_node = NULL;

    first = kmalloc(sizeof(struct bit_leaf), GFP_KERNEL);
    if (!first)
        goto exit;

    cur = this->root;
next:
    bit_node = this->bit_nodes->get(this->bit_nodes, cur);
    if (!bit_node)
        goto exit;

    if (bit_node->is_leaf) {
        *first = bit_node->leaf;
        goto exit;
    } else {
        if (!bit_node->inner.nr_child) {
            kfree(first);
            first = NULL;
            goto exit;
        }

        cur = bit_node->inner.children[0].pointer.pos;
        kfree(bit_node);
        goto next;
    }

exit:
    if (bit_node)
        kfree(bit_node);
    return first;
}

struct iterator* block_index_table_lsm_level_iterator(struct lsm_level* lsm_level) {
    struct bit_leaf* first;
    struct block_index_table* this = container_of(lsm_level, struct block_index_table, lsm_level);

    first = block_index_table_first(this);
    if (!first)
        return NULL;
    
    return bit_iterator_create(this, first);
}

int block_index_table_lsm_level_search(struct lsm_level* lsm_level, uint32_t key, void* val) {
    int err = 0;
    size_t cur, i;
    struct bit_node* bit_node = NULL;
    struct block_index_table* this = container_of(lsm_level, struct block_index_table, lsm_level);

    cur = this->root;
next:
    bit_node = this->bit_nodes->get(this->bit_nodes, cur);
    if (!bit_node) {
        err = -ENODATA;
        goto exit;
    } 

    if (bit_node->is_leaf) {
        if (bit_node->leaf.key != key) {
            err = -ENODATA;
            goto exit;
        }
        *(struct record*)val = bit_node->leaf.record;
        goto exit;
    } else {
        for (i = 0; i < bit_node->inner.nr_child; ++i) {
            if (key <= bit_node->inner.children[i].key) {
                cur = bit_node->inner.children[i].pointer.pos;
                kfree(bit_node);
                goto next;
            }
        }
        err = -ENODATA;
        goto exit;
    }

exit:
    if (bit_node)
        kfree(bit_node);
    return err;
} 

void block_index_table_lsm_level_destroy(struct lsm_level* lsm_level) {
    struct block_index_table* this = container_of(lsm_level, struct block_index_table, lsm_level);

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->bit_nodes))
            disk_array_destroy(this->bit_nodes);
        kfree(this);
    } 
}

size_t __bit_array_size(size_t capacity, size_t nr_degree) {
    size_t size = 0, cur = 1, height, i;
    
    height = __bit_height(capacity, nr_degree);
    for (i = 0; i < height; ++i) {
        size += cur;
        cur *= nr_degree;
    }

    return size;
}

int block_index_table_init(struct block_index_table* this, size_t level, size_t capacity, size_t size, size_t nr_degree, struct dm_block_manager* bm, dm_block_t start, struct aead_cipher* cipher) {
    this->lsm_level.capacity = capacity;
    this->lsm_level.size = size;
    this->level = level;
    this->nr_degree = nr_degree;
    this->cipher = cipher;

    this->start = start;
    this->bit_nodes = disk_array_create(bm, start, __bit_array_size(capacity, nr_degree), sizeof(struct bit_node));
    if (IS_ERR_OR_NULL(this->bit_nodes)) 
        return -EAGAIN;

    this->lsm_level.iterator = block_index_table_lsm_level_iterator;
    this->lsm_level.search = block_index_table_lsm_level_search;
    this->lsm_level.destroy = block_index_table_lsm_level_destroy;

    return 0;
}

struct lsm_level* block_index_table_create(size_t level, size_t capacity, size_t size, size_t nr_degree, struct dm_block_manager* bm, dm_block_t start, struct aead_cipher* cipher) {
    int r;
    struct block_index_table* this;

    this = kzalloc(sizeof(struct block_index_table), GFP_KERNEL);
    if (!this)
        return NULL;
    
    r = block_index_table_init(this, level, capacity, size, nr_degree, bm, start, cipher);
    if (r)
        return NULL;
    
    return &this->lsm_level;
}

void* lsm_tree_set(struct lsm_tree* this, uint32_t key, void* val) {
    return this->memtable->put(this->memtable, key, val);
}

int lsm_tree_get(struct lsm_tree* this, uint32_t key, void* val) {
    int err;
    size_t i;

    for (i = 0; i < this->nr_level; ++i) {
        err = this->levels[i]->search(this->levels[i], key, val);
        if (!err)
            return 0;
    }

    return -ENODATA;
}

void lsm_tree_destroy(struct lsm_tree* this) {
    size_t i;

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->levels)) {
            for (i = 0; i < this->nr_level; ++i) {
                if (!IS_ERR_OR_NULL(this->levels[i]))
                    this->levels[i]->destroy(this->levels[i]);
            }
            kfree(this->levels);
        }
        kfree(this);
    }
}

int lsm_tree_init(struct lsm_tree* this, struct lsm_level_catalogue* catalogue) {
    this->memtable = rbtree_memtable_create(DEFAULT_MEMTABLE_CAPACITY);
    if (!this->memtable)
        return -ENOMEM;

    this->catalogue = catalogue;
    this->nr_level = this->catalogue->nr_level(this->catalogue);
    this->levels = kmalloc(this->nr_level * sizeof(struct lsm_level*), GFP_KERNEL);
    if (!this->levels)
        return -ENOMEM;
    
    this->levels[0] = &this->memtable->lsm_level;
    this->set = lsm_tree_set;
    this->get = lsm_tree_get;
    this->merge = NULL;
    this->destroy = lsm_tree_destroy;
    return 0;
}

struct lsm_tree* lsm_tree_create(struct lsm_level_catalogue* catalogue) {
    int r;
    struct lsm_tree* this;

    this = kmalloc(sizeof(struct lsm_tree), GFP_KERNEL);
    if (!this)
        return NULL;

    r = lsm_tree_init(this, catalogue);
    if (r)
        return NULL;
    
    return this;
}