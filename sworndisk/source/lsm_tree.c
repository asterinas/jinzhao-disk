#include "../include/dm_sworndisk.h"
#include "../include/lsm_tree.h"
#include "../include/segment_buffer.h"

// block index table implementaion
void bit_node_print(struct bit_node* bit_node) {
    size_t i;

    DMINFO("is leaf: %d", bit_node->leaf);
    if (bit_node->leaf) {
        DMINFO("key: %d", bit_node->node.key);
        DMINFO("value: %lld", bit_node->node.record.pba);
        DMINFO("next: %ld", bit_node->node.next.pos);
    } else {
        for (i = 0; i < BIT_DEGREE; ++i) {
            DMINFO("child %ld", i);
            DMINFO("\tkey: %d", bit_node->children[i].key);
            DMINFO("\tpos: %ld", bit_node->children[i].pointer.pos);
        }
    }
}

// block index table iterator implementaion
bool bit_iterator_has_next(struct iterator* iterator) {
    struct bit_iterator* this = container_of(iterator, struct bit_iterator, iterator);

    return this->node->next.pos != 0;
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

    bit_node = this->bit->bit_nodes->get(this->bit->bit_nodes, this->node->next.pos);
    if (!bit_node)
        return NULL;
    
    *this->node = bit_node->node;
    entry = __entry(bit_node->node.key, &this->node->record);
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
    size_t height = 0;

    while(capacity) {
        height += 1;
        capacity /= nr_degree;
    }

    if (capacity % nr_degree)
        height += 1;

    return height;
}

struct bit_node __bit_leaf(struct bit_leaf* leaf) {
    struct bit_node bit_node = {
        .leaf = true,
        .node = *leaf
    };

    return bit_node;
}

struct bit_node __bit_inner_node(struct bit_generator_slot* slot) {
    size_t i;
    struct bit_node bit_node = {
        .leaf = false
    };

    for (i = 0; i < BIT_DEGREE; ++i) {
        bit_node.children[i].valid = true;
        bit_node.children[i].key = slot->nodes[i].leaf ? slot->nodes[i].node.key : slot->nodes[i].children[BIT_DEGREE-1].key;
        bit_node.children[i].pointer.pos = slot->pointers[i].pos;
    }

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
int bit_generator_add(struct lsm_level_generator* lsm_level_generator, struct entry* entry) {
    int err = 0;
    size_t h = 0, cur;
    struct bit_node leaf_node, bit_node;
    struct bit_leaf leaf = {
        .key = entry->key,
        .record = *((struct record*)entry->val),
    };
    struct bit_generator* this = container_of(lsm_level_generator, struct bit_generator, lsm_level_generator);

    cur = this->pos;
    this->slots[h].pointers[this->slots[h].nr] = __bit_pointer(cur, NULL, NULL, NULL);
    leaf_node = __bit_leaf(&leaf);
    this->slots[h].nodes[this->slots[h].nr] = leaf_node;
    
    this->pos += 1;
    this->slots[h].nr += 1;
    while(this->slots[h].nr == BIT_DEGREE) {
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

    leaf_node.node.next.pos = this->pos;
    return this->bit->bit_nodes->set(this->bit->bit_nodes, cur, &leaf_node);
}

void bit_generator_destroy(struct lsm_level_generator* lsm_level_generator) {
    struct bit_generator* this = container_of(lsm_level_generator, struct bit_generator, lsm_level_generator);

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->slots))
            kfree(this->slots);
        kfree(this);
    }
}

int bit_generator_init(struct bit_generator* this, struct block_index_table* bit) {
    int err = 0;
    
    this->bit = bit;
    this->capacity = bit->lsm_level.capacity;
    this->pos = 0;
    this->height = __bit_height(this->capacity, bit->nr_degree);
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

struct lsm_level_generator* bit_generator_create(struct block_index_table* bit) {
    int err;
    struct bit_generator* this;

    this = kzalloc(sizeof(struct bit_generator), GFP_KERNEL);
    if (!this)
        return NULL;
    
    err = bit_generator_init(this, bit);
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

    if (bit_node->leaf) {
        *first = bit_node->node;
        goto exit;
    } else {
        if (!bit_node->children[0].valid) {
            kfree(first);
            first = NULL;
            goto exit;
        }

        cur = bit_node->children[0].pointer.pos;
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

    if (bit_node->leaf) {
        if (bit_node->node.key != key) {
            err = -ENODATA;
            goto exit;
        }
        *(struct record*)val = bit_node->node.record;
        goto exit;
    } else {
        for (i = 0; i < this->nr_degree; ++i) {
            if (!bit_node->children[i].valid) {
                err = -ENODATA;
                goto exit;
            }

            if (key <= bit_node->children[i].key) {
                cur = bit_node->children[i].pointer.pos;
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

int block_index_table_init(struct block_index_table* this, size_t capacity, size_t nr_degree, struct dm_block_manager* bm, dm_block_t start, struct aead_cipher* cipher) {
    this->lsm_level.capacity = capacity;
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

struct lsm_level* block_index_table_create(size_t capacity, size_t nr_degree, struct dm_block_manager* bm, dm_block_t start, struct aead_cipher* cipher) {
    int r;
    struct block_index_table* this;

    this = kzalloc(sizeof(struct block_index_table), GFP_KERNEL);
    if (!this)
        return NULL;
    
    r = block_index_table_init(this, capacity, nr_degree, bm, start, cipher);
    if (r)
        return NULL;
    
    return &this->lsm_level;
}