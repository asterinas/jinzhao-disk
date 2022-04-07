#include "../include/lsm_tree.h"

// block index table iterator implementaion
bool bit_iterator_has_next(struct iterator* iterator) {
    struct bit_iterator* this = container_of(iterator, struct bit_iterator, iterator);

    return this->node->next->pos != 0;
}

void* bit_iterator_next(struct iterator* iterator) {
    struct bit_node* bit_node;
    struct bit_iterator* this = container_of(iterator, struct bit_iterator, iterator);

    bit_node = this->bit->bit_nodes->get(this->bit->bit_nodes, this->node->next->pos);
    if (!bit_node)
        return NULL;
    
    *this->node = bit_node->node;
    kfree(bit_node);
    return &this->node.record;
}

void bit_iterator_destroy(struct iterator* iterator) {
    struct bit_iterator* this = container_of(iterator, struct bit_iterator, iterator);

    if (!IS_ERR_OR_NULL(this)) {
        if (!IS_ERR_OR_NULL(this->node))
            kfree(this->node);
        kfree(this);
    }
}

int bit_iterator_init(struct bit_iterator* this, struct block_index_table* bit, struct bit_leaf_node* first) {
    this->bit = bit;
    this->node = first;
    this->iterator.has_next = bit_iterator_has_next;
    this->iterator.next = bit_iterator_next;
    this->iterator.destroy = bit_iterator_destroy;

    return 0;
}

struct iterator* bit_iterator_create(struct block_index_table* bit, struct bit_leaf_node* first) {
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

// block index table lsm level implementaion
struct bit_leaf_node* block_index_table_first(struct block_index_table* this) {
    size_t cur;
    struct bit_leaf_node* first = NULL;
    struct bit_node* bit_node = NULL;

    first = kmalloc(sizeof(struct bit_leaf_node), GFP_KERNEL);
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
    struct bit_iterator* bit_iterator;
    struct bit_leaf_node* first;
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
        *val = bit_node->node.record;
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

int block_index_table_init(struct block_index_table* this, size_t capacity, size_t nr_degree, struct dm_block_manager* bm, dm_block_t start, struct aead_cipher* cipher) {
    this->lsm_level.capacity = capacity;
    this->nr_degree = nr_degree;
    this->cipher = cipher;

    this->start = start;
    this->bit_nodes = disk_array_create(bm, start, capacity, sizeof(struct bit_node));
    if (IS_ERR_OR_NULL(this->bit_nodes)) 
        return -EAGAIN;

    return 0;
}

struct block_index_table* block_index_table_create(size_t capacity, size_t nr_degree, struct dm_block_manager* bm, dm_block_t start, struct aead_cipher* cipher) {
    int r;
    struct block_index_table* this;

    this = kzalloc(sizeof(struct block_index_table), GFP_KERNEL);
    if (!this)
        return NULL;
    
    r = block_index_table_init(this, capacity, nr_degree, bm, start, cipher);
    if (r)
        return NULL;
    
    return this;
}