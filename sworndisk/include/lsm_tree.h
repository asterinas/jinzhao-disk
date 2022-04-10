#ifndef SWORNDISK_LSM_TREE_H
#define SWORNDISK_LSM_TREE_H

#include "metadata.h"
#include "crypto.h"
#include "disk_structs.h"

// record, lba => (pba, key, iv, mac)
struct record {
    dm_block_t pba; // physical block address
    char *mac;
    char *key;
    char *iv;
};  

struct record* record_create(dm_block_t pba, char* key, char* iv, char* mac);
void record_destroy(void* record);

struct entry {
    uint32_t key;
    void* val;
};  

struct entry* __entry(uint32_t key, void* val);

struct iterator {
    bool (*has_next)(struct iterator* iterator);
    void* (*next)(struct iterator* iterator);
    void (*destroy)(struct iterator* iterator);
};

struct lsm_level {
    size_t size, capacity;

    struct iterator* (*iterator)(struct lsm_level* lsm_level);
    int (*search)(struct lsm_level* lsm_level, uint32_t key, void* val);
    void (*destroy)(struct lsm_level* lsm_level);
};

#define BIT_DEGREE 4
struct bit_pointer {
    size_t pos;
    char key[AES_GCM_KEY_SIZE];
    char iv[AES_GCM_IV_SIZE];
    char mac[AES_GCM_AUTH_SIZE];
} __packed;

struct bit_child {
    uint32_t key;
    struct bit_pointer pointer;
} __packed;

struct bit_leaf {
    uint32_t key;
    struct record record;
    struct bit_pointer next;
} __packed;

struct bit_inner {
    size_t nr_child;
    struct bit_child children[BIT_DEGREE];
};

struct bit_node {
    bool is_leaf: 1;
    union {
        struct bit_leaf leaf;
        struct bit_inner inner;
    };
} __packed;

void bit_node_print(struct bit_node* bit_node);

struct bit_iterator {
    struct bit_leaf* node;
    struct block_index_table* bit;
    struct iterator iterator;
};

struct lsm_level_generator {
    int (*add)(struct lsm_level_generator* lsm_level_generator, struct entry* entry);
    void (*destroy)(struct lsm_level_generator* lsm_level_generator);
};

struct bit_generator_slot {
    size_t nr;
    struct bit_pointer pointers[BIT_DEGREE];
    struct bit_node nodes[BIT_DEGREE];
};

struct block_index_table {
    struct lsm_level lsm_level;
    size_t nr_degree, root;
    dm_block_t start;
    struct disk_array* bit_nodes;
    struct aead_cipher* cipher;
};
struct lsm_level* block_index_table_create(size_t capacity, size_t size, size_t nr_degree, struct dm_block_manager* bm, dm_block_t start, struct aead_cipher* cipher);

struct bit_generator {
    struct lsm_level_generator lsm_level_generator;
    size_t size, nr, height, pos;
    struct bit_generator_slot* slots;
    struct block_index_table* bit;
};

struct lsm_level_generator* bit_generator_create(struct block_index_table* bit, size_t size);

struct lsm_tree {
    size_t nr_level;
    struct lsm_level* levels;

    int (*set)(struct lsm_tree* this, uint32_t key, void* val);
    int (*get)(struct lsm_tree* this, uint32_t key, void* val);
    int (*merge)(struct lsm_tree* this, size_t upper, size_t lower);
};


void block_index_table_iterator_test(struct dm_block_manager* bm);

#endif