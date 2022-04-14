#ifndef SWORNDISK_LSM_TREE_H
#define SWORNDISK_LSM_TREE_H

#include <linux/fs.h>

#include "crypto.h"
#include "disk_structs.h"

#define DEFAULT_LSM_TREE_NR_LEVEL 1
#define DEFAULT_LSM_FILE_CAPACITY 65536

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


#define DEFAULT_BIT_DEGREE 4
struct bit_pointer {
    size_t pos;
    char key[AES_GCM_KEY_SIZE];
    char iv[AES_GCM_IV_SIZE];
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
    struct bit_child children[DEFAULT_BIT_DEGREE];
} __packed;

struct bit_node {
    bool is_leaf: 1;
    union {
        struct bit_leaf leaf;
        struct bit_inner inner;
    };
    char mac[AES_GCM_AUTH_SIZE];
} __packed;

void bit_node_print(struct bit_node* bit_node);
size_t __bit_array_len(size_t capacity, size_t nr_degree);

struct lsm_file {
    struct iterator* (*iterator)(struct lsm_file* lsm_file);
    int (*search)(struct lsm_file* lsm_file, uint32_t key, void* data);
    void (*destroy)(struct lsm_file* lsm_file);
};

struct bit_file {
    struct lsm_file lsm_file;

    struct dm_block_manager* bm;
    struct disk_array* nodes;
};

struct lsm_file_builder {
    int (*add_entry)(struct lsm_file_builder* builder, struct entry* entry);
    struct lsm_file* (*complete)(struct lsm_file_builder* builder);
    void (*destroy)(struct lsm_file_builder* builder);
};

struct bit_builder_context {
    size_t nr;
    struct bit_pointer pointers[DEFAULT_BIT_DEGREE];
    struct bit_node nodes[DEFAULT_BIT_DEGREE];
};

struct bit_builder {
    struct lsm_file_builder lsm_file_builder;

    struct file* file;
    loff_t begin;
    size_t cur, height;
    void* buffer;
    struct bit_builder_context* ctx;
};

struct lsm_file_builder* bit_builder_create(struct file* file, size_t begin);

struct bit_compactor_job {
       
};

#endif