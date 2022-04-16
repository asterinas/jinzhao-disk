#ifndef SWORNDISK_LSM_TREE_H
#define SWORNDISK_LSM_TREE_H

#include <linux/fs.h>
#include <linux/list.h>

#include "crypto.h"
#include "disk_structs.h"
#include "hashmap.h"

#define DEFAULT_LSM_TREE_NR_LEVEL 2
#define DEFAULT_LSM_FILE_CAPACITY 65536

size_t __bit_array_len(size_t capacity, size_t nr_degree);

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

struct entry __entry(uint32_t key, void* val);

struct iterator {
    bool (*has_next)(struct iterator* iterator);
    int (*next)(struct iterator* iterator, void* data);
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
    struct list_head node;

    struct iterator* (*iterator)(struct lsm_file* lsm_file);
    uint32_t (*get_first_key)(struct lsm_file* lsm_file);
    uint32_t (*get_last_key)(struct lsm_file* lsm_file);
    int (*search)(struct lsm_file* lsm_file, uint32_t key, void* val);
    void* (*get_stats)(struct lsm_file* lsm_file);
    void (*destroy)(struct lsm_file* lsm_file);
};

struct bit_file {
    struct lsm_file lsm_file;

    struct file* file;
    loff_t root;
    size_t id, level;
    uint32_t first_key, last_key;
};

struct lsm_file* bit_file_create(struct file* file, loff_t root, size_t id, size_t level, uint32_t first_key, uint32_t last_key);

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
    bool has_first_key;
    uint32_t first_key, last_key;
    size_t cur, height, id, level;
    void* buffer;
    struct bit_builder_context* ctx;
};

struct lsm_file_builder* bit_builder_create(struct file* file, size_t begin, size_t id, size_t level);

struct lsm_level {
    bool (*is_full)(struct lsm_level* lsm_level);
    int (*add_file)(struct lsm_level* lsm_level, struct lsm_file* file);
    int (*remove_file)(struct lsm_level* lsm_level, size_t id);
    int (*search)(struct lsm_level* lsm_level, uint32_t key, void* val);
    struct lsm_file* (*pick_demoted_file)(struct lsm_level* lsm_level);
    int (*find_relative_files)(struct lsm_level* lsm_level, struct lsm_file* file, struct list_head* relatives);
    void (*destroy)(struct lsm_level* lsm_level);
};

struct bit_level {
    struct lsm_level lsm_level;

    size_t capacity, size, max_size;
    struct bit_file** bit_files;
};

struct lsm_catalogue {
    loff_t start;
    size_t nr_disk_level, common_ratio, max_level_nr_file, total_file;

    int (*alloc_file)(struct lsm_catalogue* lsm_catalogue, size_t* fd);
    int (*release_file)(struct lsm_catalogue* lsm_catalogue, size_t fd);
    int (*set_file_stats)(struct lsm_catalogue* lsm_catalogue, size_t fd, void* stats);
    int (*get_file_stats)(struct lsm_catalogue* lsm_catalogue, size_t fd, void* stats);
    int (*get_all_file_stats)(struct lsm_catalogue* lsm_catalogue, struct list_head* stats);
};

struct compaction_job {
    struct list_head* input_files;
    
    int (*run)(struct compaction_job* this);
};

#endif