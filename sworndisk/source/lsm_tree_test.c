#include <linux/random.h>

#include "../include/lsm_tree_test.h"
#include "../include/metadata.h"

// block index table builder test 
int block_index_table_builder_test() {
    int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, begin = 16 * SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder = bit_builder_create(file, begin, 0, 0);
    struct record record = {
        .pba = 0
    };
    struct entry entry = {
        .key = 0,
        .val = &record
    };
    struct bit_node bit_node;
    loff_t pos;


    if (!file) {
        err = -EINVAL;
        goto exit;
    }

    if (!builder) {
        err = -ENOMEM;
        goto exit;
    }

    for (i = 0; i < 65536; ++i) {
        builder->add_entry(builder, &entry);
        entry.key += 1;
    }

    builder->complete(builder);

    for (i = 0; i < __bit_array_len(65536, DEFAULT_BIT_DEGREE); ++i) {
        pos = begin + i * sizeof(struct bit_node);
        kernel_read(file, &bit_node, sizeof(bit_node), &pos);
        // bit_node_print(&bit_node);
    }

exit:
    if (file)
        filp_close(file, NULL);
    if (builder)
        builder->destroy(builder);
    return err;
}

// block index table search test
extern int bit_file_first_leaf(struct bit_file* this, struct bit_leaf* leaf);
extern int bit_file_search(struct lsm_file* lsm_file, uint32_t key, void* val);
int block_index_table_search_test() {
    int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, begin = 16 * SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder = bit_builder_create(file, begin, 0, 0);
    struct record record = {
        .pba = 100
    };
    struct entry entry = {
        .key = 0,
        .val = &record
    };
    struct bit_file* bit_file;
    // struct bit_leaf leaf;

    if (!file) {
        err = -EINVAL;
        goto exit;
    }

    if (!builder) {
        err = -ENOMEM;
        goto exit;
    }

    for (i = 0; i < 65533; ++i) {
        builder->add_entry(builder, &entry);
        entry.key += 1;
        record.pba += 1;
        entry.val = &record;
    }

    bit_file = container_of(builder->complete(builder), struct bit_file, lsm_file);
    for (i = 0; i < 65536; ++i) {
        err = bit_file_search(&bit_file->lsm_file, i, &record);
        if (!err)
            DMINFO("pba: %lld", record.pba);
    }

exit:
    if (file)
        filp_close(file, NULL);
    if (builder)
        builder->destroy(builder);
    return err;
}

// block index table iterator test
int block_index_table_iterator_test() {
    int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, begin = 16 * SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder = bit_builder_create(file, begin, 0, 0);
    struct record record = {
        .pba = 100
    };
    struct entry entry = {
        .key = 0,
        .val = &record
    };
    struct lsm_file* bit_file;
    struct iterator* iter;

    if (!file) {
        err = -EINVAL;
        goto exit;
    }

    if (!builder) {
        err = -ENOMEM;
        goto exit;
    }

    for (i = 0; i < 60007; ++i) {
        builder->add_entry(builder, &entry);
        entry.key += 1;
        record.pba += 1;
        entry.val = &record;
    }

    bit_file = builder->complete(builder);
    iter = bit_file->iterator(bit_file);
    while(iter->has_next(iter)) {
        iter->next(iter, &entry);
        DMINFO("entry key: %d", entry.key);
    }
    iter->destroy(iter);
    bit_file->destroy(bit_file);

exit:
    if (file)
        filp_close(file, NULL);
    if (builder)
        builder->destroy(builder);
    return err;
}

// block index table add file test
extern struct lsm_level* bit_level_create(size_t capacity);
extern int64_t bit_file_cmp(struct bit_file* file1, struct bit_file* file2);
int block_index_table_add_file_test() {
    size_t capacity = 65536, i;
    struct lsm_file* file;
    struct lsm_level* level = bit_level_create(capacity);
    struct bit_level* bit_level = container_of(level, struct bit_level, lsm_level);
    uint32_t first_key, last_key;

    for (i = 0; i < (capacity << 1); ++i) {
        get_random_bytes(&first_key, sizeof(first_key));
        get_random_bytes(&last_key, sizeof(last_key));
        file = bit_file_create(NULL, 0, 0, 0, first_key, last_key);
        level->add_file(level, file);
    }

    for (i = 0; i < bit_level->size; ++i) {
        DMINFO("first key: %u, last key: %u", 
          bit_level->bit_files[i]->first_key, bit_level->bit_files[i]->last_key);
        if (i > 1 && bit_file_cmp(bit_level->bit_files[i-1], bit_level->bit_files[i]) > 0)
            DMINFO("bit file array hasn't sorted");
    }

    return 0;
}