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

exit:
    if (file)
        filp_close(file, NULL);
    if (builder)
        builder->destroy(builder);
    return err;
}