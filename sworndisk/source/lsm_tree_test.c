#include "../include/lsm_tree_test.h"
#include "../include/metadata.h"

// block index table builder test 
int block_index_table_builder_test() {
    int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, begin = 16 * SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder = bit_builder_create(file, begin);
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

    for (i = 0; i < 19; ++i) {
        builder->add_entry(builder, &entry);
        entry.key += 1;
    }

    builder->complete(builder);

    for (i = 0; i < __bit_array_len(19, DEFAULT_BIT_DEGREE); ++i) {
        pos = begin + i * sizeof(struct bit_node);
        kernel_read(file, &bit_node, sizeof(bit_node), &pos);
        bit_node_print(&bit_node);
    }

exit:
    if (file)
        filp_close(file, NULL);
    if (builder)
        builder->destroy(builder);
    return err;
}