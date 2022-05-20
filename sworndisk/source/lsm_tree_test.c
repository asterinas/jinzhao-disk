#include <linux/random.h>

#include "../include/lsm_tree_test.h"
#include "../include/metadata.h"

// block index table builder test 
int block_index_table_builder_test() {
    int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, begin = 16 * SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder = bit_builder_create(file, begin, 0, 0, 0);
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
    struct lsm_file_builder* builder = bit_builder_create(file, begin, 0, 0, 0);
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
    struct lsm_file_builder* builder = bit_builder_create(file, begin, 0, 0, 0);
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
        record_destroy(entry.val);
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
extern int64_t bit_file_cmp(struct bit_file* file1, struct bit_file* file2);
int block_index_table_add_file_test() {
    size_t capacity = 100, i;
    struct lsm_file* file;
    struct lsm_level* level = bit_level_create(0, capacity);
    struct bit_level* bit_level = container_of(level, struct bit_level, lsm_level);
    uint32_t first_key, last_key;
    char root_key[AES_GCM_KEY_SIZE], root_iv[AES_GCM_IV_SIZE];

    for (i = 0; i < (capacity << 1); ++i) {
        get_random_bytes(&first_key, sizeof(first_key));
        get_random_bytes(&last_key, sizeof(last_key));
        file = bit_file_create(NULL, 0, 0, 0, 0, first_key, last_key, root_key, root_iv);
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

// block index table level search test
extern struct bit_file* bit_level_locate_file(struct bit_level* this, uint32_t key);
int block_index_table_level_locate_file_test() {
    size_t capacity = 10, i;
    struct lsm_file* file;
    struct bit_file* bit_file;
    struct lsm_level* level = bit_level_create(0, capacity);
    struct bit_level* bit_level = container_of(level, struct bit_level, lsm_level);
    uint32_t first_key, last_key, key;
     char root_key[AES_GCM_KEY_SIZE], root_iv[AES_GCM_IV_SIZE];

    for (i = 0; i < (capacity << 1); ++i) {
        first_key = 1000 * i;
        last_key = 1000 * (i + 1) - 1;
        file = bit_file_create(NULL, 0, 0, 0, first_key, last_key, 0, root_key, root_iv);
        level->add_file(level, file);
    }

    for (i = 0; i < 10; ++i) {
        get_random_bytes(&key, sizeof(key));
        bit_file = bit_level_locate_file(bit_level, key % last_key);
        if (bit_file) {
            DMINFO("key: %u, range: %u ~ %u", key % last_key, bit_file->first_key, bit_file->last_key);
        }
    }

    level->destroy(level);
    return 0;
}

// block index table level search test
int block_index_table_level_search_test() {
    size_t capacity = 10;
    struct lsm_level* level = bit_level_create(0, capacity);
    // struct bit_level* bit_level = container_of(level, struct bit_level, lsm_level);
    int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, j, begin = 16 * SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder;
    struct record record = {
        .pba = 100
    };
    struct entry entry = {
        .key = 0,
        .val = &record
    };
    struct lsm_file* bit_file;

    if (!file) {
        err = -EINVAL;
        goto exit;
    }

    for (j = 0; j < 6; ++j) {
        builder = bit_builder_create(file, begin, j, 0, 0);
        begin += __bit_array_len(DEFAULT_LSM_FILE_CAPACITY, DEFAULT_BIT_DEGREE) * sizeof(struct bit_node);

        for (i = 0; i < 60007; ++i) {
            builder->add_entry(builder, &entry);
            entry.key += 1;
            record.pba += 1;
            entry.val = &record;
        }

        bit_file = builder->complete(builder);
        level->add_file(level, bit_file);
    }

    level->remove_file(level, 0);
    level->remove_file(level, 2);
    level->remove_file(level, 4);
    level->remove_file(level, 6);
    level->remove_file(level, 8);

    for (i = 0; i < entry.key; i += 10000) {
        err = level->search(level, i, &record);
        if (!err)
            DMINFO("key: %ld, pba: %lld", i, record.pba);
    }

    // for (i = 0; i < bit_level->size; ++i) {
    //     DMINFO("first key: %u, last key: %u", 
    //       bit_level->bit_files[i]->first_key, bit_level->bit_files[i]->last_key);
    // }

exit:
    if (file)
        filp_close(file, NULL);
    if (level)
        level->destroy(level);
    return err;
}

// block index table get first & last key test
int block_index_table_get_first_and_last_key_test() {
     int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, begin = 16 * SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder = bit_builder_create(file, begin, 0, 0, 0);
    struct record record = {
        .pba = 100
    };
    struct entry entry = {
        .key = 0,
        .val = &record
    };
    struct lsm_file* bit_file = NULL;
    // struct bit_leaf leaf;

    if (!file) {
        err = -EINVAL;
        goto exit;
    }

    if (!builder) {
        err = -ENOMEM;
        goto exit;
    }

    for (i = 3000; i < 60006; ++i) {
        entry.key = i;
        builder->add_entry(builder, &entry);
        record.pba += 1;
        entry.val = &record;
    }

    bit_file = builder->complete(builder);
    DMINFO("first key: %u, last key: %u", bit_file->get_first_key(bit_file), bit_file->get_last_key(bit_file));
exit:
    if (file)
        filp_close(file, NULL);
    if (builder)
        builder->destroy(builder);
    if (bit_file)
        bit_file->destroy(bit_file);
    return err;
}

// block index table level find relative files test 
int block_index_table_level_find_relative_files_test() {
    size_t capacity = 10;
    struct lsm_level* level = bit_level_create(0, capacity);
    // struct bit_level* bit_level = container_of(level, struct bit_level, lsm_level);
    int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, j, begin = 16 * SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder;
    struct record record = {
        .pba = 100
    };
    struct entry entry = {
        .key = 0,
        .val = &record
    };
    struct lsm_file *bit_file, *bit_file_cursor;
    struct list_head relatives, demoted_files;

    if (!file) {
        err = -EINVAL;
        goto exit;
    }

    for (j = 0; j < 6; ++j) {
        builder = bit_builder_create(file, begin, j, 0, 0);
        begin += __bit_array_len(DEFAULT_LSM_FILE_CAPACITY, DEFAULT_BIT_DEGREE) * sizeof(struct bit_node);

        for (i = 0; i < 60007; ++i) {
            builder->add_entry(builder, &entry);
            entry.key += 1;
            record.pba += 1;
            entry.val = &record;
        }

        bit_file = builder->complete(builder);
        level->add_file(level, bit_file);
    }

    level->remove_file(level, 0);
    level->remove_file(level, 1);
    // level->remove_file(level, 2);
    // level->remove_file(level, 3);
    // level->remove_file(level, 4);
    // level->remove_file(level, 5);
    level->remove_file(level, 6);

    builder = bit_builder_create(file, begin, j, 0, 0);
    for (i = 65000; i < 300000; ++i) {
        entry.key = i;
        builder->add_entry(builder, &entry);
        record.pba += 1;
        entry.val = &record;
    }

    bit_file = builder->complete(builder);
    DMINFO("bit file range: %u ~ %u", bit_file->get_first_key(bit_file), bit_file->get_last_key(bit_file));
    INIT_LIST_HEAD(&demoted_files);
    list_add_tail(&bit_file->node, &demoted_files);
    level->find_relative_files(level, &demoted_files, &relatives);
    list_for_each_entry(bit_file_cursor, &relatives, node) {
        DMINFO("\trelative: %u ~ %u", bit_file_cursor->get_first_key(bit_file_cursor), bit_file_cursor->get_last_key(bit_file_cursor));
    }
    bit_file->destroy(bit_file);
exit:
    if (file)
        filp_close(file, NULL);
    if (level)
        level->destroy(level);
    return err;
}

// block index table catalogue test
int block_index_table_catalogue_test(struct lsm_catalogue* catalogue) {
    size_t fd, i;
    struct list_head stats;
    struct file_stat info, *pinfo;

    for (i = 0; i < catalogue->total_file; ++i) {
        catalogue->alloc_file(catalogue, &fd);
        info.id = fd;
        catalogue->set_file_stats(catalogue, i, info);
    }

    for (i = 0; i < catalogue->total_file; i += 2) {
        catalogue->release_file(catalogue, i);
    }

    catalogue->get_all_file_stats(catalogue, &stats);
    list_for_each_entry(pinfo, &stats, node) {
        DMINFO("fd: %ld", pinfo->id);
    }

    for (i = 0; i < catalogue->total_file; ++i) {
        catalogue->get_file_stats(catalogue, i, &info);
        DMINFO("fd: %ld", info.id);
    }

    return 0;
}

// compaction job run test 
int compaction_job_run_test(struct lsm_catalogue* catalogue) {
    size_t capacity = 10, fd;
    struct lsm_level* level1 = bit_level_create(0, capacity);
    struct lsm_level* level2 = bit_level_create(1, capacity);
    // struct bit_level* bit_level = container_of(level, struct bit_level, lsm_level);
    int err = 0;
    const char* filename = "/dev/sdb5";
    struct file* file = filp_open(filename, O_RDWR, 0);
    size_t i, j, begin = SWORNDISK_METADATA_BLOCK_SIZE;
    struct lsm_file_builder* builder = NULL;
    struct record record = {
        .pba = 100
    };
    struct entry entry = {
        .key = 0,
        .val = &record
    };
    struct lsm_file* bit_file = NULL;
    struct compaction_job* compaction_job = NULL;

    if (!file) {
        err = -EINVAL;
        goto exit;
    }

    catalogue->alloc_file(catalogue, &fd);
    builder = bit_builder_create(file, begin + fd * catalogue->file_size, fd, 1, catalogue->get_next_version(catalogue));
    for (i = 0; i < 60007; ++i) {
        entry.key = i;
        record.pba = i + 100;
        entry.val = &record;
        builder->add_entry(builder, &entry);
    }
    bit_file = builder->complete(builder);
    // DMINFO("file version: %ld", bit_file->version);
    level2->add_file(level2, bit_file);
    builder->destroy(builder);

    entry.key = 0;
    for (j = 0; j < 6; ++j) {
        catalogue->alloc_file(catalogue, &fd);
        builder = bit_builder_create(file, begin + fd * catalogue->file_size, fd, 0, catalogue->get_next_version(catalogue));

        for (i = 0; i < 60007; ++i) {
            record.pba = entry.key;
            entry.val = &record;
            builder->add_entry(builder, &entry);
            entry.key += 1;
        }

        bit_file = builder->complete(builder);
        // DMINFO("file version: %ld", bit_file->version);
        // info = bit_file->get_stats(bit_file);
        // DMINFO("id: %ld, level: %ld, root: %lld, first key: %u, last key: %u", 
        //   info->id, info->level, info->root, info->first_key, info->last_key);
        // kfree(info);
        level1->add_file(level1, bit_file);
    }

    for (i = 0; i < 500000; i += 10000) {
        err = level1->search(level1, i, &record);
        if (!err)
            DMINFO("lba: %ld, pba: %lld", i, record.pba);
    }

    compaction_job = compaction_job_create(file, catalogue, level1, level2);
    compaction_job->run(compaction_job);

    // for (i = 0; i < 500000; i += 10000) {
    //     err = level2->search(level2, i, &record);
    //     if (!err)
    //         DMINFO("lba: %ld, pba: %lld", i, record.pba);
    // }

exit:
    if (file)
        filp_close(file, NULL);
    if (level1)
        level1->destroy(level1);
    if (level2)
        level2->destroy(level2);
    if (compaction_job)
        compaction_job->destroy(compaction_job);
    return err;
}

// lsm tree test 
int lsm_tree_test(struct lsm_catalogue* catalogue, struct aead_cipher* cipher) {
    const char* filename = "/dev/sdb5";
    size_t i;
    struct record *record, result;
    struct lsm_tree* lsm_tree = lsm_tree_create(filename, catalogue, cipher);

    for (i = 0; i < 1048576; ++i) {
        record = record_create(i, NULL, NULL, NULL);
        lsm_tree->put(lsm_tree, i, record);
    }

    for (i = 0; i < 1048576; i += 10000) {
        lsm_tree->search(lsm_tree, i, &result);
        DMINFO("lba: %ld, pba: %lld", i, result.pba);
    }

    lsm_tree->destroy(lsm_tree);

    return 0;
}