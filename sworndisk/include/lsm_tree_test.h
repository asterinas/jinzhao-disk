#ifndef SWORNDISK_LSM_TREE_TEST_H
#define SWORNDISK_LSM_TREE_TEST_H

#include "lsm_tree.h"

int block_index_table_builder_test(void);
int block_index_table_search_test(void);
int block_index_table_iterator_test(void);
int block_index_table_add_file_test(void);
int block_index_table_level_locate_file_test(void);
int block_index_table_level_search_test(void);
int block_index_table_get_first_and_last_key_test(void);
int block_index_table_level_find_relative_files_test(void);
int block_index_table_catalogue_test(struct lsm_catalogue* catalogue);
int compaction_job_run_test(struct lsm_catalogue* catalogue);
int lsm_tree_test(struct lsm_catalogue* catalogue, struct aead_cipher* cipher);

#endif