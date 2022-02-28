/*
 * This module creates target for linear device mapper which maps a linear range of the device-mapper
 * device onto a linear range of another device.
 *
 * See http://narendrapal2020.blogspot.com/2014/03/device-mapper.html and
 * http://techgmm.blogspot.com/p/writing-your-own-device-mapper-target.html.
 *
 * Test on linux kernel 2.6.32.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sort.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/jiffies.h>
#include <linux/init.h>
#include <linux/mempool.h>
#include <linux/rwsem.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h> 
#include <linux/bitmap.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>
#include <linux/vmalloc.h>

#include "persistent-data/dm-bitset.h"
#include "dm.h"
#include "dm-sworndisk-metadata.h"

#define DM_MSG_PREFIX "sworndisk"

#define SD_BLOCK_SIZE 4096 // SwornDisk Block Size
#define SD_SECTOR_SIZE 512
#define NR_SEGMENT 4096
#define SEC_PER_BLK 8
#define BLK_PER_SEG 64
#define SEC_PER_SEG (SEC_PER_BLK*BLK_PER_SEG)

struct hashmap {
    int bucket_num;
    struct hlist_head *hlists;
};

struct hashmap_value {
    int key;
    int data;
    struct hlist_node node;
};

void hashmap_init(struct hashmap* map, int bits);
void hashmap_destroy(struct hashmap* map);
void hashmap_add(struct hashmap* map, int key, int data);
bool hashmap_delete(struct hashmap* map, int key);
void test_hashmap(void);
bool hashmap_exists(struct hashmap* map, int key);
int hashmap_getval(struct hashmap* map, int key, int *result);

int get_bucket(int key, int bucket_num);

#define HASHMAP_BUCKET_NUM 65536
void hashmap_init(struct hashmap* map, int bucket_num) {
    int i;

    map->bucket_num = bucket_num;
    map->hlists = (struct hlist_head*)vmalloc(sizeof(struct hlist_head)*bucket_num);
    for(i=0; i<bucket_num; ++i) {
        INIT_HLIST_HEAD(&map->hlists[i]);
    }
}

void hashmap_destroy(struct hashmap* map) {
    vfree(map->hlists);
}

void hashmap_add(struct hashmap* map, int key, int data) {
    struct hashmap_value* value = (struct hashmap_value*)vmalloc(sizeof(struct hashmap_value));

    hashmap_delete(map, key);
    value->key = key;
    value->data = data;
    hlist_add_head(&value->node, &map->hlists[get_bucket(key, map->bucket_num)]);
}

int get_bucket(int key, int bucket_num) {
    return key % bucket_num;
}

bool hashmap_exists(struct hashmap* map, int key) {
    struct hashmap_value* obj;

    hlist_for_each_entry(obj, &map->hlists[get_bucket(key, map->bucket_num)], node) {
        if(obj->key == key) 
            return true;
    }
    return false;
}

bool hashmap_delete(struct hashmap* map, int key) {
    struct hashmap_value* obj;

    hlist_for_each_entry(obj, &map->hlists[get_bucket(key, map->bucket_num)], node) {
        if(obj->key == key) {
            hlist_del_init(&obj->node);
            return true;
        }
    }

    return false;
}

int hashmap_getval(struct hashmap* map, int key, int *result) {
    struct hashmap_value* obj;

    hlist_for_each_entry(obj, &map->hlists[get_bucket(key, map->bucket_num)], node) {
        if(obj->key == key) {
            *result = obj->data;
            return 0;
        }
    }

    return -ENODATA;
}

struct memtable {
    struct hashmap map;

    void (*put)(struct memtable* mt, int lsa, int psa);
    int (*get)(struct memtable* mt, int lsa, int *psa);
    bool (*contains)(struct memtable* mt, int lsa);
    void (*write)(struct memtable* mt, int lsa, int psa, unsigned int nr_sector);
};

void memtable_put(struct memtable* mt, int lsa, int psa) {
    // DMINFO("mem put");
    hashmap_add(&mt->map, lsa, psa);
}

int memtable_get(struct memtable* mt, int lsa, int *psa) {
    // DMINFO("mem get");
    int r;

    r = hashmap_getval(&mt->map, lsa, psa);
    if (r)
        return r;
    return 0;
}

bool memtable_contains(struct memtable* mt, int lsa) {
    return hashmap_exists(&mt->map, lsa);
}

void memtable_write(struct memtable* mt, int lsa, int psa, unsigned int nr_sector) {
    int i;

    for (i=0; i<nr_sector; ++i) {
        mt->put(mt, lsa+i, psa+i);
    }
}

void memtable_init(struct memtable* mt) {
    hashmap_init(&mt->map, HASHMAP_BUCKET_NUM);
    mt->put = memtable_put;
    mt->get = memtable_get;
    mt->contains = memtable_contains;
    mt->write = memtable_write;
}

struct lsm_tree {

};

struct segment_allocator {
    struct dm_sworndisk_metadata *cmd;
    unsigned int nr_segment;
    unsigned int cur_segment;
    unsigned int cur_sector;

    int (*get_next_free_segment)(struct segment_allocator* al);
    int (*alloc_sectors)(struct segment_allocator* al, struct bio* bio, int *psa, unsigned int *nr_sector, bool *should_flush);
    int (*write_reverse_index_table)(struct segment_allocator* al, int psa, int lsa, int nr_sector);
    void (*clean)(struct segment_allocator* al);
};

struct segment_buffer {
    spinlock_t lock;
    struct bio_list bios;
    struct segment_allocator sa;
    struct memtable mt;

    int (*push_bio)(struct segment_buffer* buf, struct bio *bio);
    void (*flush_bios)(struct segment_buffer* buf);
};

/* For underlying device */
struct dm_sworndisk_target {
    struct dm_dev *data_dev;
    struct dm_dev *metadata_dev;
    // struct dm_dev *origin_dev;
    sector_t start;
    struct workqueue_struct *wq;
	struct work_struct migration_worker;
    struct work_struct deferred_indexfind_worker;
    struct work_struct deferred_bio_worker;
    struct bio_list deferred_indexfind_bios;
    struct bio_list deferred_bios;
	struct dm_sworndisk_metadata *cmd;
    struct segment_buffer seg_buffer;
    spinlock_t lock;
    sector_t sstlen;
    int pba_tail;

    // struct delayed_work segment_background_cleaning_work;
};

unsigned int bio_get_sector(struct bio *bio) {
    return bio->bi_iter.bi_sector;
}

void bio_set_sector(struct bio *bio, unsigned int sector) {
    bio->bi_iter.bi_sector = sector;
}

unsigned int sector_2_block(unsigned int sector) {
    return sector / SEC_PER_BLK;
}

unsigned int block_2_segment(unsigned int block) {
    return block / BLK_PER_SEG;
}

unsigned int sector_2_segment(unsigned int sector) {
    return block_2_segment(sector_2_block(sector));
}

int segbuf_push_bio(struct segment_buffer* buf, struct bio *bio) {
    int r;
    int lsa;
    int psa;
    unsigned int nr_sector;
    unsigned long flags;
    bool should_flush;

    // spin_lock_irqsave(&buf->lock, flags);

    r = buf->sa.alloc_sectors(&buf->sa, bio, &psa, &nr_sector, &should_flush);
    if (r) {
        DMINFO("alloc_sectors error");
        return r;
    }
        

    // if (should_flush) 
        // buf->flush_bios(buf);


    // rediret bio
    lsa = bio_get_sector(bio);

    // DMINFO("lsa: %d, psa: %d, nr_sector: %d", lsa, psa, nr_sector);
    bio_set_sector(bio, psa);
    // update block index tree

    buf->mt.write(&buf->mt, lsa, psa, nr_sector);
    // DMINFO("write memtable, lsa: %d, psa: %d", lsa, psa);

    // update reverse index table
    buf->sa.write_reverse_index_table(&buf->sa, psa, lsa, nr_sector);
    // DMINFO("write rit, psa: %d, lsa:%d", psa, lsa);

	bio_list_add(&buf->bios, bio);
	// spin_unlock_irqrestore(&buf->lock, flags);

    buf->flush_bios(buf);
    return 0;
}

void segbuf_flush_bios(struct segment_buffer* buf) {
    struct bio *bio;
    unsigned long flags;

    // spin_lock_irqsave(&buf->lock, flags);
    while ((bio = bio_list_pop(&buf->bios))) {
        // DMINFO("flush bio, psa: %d", bio_get_sector(bio));
        submit_bio(bio);
    }
    // spin_unlock_irqrestore(&buf->lock, flags);
}

void segbuf_init(struct segment_buffer *buf) {
    spin_lock_init(&buf->lock);
    bio_list_init(&buf->bios);
    memtable_init(&buf->mt);

    buf->push_bio = segbuf_push_bio;
    buf->flush_bios = segbuf_flush_bios;
};


int sa_get_next_free_segment(struct segment_allocator* al) {
    int r;
    int seg;

    r = dm_sworndisk_get_first_free_segment(al->cmd, &seg);
    if (r) {
        DMINFO("dm_sworndisk_get_first_free_segment error");
        return -1;
    }

    r = dm_sworndisk_set_svt(al->cmd, seg, true);
    if (r)
        return -1;
    return seg;
}

int sa_alloc_sectors(struct segment_allocator* al, struct bio* bio, int *psa, unsigned int *nr_sector, bool *should_flush) {
    int seg;

    *should_flush = false;
    *nr_sector = bio_sectors(bio) + (bool)(bio->bi_iter.bi_size % SD_SECTOR_SIZE);
    // DMINFO("segment: %d, sector: %d, nr_sector: %d", al->cur_segment, al->cur_sector, *nr_sector);
    if (al->cur_sector + *nr_sector >= SEC_PER_SEG) {
        *should_flush = true;
        seg = al->get_next_free_segment(al);
        if (seg < 0) 
            return seg;
        al->cur_segment = seg;
        al->cur_sector = 0;
    }

    *psa = al->cur_segment*SEC_PER_SEG + al->cur_sector;
    al->cur_sector += *nr_sector;
    return 0;
}

int sa_write_reverse_index_table(struct segment_allocator* al, int lsa, int psa, int nr_sector) {
    int r;
    int i;

    for (i=0; i<nr_sector; ++i) {
        r = dm_sworndisk_rit_insert(al->cmd, psa+i, lsa+i);
        if (r)
            return r;
    }

    return 0;
}

int sa_init(struct segment_allocator* al, struct dm_sworndisk_metadata *cmd, unsigned int nr_segment) {
    al->cmd = cmd;
    al->nr_segment = nr_segment;
    al->cur_sector = 0;
    al->get_next_free_segment = sa_get_next_free_segment;
    al->alloc_sectors = sa_alloc_sectors;
    al->write_reverse_index_table = sa_write_reverse_index_table;
    al->clean = NULL;

    al->cur_segment = al->get_next_free_segment(al);
    if (al->cur_segment < 0)
        return -1;
    return 0;
}

void segment_allocator_test(struct dm_sworndisk_metadata *cmd) {
    int i;
    int r;
    int psa;
    int nr_sector;
    bool should_flush;
    struct bio bio;


    struct segment_allocator al;
    r = sa_init(&al, cmd, NR_SEGMENT);
    if (r)
        DMINFO("segment_allocator init error");

    for (i=0; i<10; ++i) {
        bio.bi_iter.bi_size = 4097;
        al.alloc_sectors(&al, &bio, &psa, &nr_sector, &should_flush);
        DMINFO("psa: %d, nr_sector: %d", psa, nr_sector);
    }
}

struct kv {
    int pba;
    int lba;
};

struct lsm_c0 {
    struct kv *hash_map;
    unsigned int capacity;
    unsigned int size;
    unsigned int max_size;
} c0;

void c0_init(void) 
{
    c0.capacity = 100007;
    c0.max_size = 50000;
    c0.hash_map = kmalloc(sizeof(struct kv) * c0.capacity, GFP_KERNEL);
    memset(c0.hash_map, -1, sizeof(struct kv) * c0.capacity);
    return;
}

void c0_clear(void) 
{
    memset(c0.hash_map, -1, sizeof(struct kv) * c0.capacity);
}

int hash_f(int k) {
    return k % c0.capacity;
}

int c0_find(int lba) {
    int h = hash_f(lba);
    while (c0.hash_map[h].lba != -1 && c0.hash_map[h].lba != lba) {
        h = (h+1)%(c0.capacity);
    }
    
    return c0.hash_map[h].pba;
}

int c0_insert(int lba, struct dm_sworndisk_target *mdt) {
    int h = hash_f(lba);
    while (c0.hash_map[h].lba != -1 && c0.hash_map[h].lba != lba) {
        h = (h+1)%(c0.capacity);
    }

    if (c0.hash_map[h].lba == -1) {
        c0.size++;
    }
    c0.hash_map[h].lba = lba;
    c0.hash_map[h].pba = mdt->pba_tail;   
    mdt->pba_tail++;
    return c0.hash_map[h].pba;
}

int kv_cmp(const void *a,const void *b)
{
    struct kv *da1 = (struct kv *)a;
    struct kv *da2 = (struct kv *)b;
 
    if(da1->lba > da2->lba)
        return 1;
    else if(da1->lba < da2->lba)
        return -1;
    else
        return 0;
}

static void process_migration(struct work_struct *ws)
{
    int i;
    int j = 0;
    struct kv *sst = kmalloc(sizeof(struct kv) * c0.size, GFP_KERNEL);
    for (i = 0; i < c0.capacity; i++)
        if (c0.hash_map[i].lba != -1) {
            sst[j] = c0.hash_map[i];
            j++;
        }
    sort(sst, c0.size, sizeof(struct kv), kv_cmp, NULL);
    kfree(sst);

}



// int linux_kernel_crypto_encrypt(void* data_in_out, int data_len, void* key, int key_len) {
// 	struct crypto_skcipher* cipher;
// 	struct skcipher_request* req;
//     struct crypto_wait wait;
// 	struct scatterlist sg;
//     size_t block_size;
// 	int ret;

//     // 分配算法对象，支持的算法可以在/proc/crypto文件中查看
// 	cipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
// 	if (IS_ERR(cipher)) {
// 		printk("fail to allocate cipher\n");
// 		return -1;
// 	}

//     // skcipher api不支持填充，所以加/解密数据需要为加密块的整数倍
//     block_size = crypto_skcipher_blocksize(cipher);
//     if (data_len % block_size != 0) {
// 		printk("data len not aligned");
// 		return -1;
// 	}

//     // 分配req对象
// 	req = skcipher_request_alloc(cipher, GFP_KERNEL);
// 	if (IS_ERR(req)) {
// 		printk("fail to allocate req\n");
// 		return -1;
// 	}
// 	sg_init_one(&sg, data_in_out, data_len);
// 	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
//     char iv[16] = { 0 };
// 	skcipher_request_set_crypt(req, &sg, &sg, data_len, iv);
// 	ret = crypto_skcipher_setkey(cipher, key, key_len);
//     if ( 0 != ret) {
//         printk("fail to set key, error %d\n", ret);
//         return -1;
//     }
//     // 执行解密操作
// 	ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait); 
// 	if (0 != ret) {
//         printk("decryption error %d\n", ret);
//         return -1;
// 	}
// 	// 释放资源
// 	crypto_free_skcipher(cipher);
// 	skcipher_request_free(req);
// 	//printk("encryption finished");
// 	return 0;
// }

// int linux_kernel_crypto_decrypt(void* data_in_out, int data_len, void* key, int key_len) {
// 	struct crypto_skcipher* cipher;
// 	struct skcipher_request* req;
//     struct crypto_wait wait;
// 	struct scatterlist sg;
//     size_t block_size;
// 	int ret;

//     // 分配算法对象，支持的算法可以在/proc/crypto文件中查看
// 	cipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
// 	if (IS_ERR(cipher)) {
// 		printk("fail to allocate cipher\n");
// 		return -1;
// 	}

//     // skcipher api不支持填充，所以加/解密数据需要为加密块的整数倍
//     block_size = crypto_skcipher_blocksize(cipher);
//     if (data_len % block_size != 0) {
// 		printk("data len not aligned");
// 		return -1;
// 	}

//     // 分配req对象
// 	req = skcipher_request_alloc(cipher, GFP_KERNEL);
// 	if (IS_ERR(req)) {
// 		printk("fail to allocate req\n");
// 		return -1;
// 	}
// 	sg_init_one(&sg, data_in_out, data_len);
// 	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
//     char iv[16] = { 0 };
// 	skcipher_request_set_crypt(req, &sg, &sg, data_len, iv);
// 	ret = crypto_skcipher_setkey(cipher, key, key_len);
//     if ( 0 != ret) {
//         printk("fail to set key, error %d\n", ret);
//         return -1;
//     }
//     // 执行解密操作
// 	ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait); 
// 	if (0 != ret) {
//         printk("decryption error %d\n", ret);
//         return -1;
// 	}
// 	// 释放资源
// 	crypto_free_skcipher(cipher);
// 	skcipher_request_free(req);
// 	//printk("decryption finished");
// 	return 0;
// }


static void defer_bio(struct dm_sworndisk_target *mdt, struct bio *bio)
{
	unsigned long flags;

    // DMINFO("defer bio, lsa: %d", bio_get_sector(bio));
	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_add(&mdt->deferred_bios, bio);
	spin_unlock_irqrestore(&mdt->lock, flags);

	queue_work(mdt->wq, &mdt->deferred_bio_worker);
}

static int findc1(struct dm_sworndisk_target *mdt, int lba) {
    // __le64 lba0, pba;
    // int h, t, m;
    // h = 0; t = mdt->sstlen;
    // while (h <= t) {
    //     m = (h + t) / 2;
	//     dm_cache_read(mdt->cmd, m, &pba);
        
    //     lba0 = pba >> 32;
    //     pba = pba << 32 >> 32;
    //     //DMINFO("%d %llu %llu", m, lba0, pba);
        
    //     if (lba < lba0)
    //         t = m - 1;
    //     else if (lba > lba0)
    //         h = m + 1;
    //     else
    //         return pba;
    // }
    
    return 0;
}

static void process_deferred_indexfind_bios(struct work_struct *ws) {
    struct dm_sworndisk_target *mdt = container_of(ws, struct dm_sworndisk_target, deferred_indexfind_worker);
    unsigned long flags;
	struct bio_list bios;
	struct bio *bio;
    int lba, pba, offset;

	bio_list_init(&bios);

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_merge(&bios, &mdt->deferred_indexfind_bios);
	bio_list_init(&mdt->deferred_indexfind_bios);
	spin_unlock_irqrestore(&mdt->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
        offset = bio->bi_iter.bi_sector % 8;
		lba = bio->bi_iter.bi_sector - offset;
        pba = findc1(mdt, lba);
        bio->bi_iter.bi_sector = pba + offset;
        defer_bio(mdt, bio);
	}

}

static void defer_indexfind_bio(struct dm_sworndisk_target *mdt, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_add(&mdt->deferred_indexfind_bios, bio);
	spin_unlock_irqrestore(&mdt->lock, flags);

    queue_work(mdt->wq, &mdt->deferred_indexfind_worker);
}

static void process_deferred_bios(struct work_struct *ws)
{
	struct dm_sworndisk_target *mdt = container_of(ws, struct dm_sworndisk_target, deferred_bio_worker);

	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_merge(&bios, &mdt->deferred_bios);
	bio_list_init(&mdt->deferred_bios);
	spin_unlock_irqrestore(&mdt->lock, flags);

	while ((bio = bio_list_pop(&bios))) {
        mdt->seg_buffer.push_bio(&mdt->seg_buffer, bio);
	}
}

static int dm_sworndisk_target_map(struct dm_target *target, struct bio *bio)
{
    int r;
    int lsa, psa;
    struct dm_sworndisk_target *mdt = target->private;

    lsa = bio_get_sector(bio);
    bio_set_dev(bio, mdt->data_dev->bdev);

    if (bio_op(bio) == REQ_OP_WRITE) {
        defer_bio(mdt, bio);
        return DM_MAPIO_SUBMITTED;
    }

    if (bio_op(bio) == REQ_OP_READ) {
        r = mdt->seg_buffer.mt.get(&mdt->seg_buffer.mt, lsa, &psa);
        if (r)
            goto exit;
        bio_set_sector(bio, psa);
        submit_bio(bio);
        return DM_MAPIO_SUBMITTED;
    }

exit:
    return DM_MAPIO_REMAPPED;
}

// static int dm_sworndisk_target_map(struct dm_target *target, struct bio *bio)
// {
//     struct dm_sworndisk_target *mdt = target->private;
//     int lba, pba, offset;
//     /*  bio should perform on our underlying device   */
//     lba = bio->bi_iter.bi_sector;
//     bio_set_dev(bio, mdt->data_dev->bdev);

//     if (bio_op(bio) == REQ_OP_WRITE) {
//         //bio_set_dev(bio, mdt->data_dev->bdev);
//         offset = lba % 8;
//         lba -= offset;
//         pba = c0_insert(lba, mdt);
//         bio->bi_iter.bi_sector = pba * 8 + offset;
//         // DMINFO("bio->bi_size: %d", bio->bi_iter.bi_size);
//         defer_bio(mdt, bio);
//         if (c0.size > c0.max_size)
//             queue_work(mdt->wq, &mdt->migration_worker);
//         return DM_MAPIO_SUBMITTED;
//     }

//     if (bio_op(bio) == REQ_OP_READ) {
//         offset = lba % 8;
//         pba = c0_find(lba - offset);
//         if (pba != -1) {
//             // DMINFO("????");
//             //bio_set_dev(bio, mdt->data_dev->bdev);
//             bio->bi_iter.bi_sector = pba * 8 + offset;
//             defer_bio(mdt, bio);
//         }
//         else {
//             defer_indexfind_bio(mdt, bio);
//         }
//         return DM_MAPIO_SUBMITTED;
//     }
    
//     // DMINFO("Exit : %s", __func__);
//     return DM_MAPIO_REMAPPED;
// }

void test_get_first_free_seg(struct dm_sworndisk_target *mdt) {
    int i, seg, r;
    
    for (i=0; i<20; ++i) {
        r = dm_sworndisk_get_first_free_segment(mdt->cmd, &seg);
        if (r) 
            DMINFO("get first free segment err");
        DMINFO("next free segment: %d", seg);
        r = dm_sworndisk_set_svt(mdt->cmd, i, true);
        if (r) 
            DMINFO("dm_sworndisk_set_svt err");
    }
}

void dm_sworndisk_rit_test(struct dm_sworndisk_target *mdt) {
    int i, r, lba;

    for (i=0; i<10; ++i) {
        r = dm_sworndisk_rit_insert(mdt->cmd, i, i*10);
        if (r)
            DMINFO("dm_sworndisk_rit_insert err");
    }

    for (i=0; i<10; ++i) {
        r = dm_sworndisk_rit_get(mdt->cmd, i, &lba);
        if (r)
            DMINFO("dm_sworndisk_rit_get err");
        else 
            DMINFO("pba: %d, lba: %d", i, lba);
    }
}

/*
 * This is constructor function of target gets called when we create some device of type 'dm_sworndisk_target'.
 * i.e on execution of command 'dmsetup create'. It gets called per device.
 */
static int dm_sworndisk_target_ctr(struct dm_target *target,
			    unsigned int argc, char **argv)
{
    bool may_format;
    struct dm_sworndisk_target *mdt;
    unsigned long long start;
    char dummy;
    int ret = 0;
    struct dm_sworndisk_metadata *cmd;
    // DMINFO("Entry: %s", __func__);

    if (argc != 3) {
        DMERR("Invalid no. of arguments.");
        target->error = "Invalid argument count";
        ret =  -EINVAL;
    }

    mdt = kmalloc(sizeof(struct dm_sworndisk_target), GFP_KERNEL);

    if (mdt==NULL) {
        DMERR("Error in kmalloc");
        target->error = "Cannot allocate linear context";
        ret = -ENOMEM;
    }

    if (sscanf(argv[2], "%llu%c", &start, &dummy)!=1) {
        target->error = "Invalid device sector";
        kfree(mdt);
        ret = -EINVAL;
    }
    mdt->start=(sector_t)start;
    mdt->sstlen = target->len / 8;
    mdt->pba_tail = 0;
    // DMINFO("%llu %llu start", start, target->len);
    /*  To add device in target's table and increment in device count */

    if (dm_get_device(target, argv[0], dm_table_get_mode(target->table), &mdt->data_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto out;
    }
    if (dm_get_device(target, argv[1], dm_table_get_mode(target->table), &mdt->metadata_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto out;
    }
    // if (dm_get_device(target, argv[2], dm_table_get_mode(target->table), &mdt->origin_dev)) {
    //         target->error = "dm-basic_target: Device lookup failed";
    //         goto out;
    // }
    may_format = 0;
    cmd = dm_sworndisk_metadata_open(mdt->metadata_dev->bdev, DM_SWORNDISK_METADATA_BLOCK_SIZE, may_format, 1, NR_SEGMENT, SEC_PER_SEG);
    if (IS_ERR(cmd)) {
        DMERR("open metadata device error");
        goto out;
    }
    mdt->cmd = cmd;
    // DMINFO("mdt->cmd: %p", mdt->cmd);
    mdt->wq = alloc_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM, 0);
	if (!mdt->wq) {
		target->error = "could not create workqueue for metadata object";
		goto out;
	}

	INIT_WORK(&mdt->migration_worker, process_migration);
    INIT_WORK(&mdt->deferred_indexfind_worker, process_deferred_indexfind_bios);
	INIT_WORK(&mdt->deferred_bio_worker, process_deferred_bios);
    target->private = mdt;
    spin_lock_init(&mdt->lock);

	bio_list_init(&mdt->deferred_bios);
    bio_list_init(&mdt->deferred_indexfind_bios);
    c0_init();

    segbuf_init(&mdt->seg_buffer);
    sa_init(&mdt->seg_buffer.sa, mdt->cmd, NR_SEGMENT);
    // memtable_test();
    // segment_allocator_test(cmd);
    // dm_sworndisk_rit_test(mdt);
    // DMINFO("Exit : %s ", __func__);
    // INIT_DELAYED_WORK(&mdt->segment_background_cleaning_work, sworndisk_segment_background_cleaning);
    // schedule_delayed_work(&mdt->segment_background_cleaning_work, 1 * HZ);
    // test_get_first_free_seg(mdt);

    return ret;

out:
    DMERR("Exit : %s with ERROR", __func__);
    return ret;
}

/*
 *  This is destruction function, gets called per device.
 *  It removes device and decrement device count.
 */
static void dm_sworndisk_target_dtr(struct dm_target *ti)
{
    struct dm_sworndisk_target *mdt = (struct dm_sworndisk_target *) ti->private;
    // DMINFO("Entry: %s", __func__);
    dm_put_device(ti, mdt->data_dev);
    dm_put_device(ti, mdt->metadata_dev);
    // dm_put_device(ti, mdt->origin_dev);
    dm_sworndisk_metadata_close(mdt->cmd);
    kfree(mdt);
    // DMINFO("Exit : %s", __func__);
}
/*  This structure is fops for dm_sworndisk target */
static struct target_type dm_sworndisk_target = {

    .name = "sworndisk",
    .version = {1,0,0},
    .module = THIS_MODULE,
    .ctr = dm_sworndisk_target_ctr,
    .dtr = dm_sworndisk_target_dtr,
    .map = dm_sworndisk_target_map,
};

/*---------Module Functions -----------------*/

static int init_dm_sworndisk_target(void)
{
    int result;
    // DMINFO("Entry: %s", __func__);
    result = dm_register_target(&dm_sworndisk_target);
    if (result < 0) {
        DMERR("Error in registering target");
    } else {
        DMINFO("Target registered");
    }
    // DMINFO("Exit : %s", __func__);
    return 0;
}


static void cleanup_dm_sworndisk_target(void)
{
    // DMINFO("Entry: %s", __func__);
    dm_unregister_target(&dm_sworndisk_target);
    // DMINFO("Target unregistered");
    // DMINFO("Exit : %s", __func__);
}

// void sworndisk_segment_background_cleaning(struct work_struct *work) {
//     struct dm_sworndisk_target* mdt = container_of(work, struct dm_sworndisk_target, segment_background_cleaning_work);
//     DMINFO("hello, 1s");
// }

module_init(init_dm_sworndisk_target);
module_exit(cleanup_dm_sworndisk_target);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("lnhoo");
