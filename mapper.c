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
#include "dm.h"
#include "metadata.h"
#include <crypto/skcipher.h>
#include <linux/scatterlist.h> 

#define DM_MSG_PREFIX "hello"

/* For underlying device */
struct my_dm_target {
    struct dm_dev *data_dev;
    struct dm_dev *metadata_dev;
    struct dm_dev *origin_dev;
    sector_t start;
    struct workqueue_struct *wq;
	struct work_struct migration_worker;
    struct work_struct deferred_indexfind_worker;
    struct work_struct deferred_bio_worker;
    struct bio_list deferred_indexfind_bios;
    struct bio_list deferred_bios;
	struct dm_cache_metadata *cmd;
    spinlock_t lock;
    sector_t sstlen;
    int pba_tail;
};

struct kv{
    int lba;
    int pba;
    unsigned int key[4];
    unsigned int mac[4];
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

int c0_insert(int lba, struct my_dm_target *mdt) {
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

int linux_kernel_crypto_encrypt(void* data_in_out, int data_len, void* key, int key_len) {
	struct crypto_skcipher* cipher;
	struct skcipher_request* req;
    struct crypto_wait wait;
	struct scatterlist sg;
    size_t block_size;
	int ret;

    // 分配算法对象，支持的算法可以在/proc/crypto文件中查看
	cipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(cipher)) {
		printk("fail to allocate cipher\n");
		return -1;
	}

    // skcipher api不支持填充，所以加/解密数据需要为加密块的整数倍
    block_size = crypto_skcipher_blocksize(cipher);
    if (data_len % block_size != 0) {
		printk("data len not aligned");
		return -1;
	}

    // 分配req对象
	req = skcipher_request_alloc(cipher, GFP_KERNEL);
	if (IS_ERR(req)) {
		printk("fail to allocate req\n");
		return -1;
	}
	sg_init_one(&sg, data_in_out, data_len);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
    char iv[16] = { 0 };
	skcipher_request_set_crypt(req, &sg, &sg, data_len, iv);
	ret = crypto_skcipher_setkey(cipher, key, key_len);
    if ( 0 != ret) {
        printk("fail to set key, error %d\n", ret);
        return -1;
    }
    // 执行解密操作
	ret = crypto_wait_req(crypto_skcipher_encrypt(req), &wait); 
	if (0 != ret) {
        printk("decryption error %d\n", ret);
        return -1;
	}
	// 释放资源
	crypto_free_skcipher(cipher);
	skcipher_request_free(req);
	//printk("encryption finished");
	return 0;
}

int linux_kernel_crypto_decrypt(void* data_in_out, int data_len, void* key, int key_len) {
	struct crypto_skcipher* cipher;
	struct skcipher_request* req;
    struct crypto_wait wait;
	struct scatterlist sg;
    size_t block_size;
	int ret;

    // 分配算法对象，支持的算法可以在/proc/crypto文件中查看
	cipher = crypto_alloc_skcipher("cbc(aes)", 0, 0);
	if (IS_ERR(cipher)) {
		printk("fail to allocate cipher\n");
		return -1;
	}

    // skcipher api不支持填充，所以加/解密数据需要为加密块的整数倍
    block_size = crypto_skcipher_blocksize(cipher);
    if (data_len % block_size != 0) {
		printk("data len not aligned");
		return -1;
	}

    // 分配req对象
	req = skcipher_request_alloc(cipher, GFP_KERNEL);
	if (IS_ERR(req)) {
		printk("fail to allocate req\n");
		return -1;
	}
	sg_init_one(&sg, data_in_out, data_len);
	skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
    char iv[16] = { 0 };
	skcipher_request_set_crypt(req, &sg, &sg, data_len, iv);
	ret = crypto_skcipher_setkey(cipher, key, key_len);
    if ( 0 != ret) {
        printk("fail to set key, error %d\n", ret);
        return -1;
    }
    // 执行解密操作
	ret = crypto_wait_req(crypto_skcipher_decrypt(req), &wait); 
	if (0 != ret) {
        printk("decryption error %d\n", ret);
        return -1;
	}
	// 释放资源
	crypto_free_skcipher(cipher);
	skcipher_request_free(req);
	//printk("decryption finished");
	return 0;
}


static void defer_bio(struct my_dm_target *mdt, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_add(&mdt->deferred_bios, bio);
    DMINFO("%d", bio->bi_iter.bi_sector);
	spin_unlock_irqrestore(&mdt->lock, flags);

	queue_work(mdt->wq, &mdt->deferred_bio_worker);
}

static int findc1(struct my_dm_target *mdt, int lba) {
    __le64 lba0, pba;
    int h, t, m;
    h = 0; t = mdt->sstlen;
    while (h <= t) {
        m = (h + t) / 2;
	    dm_cache_read(mdt->cmd, m, &pba);
        
        lba0 = pba >> 32;
        pba = pba << 32 >> 32;
        //DMINFO("%d %llu %llu", m, lba0, pba);
        
        if (lba < lba0)
            t = m - 1;
        else if (lba > lba0)
            h = m + 1;
        else
            return pba;
    }
    
    return 0;
}

static void process_deferred_indexfind_bios(struct work_struct *ws) {
    struct my_dm_target *mdt = container_of(ws, struct my_dm_target, deferred_indexfind_worker);
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

static void defer_indexfind_bio(struct my_dm_target *mdt, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_add(&mdt->deferred_indexfind_bios, bio);
	spin_unlock_irqrestore(&mdt->lock, flags);

    queue_work(mdt->wq, &mdt->deferred_indexfind_worker);
}

static void process_deferred_bios(struct work_struct *ws)
{
	struct my_dm_target *mdt = container_of(ws, struct my_dm_target, deferred_bio_worker);

	unsigned long flags;
	struct bio_list bios;
	struct bio *bio;

	bio_list_init(&bios);

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_merge(&bios, &mdt->deferred_bios);
	bio_list_init(&mdt->deferred_bios);
	spin_unlock_irqrestore(&mdt->lock, flags);
//    DMINFO("????");
	while ((bio = bio_list_pop(&bios))) {
        //DMINFO("%d %d %d", bio_op(bio), bio->bi_iter.bi_sector, bio->bi_vcnt);
        generic_make_request(bio);
	}

}

static int hello_target_map(struct dm_target *target, struct bio *bio)
{
    //DMINFO("Entry: %s", __func__);
    struct my_dm_target *mdt = target->private;
    int lba, pba, offset;
    /*  bio should perform on our underlying device   */
    lba = bio->bi_iter.bi_sector;
    bio_set_dev(bio, mdt->origin_dev->bdev);
    //DMINFO("bio %llu %llu", REQ_FUA, REQ_PREFLUSH);
    DMINFO("bio  op: %d wrtie: %d flush: %d sync: %d", bio->bi_opf, op_is_write(bio->bi_opf), op_is_flush(bio->bi_opf), op_is_sync(bio->bi_opf));
    DMINFO("bio size: %d lba: %d" , bio->bi_iter.bi_size, lba);
    // return DM_MAPIO_REMAPPED;
    if (bio_op(bio) == REQ_OP_WRITE) {
        //bio_set_dev(bio, mdt->data_dev->bdev);
        offset = lba % 8;
        lba -= offset;
        pba = c0_insert(lba, mdt);
        bio->bi_iter.bi_sector = pba * 8 + offset;
        defer_bio(mdt, bio);
        if (c0.size > c0.max_size)
            queue_work(mdt->wq, &mdt->migration_worker);
        return DM_MAPIO_SUBMITTED;
    }

    if (bio_op(bio) == REQ_OP_READ) {
        offset = lba % 8;
        pba = c0_find(lba - offset);
        if (pba != -1) {
            DMINFO("????");
            //bio_set_dev(bio, mdt->data_dev->bdev);
            bio->bi_iter.bi_sector = pba * 8 + offset;
            defer_bio(mdt, bio);
        }
        else {
            defer_indexfind_bio(mdt, bio);
        }
        return DM_MAPIO_SUBMITTED;
    }
    
    DMINFO("Exit : %s", __func__);
    return DM_MAPIO_REMAPPED;
}

/*
 * This is constructor function of target gets called when we create some device of type 'hello_target'.
 * i.e on execution of command 'dmsetup create'. It gets called per device.
 */
static int hello_target_ctr(struct dm_target *target,
			    unsigned int argc, char **argv)
{
    int i;
    struct my_dm_target *mdt;
    unsigned long long start;
    char dummy;
    int ret = 0;
    DMINFO("Entry: %s", __func__);

    if (argc != 4) {
        DMERR("Invalid no. of arguments.");
        target->error = "Invalid argument count";
        ret =  -EINVAL;
    }

    mdt = kmalloc(sizeof(struct my_dm_target), GFP_KERNEL);

    if (mdt==NULL) {
        DMERR("Error in kmalloc");
        target->error = "Cannot allocate linear context";
        ret = -ENOMEM;
    }

    if (sscanf(argv[3], "%llu%c", &start, &dummy)!=1) {
        target->error = "Invalid device sector";
        kfree(mdt);
        ret = -EINVAL;
    }
    mdt->start=(sector_t)start;
    mdt->sstlen = target->len / 8;
    mdt->pba_tail = 0;
    DMINFO("%llu %llu start", start, target->len);
    /*  To add device in target's table and increment in device count */

    if (dm_get_device(target, argv[0], dm_table_get_mode(target->table), &mdt->data_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto out;
    }
    if (dm_get_device(target, argv[1], dm_table_get_mode(target->table), &mdt->metadata_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto out;
    }
    if (dm_get_device(target, argv[2], dm_table_get_mode(target->table), &mdt->origin_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto out;
    }
    bool may_format = 0;
    struct dm_cache_metadata *cmd = dm_cache_metadata_open(mdt->metadata_dev->bdev,
				    8, may_format, target->len);

    mdt->cmd = cmd;
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

    DMINFO("Exit : %s ", __func__);
    return ret;

out:
    DMERR("Exit : %s with ERROR", __func__);
    return ret;
}

/*
 *  This is destruction function, gets called per device.
 *  It removes device and decrement device count.
 */
static void hello_target_dtr(struct dm_target *ti)
{
    struct my_dm_target *mdt = (struct my_dm_target *) ti->private;
    DMINFO("Entry: %s", __func__);
    dm_put_device(ti, mdt->data_dev);
    dm_put_device(ti, mdt->metadata_dev);
    dm_put_device(ti, mdt->origin_dev);
    dm_cache_metadata_close(mdt->cmd);
    kfree(mdt);
    DMINFO("Exit : %s", __func__);
}
/*  This structure is fops for hello target */
static struct target_type hello_target = {

    .name = "hello_target",
    .version = {1,0,0},
    .module = THIS_MODULE,
    .ctr = hello_target_ctr,
    .dtr = hello_target_dtr,
    .map = hello_target_map,
};

/*---------Module Functions -----------------*/

static int init_hello_target(void)
{
    int result;
    DMINFO("Entry: %s", __func__);
    result = dm_register_target(&hello_target);
    if (result < 0) {
        DMERR("Error in registering target");
    } else {
        DMINFO("Target registered");
    }
    DMINFO("Exit : %s", __func__);
    return 0;
}


static void cleanup_hello_target(void)
{
    DMINFO("Entry: %s", __func__);
    dm_unregister_target(&hello_target);
    DMINFO("Target unregistered");
    DMINFO("Exit : %s", __func__);
}

module_init(init_hello_target);
module_exit(cleanup_hello_target);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Narendra Pal Singh");
