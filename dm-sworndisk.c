#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/bio.h>
#include <linux/device-mapper.h>
#include <linux/slab.h>
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
#include <crypto/aead.h> 
#include <linux/scatterlist.h> 
#include <linux/random.h>

#include "persistent-data/dm-bitset.h"
#include "dm.h"
#include "dm-sworndisk-metadata.h"

#define DM_MSG_PREFIX "sworndisk"

#define SD_BLOCK_SIZE 4096 // SwornDisk Block Size
#define SD_SECTOR_SIZE 512
#define NR_SEGMENT 122880
#define SEC_PER_BLK 8
#define BLK_PER_SEG 64
#define SEC_PER_SEG (SEC_PER_BLK*BLK_PER_SEG)

struct hashmap {
    int bucket_num;
    struct hlist_head *hlists;
};

struct hashmap_value {
    int key;
    void* data;
    struct hlist_node node;
};

void hashmap_init(struct hashmap* map, int bucket_num);
void hashmap_destroy(struct hashmap* map);
void hashmap_add(struct hashmap* map, int key, void* data);
bool hashmap_delete(struct hashmap* map, int key);
void test_hashmap(void);
bool hashmap_exists(struct hashmap* map, int key);
void* hashmap_getval(struct hashmap* map, int key);

int get_bucket(int key, int bucket_num);

#define HASHMAP_BUCKET_NUM 65536
void hashmap_init(struct hashmap* map, int bucket_num) {
    int i;

    map->bucket_num = bucket_num;
    map->hlists = (struct hlist_head*)kmalloc(sizeof(struct hlist_head)*bucket_num, GFP_KERNEL);
    for(i=0; i<bucket_num; ++i) {
        INIT_HLIST_HEAD(&map->hlists[i]);
    }
}

void hashmap_destroy(struct hashmap* map) {
    vfree(map->hlists);
}

void hashmap_add(struct hashmap* map, int key, void* data) {
    struct hashmap_value* value = (struct hashmap_value*)kmalloc(sizeof(struct hashmap_value), GFP_KERNEL);

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

void* hashmap_getval(struct hashmap* map, int key) {
    struct hashmap_value* obj;

    hlist_for_each_entry(obj, &map->hlists[get_bucket(key, map->bucket_num)], node) {
        if(obj->key == key) {
            return obj->data;
        }
    }

    return NULL;
}

#define AES_GCM_KEY_SIZE 16
#define AES_GCM_BLOCK_SIZE 1 // in bytes
#define AES_GCM_IV_SIZE 12
#define AES_GCM_AUTH_SIZE 16
struct mt_value {
    int psa;
    char mac[AES_GCM_AUTH_SIZE];
    char key[AES_GCM_KEY_SIZE];
    char iv[AES_GCM_IV_SIZE];
};  

struct mt_value* mt_value_create(int psa, char* key, char* iv, char* mac) {
    struct mt_value* val;

    val = (struct mt_value*) kmalloc(sizeof(struct mt_value), GFP_KERNEL);
    if (IS_ERR(val)) {
        DMERR("mt value create alloc mem error\n");
        return NULL;
    }

    val->psa = psa;
    // memcpy(&val->key, key, AES_GCM_KEY_SIZE);
    // memcpy(&val->iv, iv, AES_GCM_IV_SIZE);
    // memcpy(&val->mac, mac, AES_GCM_AUTH_SIZE);
    return val;
}

struct memtable {
    struct hashmap map;

    void (*put)(struct memtable* mt, int lsa, struct mt_value* val);
    int (*get)(struct memtable* mt, int lsa, struct mt_value* val);
    bool (*contains)(struct memtable* mt, int lsa);
};

void memtable_put(struct memtable* mt, int lsa, struct mt_value* val) {
    hashmap_add(&mt->map, lsa, val);
}

int memtable_get(struct memtable* mt, int lsa, struct mt_value *mv) {
    struct mt_value* val;

    val = hashmap_getval(&mt->map, lsa);
    if (!val)
        return -ENODATA;
    memcpy(mv, val, sizeof(struct mt_value));
    return 0;
}

bool memtable_contains(struct memtable* mt, int lsa) {
    return hashmap_exists(&mt->map, lsa);
}

void memtable_init(struct memtable* mt) {
    hashmap_init(&mt->map, HASHMAP_BUCKET_NUM);
    mt->put = memtable_put;
    mt->get = memtable_get;
    mt->contains = memtable_contains;
}

struct aead_cipher {
    int (*encrypt)(struct aead_cipher* ci, void* data, int data_len, void* key, int key_len, void* iv);
    int (*decrypt)(struct aead_cipher* ci, void* data, int data_len, void* key, int key_len, void* iv, void* mac, int mac_len);
    int (*get_random_key)(char** p_key, int key_len);
    int (*get_random_iv)(char** p_iv, int iv_len);
};
/*
    name         : gcm(aes)
    driver       : generic-gcm-aesni
    module       : aesni_intel
    priority     : 400
    refcnt       : 1
    selftest     : passed
    internal     : no
    type         : aead
    async        : yes
    blocksize    : 1
    ivsize       : 12
    maxauthsize  : 16
    geniv        : <none>
*/
struct aes_gcm_cipher {
    struct aead_cipher interface;
    struct scatterlist sg;
    struct crypto_aead *tfm;
    struct aead_request *req;
    struct crypto_wait wait;
    size_t block_size;
    size_t auth_size;
    size_t iv_size;
};

int __get_random_bytes(char** p_data, unsigned int len) {
    *p_data = kmalloc(len, GFP_KERNEL);
    if (IS_ERR(*p_data)) {
        DMERR("get random bytes alloc mem error\n");
        return PTR_ERR(*p_data);
    }
    get_random_bytes(*p_data, len);
    return 0;
}

int aes_gcm_get_random_key(char** p_key, int key_len) {
    return __get_random_bytes(p_key, key_len);
}

int aes_gcm_get_random_iv(char** p_iv, int iv_len) {
    return __get_random_bytes(p_iv, iv_len);
}

int aes_gcm_cipher_encrypt(struct aead_cipher *ac, void* data, int data_len, void* key, int key_len, void* iv) {
    int r;

    struct aes_gcm_cipher* ag = container_of(ac, struct aes_gcm_cipher, interface);
    sg_init_one(&ag->sg, data, data_len);
    aead_request_set_crypt(ag->req, &ag->sg, &ag->sg, data_len, iv);
    aead_request_set_ad(ag->req, 0);
    r = crypto_aead_setkey(ag->tfm, key, key_len);
    if (r) {
        DMERR("gcm(aes) key could not be set\n");
        return -EAGAIN;
    }
    r = crypto_aead_encrypt(ag->req);
	if (r) {
        DMERR("gcm(aes) decryption error\n");
        return -EAGAIN;
	}
    return 0;
}

int aes_gcm_cipher_decrypt(struct aead_cipher *ac, void* data, int data_len, void* key, int key_len, void* iv, void* mac, int mac_len) {
    int r;
    struct aes_gcm_cipher* ag = container_of(ac, struct aes_gcm_cipher, interface);
    memcpy(data+data_len, mac, mac_len);
    sg_init_one(&ag->sg, data, data_len+mac_len);
    aead_request_set_crypt(ag->req, &ag->sg, &ag->sg, data_len+mac_len, iv);
    aead_request_set_ad(ag->req, 0);
    r = crypto_aead_setkey(ag->tfm, key, key_len);
    if (r) {
        DMERR("gcm(aes) key could not be set\n");
        return -EAGAIN;
    }
    r = crypto_aead_decrypt(ag->req);
    if (r == -EBADMSG) {
        DMERR("gcm(aes) authentication failed");
        return r;
    } else if (r) {
        DMERR("gcm(aes) decryption error\n");
        return -EAGAIN;
	}
    return 0;
}

int aes_gcm_cipher_init(struct aes_gcm_cipher *ag) {
    ag->tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(ag->tfm)) {
        DMERR("could not allocate aead handler\n");
        return PTR_ERR(ag->tfm);
    }
    ag->req = aead_request_alloc(ag->tfm, GFP_KERNEL);
    if (!ag->req) {
        DMERR("could not allocate aead request\n");
        return -ENOMEM;
    }
    ag->block_size = crypto_aead_blocksize(ag->tfm);
    ag->auth_size = crypto_aead_authsize(ag->tfm);
    ag->iv_size = crypto_aead_ivsize(ag->tfm);

    ag->interface.get_random_key = aes_gcm_get_random_key;
    ag->interface.get_random_iv = aes_gcm_get_random_iv;
    ag->interface.encrypt = aes_gcm_cipher_encrypt;
    ag->interface.decrypt = aes_gcm_cipher_decrypt;
    return 0;
}

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

#define MB_SHIFT 20
#define MAX_DATA_SIZE (5 << MB_SHIFT)
// char data[MAX_DATA_SIZE];

struct segment_buffer {
    // spinlock_t lock;
    struct bio_list bios;
    struct segment_allocator sa;
    struct memtable mt;
    struct aes_gcm_cipher ag;

    int (*push_bio)(struct segment_buffer* buf, struct bio* bio);
    void (*flush_bios)(struct segment_buffer* buf);
    int (*encrypt_bio)(struct segment_buffer* buf, struct bio* bio, struct memtable* mt, int lsa, int psa);
};

/* For underlying device */
struct dm_sworndisk_target {
    struct dm_dev *data_dev;
    struct dm_dev *metadata_dev;
    sector_t start;
    struct workqueue_struct *wq;
    struct work_struct deferred_bio_worker;
    struct bio_list deferred_bios;
	struct dm_sworndisk_metadata *cmd;
    struct segment_buffer seg_buffer;
    struct bio_set* bio_set; 
    spinlock_t lock;

    // struct delayed_work segment_background_cleaning_work;
};

unsigned int bio_get_sector(struct bio *bio) {
    return bio->bi_iter.bi_sector;
}

void bio_set_sector(struct bio *bio, unsigned int sector) {
    bio->bi_iter.bi_sector = sector;
}

// in bytes
unsigned int bio_get_data_len(struct bio* bio) {
    return bio->bi_iter.bi_size;
}

void bio_set_data_len(struct bio* bio, unsigned int len) {
    bio->bi_iter.bi_size = len;
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
    // unsigned long flags;
    bool should_flush;

    // spin_lock_irqsave(&buf->lock, flags);

    r = buf->sa.alloc_sectors(&buf->sa, bio, &psa, &nr_sector, &should_flush);
    if (r) {
        DMERR("alloc_sectors error");
        return r;
    }
        

    // if (should_flush) 
        // buf->flush_bios(buf);


    // rediret bio
    lsa = bio_get_sector(bio);
    bio_set_sector(bio, psa);
    // encrypt bio
    buf->encrypt_bio(buf, bio, &buf->mt, lsa, psa);
    // update reverse index table
    // buf->sa.write_reverse_index_table(&buf->sa, psa, lsa, nr_sector);

	bio_list_add(&buf->bios, bio);
	// spin_unlock_irqrestore(&buf->lock, flags);

    buf->flush_bios(buf);
    return 0;
}

void segbuf_flush_bios(struct segment_buffer* buf) {
    struct bio *bio;
    // unsigned long flags;

    // spin_lock_irqsave(&buf->lock, flags);
    while ((bio = bio_list_pop(&buf->bios))) {
        // DMINFO("flush bio, psa: %d", bio_get_sector(bio));
        submit_bio(bio);
    }
    // spin_unlock_irqrestore(&buf->lock, flags);
}

int segbuf_crypto_bio_prepare_buffers(struct segment_buffer* buf, struct bio* bio, char** p_data, char** p_buffer, int data_len) {
    int offset;
    struct bvec_iter bv_iter;
    struct bio_vec bvec;
    void* kaddr;

    *p_data = (char*) kmalloc(data_len, GFP_KERNEL);
    if (IS_ERR(*p_data)) {
        DMERR("segbuf_encrypt_bio alloc data mem error\n");
        return PTR_ERR(*p_data);
    }

    *p_buffer = (char*) kmalloc(SD_SECTOR_SIZE+buf->ag.auth_size, GFP_KERNEL);
    if (IS_ERR(*p_buffer)) {
        DMERR("segbuf_encrypt_bio alloc buffer mem error\n");
        return PTR_ERR(*p_buffer);
    }
    offset = 0;
    bio_for_each_segment(bvec, bio, bv_iter) {
        kaddr = kmap(bvec.bv_page);
        memcpy(*p_data + offset, kaddr + bvec.bv_offset, bvec.bv_len);
        offset += bvec.bv_len;
        kunmap(bvec.bv_page);
    }
    return 0;
}

void segbuf_crypto_bio_writeback_buffers(struct segment_buffer* buf, struct bio* bio, char* data) {
    int offset;
    struct bvec_iter bv_iter;
    struct bio_vec bvec;
    void* kaddr;

    offset = 0;
    bio_for_each_segment(bvec, bio, bv_iter) {
        kaddr = kmap(bvec.bv_page);
        memcpy(kaddr + bvec.bv_offset, data + offset, bvec.bv_len);
        offset += bvec.bv_len;
        kunmap(bvec.bv_page);
    }
}

char key[AES_GCM_KEY_SIZE];
char iv[AES_GCM_IV_SIZE];
char mac[AES_GCM_AUTH_SIZE];

int segbuf_encrypt_bio(struct segment_buffer* buf, struct bio* bio, struct memtable* mt, int lsa, int psa) {
    // int r;
    int i;
    // char* data;
    // char* buffer; // buffer which contains data with a sector
    int offset;
    int data_len;
    // char* key;
    // char* iv;
    struct mt_value *mv;

   
    data_len = bio_get_data_len(bio);
    // r = segbuf_crypto_bio_prepare_buffers(buf, bio, &data, &buffer, data_len);
    // if (r)
    //     return r;
    
    i = 0;
    for (offset=0; offset<data_len; offset+=SD_SECTOR_SIZE) {
        // memcpy(buffer, data+offset, SD_SECTOR_SIZE);
        // r = buf->ag.interface.get_random_key(&key, AES_GCM_KEY_SIZE);
        // if (r)
        //     return r;
        // r = buf->ag.interface.get_random_iv(&iv, buf->ag.iv_size);
        // if (r)
        //     return r;

        // r = buf->ag.interface.encrypt(&buf->ag.interface, buffer, SD_SECTOR_SIZE, key, AES_GCM_KEY_SIZE, iv);
        // if (r)
        //     return r;
        
        mv = mt_value_create(psa+i, key, iv, mac);
        if (mv == NULL) 
            return -ENOMEM;
        mt->put(mt, lsa+i, mv);
        ++i;
        // memcpy(data+offset, buffer, SD_SECTOR_SIZE);
    }
    
    // segbuf_crypto_bio_writeback_buffers(buf, bio, data);
    // kfree(key);
    // kfree(iv);
    // kfree(buffer);
    // kfree(data);
    return 0;
}

struct bio_decrypt_handler {
    int lsa;
    struct bio* ob;
    struct bvec_iter bi_iter;
    struct dm_sworndisk_target* mdt;
};

void bio_decrypt_handler_init(struct bio_decrypt_handler* ha, int lsa, struct bio* ob, struct dm_sworndisk_target* mdt) {
    ha->lsa = lsa;
    ha->ob = ob;
    ha->bi_iter = ob->bi_iter;
    ha->mdt = mdt;
}

struct bio_decrypt_handler* bio_decrypt_handler_create(int lsa, struct bio* ob, struct dm_sworndisk_target* mdt) {
    struct bio_decrypt_handler* handler;

    handler = kmalloc(sizeof(struct bio_decrypt_handler), GFP_KERNEL);
    if (IS_ERR(handler)) {
        DMERR("bio_decrypt_handler_create alloc mem error\n");
        return NULL;
    }

    bio_decrypt_handler_init(handler, lsa, ob, mdt);
    return handler;
}

void end_bio_decrypt(struct bio* bio) {
    struct bio_decrypt_handler* handler;
    int r;
    int i;
    int lsa;
    char* data;
    char* buffer; // buffer which contains data with a sector
    int offset;
    int data_len;
    char* key;
    char* iv;
    char* mac;
    struct segment_buffer* buf;
    struct memtable* mt;
    struct mt_value mv;

    handler = bio->bi_private;
    lsa = handler->lsa;
    buf = &handler->mdt->seg_buffer;
    mt = &handler->mdt->seg_buffer.mt;
    bio->bi_iter = handler->bi_iter;
    data_len = bio_get_data_len(bio);

    r = segbuf_crypto_bio_prepare_buffers(buf, bio, &data, &buffer, data_len);
    if (r) {
        DMERR("segbuf_crypto_bio_prepare_buffers error");
        goto exit;
    }
        
    i = 0;
    for (offset=0; offset<data_len; offset+=SD_SECTOR_SIZE) {
        memcpy(buffer, data+offset, SD_SECTOR_SIZE);
        mt->get(mt, lsa + i, &mv);
        key = mv.key;
        iv = mv.iv;
        mac = mv.mac;

        // r = buf->ag.interface.decrypt(&buf->ag.interface, buffer, SD_SECTOR_SIZE, key, AES_GCM_KEY_SIZE, iv, mac, AES_GCM_AUTH_SIZE);
        // if (r)
        //     goto exit;

        ++i;
        memcpy(data+offset, buffer, SD_SECTOR_SIZE);
    }

    segbuf_crypto_bio_writeback_buffers(buf, bio, data);
    kfree(buffer);
    kfree(data);
exit:
    handler->ob->bi_status = bio->bi_status;
    bio_endio(handler->ob);
}

void segbuf_init(struct segment_buffer *buf) {
    // spin_lock_init(&buf->lock);
    bio_list_init(&buf->bios);
    memtable_init(&buf->mt);
    aes_gcm_cipher_init(&buf->ag);

    buf->push_bio = segbuf_push_bio;
    buf->flush_bios = segbuf_flush_bios;
    buf->encrypt_bio = segbuf_encrypt_bio;
};


int sa_get_next_free_segment(struct segment_allocator* al) {
    int r;
    int seg;

    r = dm_sworndisk_get_first_free_segment(al->cmd, &seg);
    if (r) {
        // DMINFO("dm_sworndisk_get_first_free_segment error");
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

static void defer_bio(struct dm_sworndisk_target *mdt, struct bio *bio)
{
	unsigned long flags;

	spin_lock_irqsave(&mdt->lock, flags);
	bio_list_add(&mdt->deferred_bios, bio);
	spin_unlock_irqrestore(&mdt->lock, flags);

	queue_work(mdt->wq, &mdt->deferred_bio_worker);
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

int map_read_bio(struct dm_sworndisk_target *mdt, struct bio* bio) {
    int r;
    int lsa;
    struct bio* decrypt_bio;
    struct mt_value mv;
    struct bio_decrypt_handler* bd_handler;

    lsa = bio_get_sector(bio);
    r = mdt->seg_buffer.mt.get(&mdt->seg_buffer.mt, lsa, &mv);
    if (r) {
        // DMINFO("map_read_bio, invalid lsa: %d", lsa);
        return r;
    }    

    decrypt_bio = bio_clone_fast(bio, GFP_NOIO, mdt->bio_set);
    bd_handler = bio_decrypt_handler_create(lsa, bio, mdt);
    decrypt_bio->bi_private = bd_handler;
    bio_set_dev(decrypt_bio, mdt->data_dev->bdev);
    bio_set_sector(decrypt_bio, mv.psa);
    decrypt_bio->bi_end_io = end_bio_decrypt;
    generic_make_request(decrypt_bio);
    return 0;
}

static int dm_sworndisk_target_map(struct dm_target *target, struct bio *bio)
{
    int r;
    // struct bio* sector_bio;
    struct mt_value mv;
    struct dm_sworndisk_target *mdt = target->private;

    bio_set_dev(bio, mdt->data_dev->bdev);

    if (bio_op(bio) == REQ_OP_WRITE) {
        // DMINFO("write bio, sector: %d, nr_sector: %d", bio_get_sector(bio), bio_sectors(bio));
        // while(bio_sectors(bio)>1) {
        //     sector_bio = bio_split(bio, 1, GFP_NOIO, mdt->bio_set);
        //     defer_bio(mdt, sector_bio);
        // }
        defer_bio(mdt, bio);
        return DM_MAPIO_SUBMITTED;
    }

    if (bio_op(bio) == REQ_OP_READ) {
        // DMINFO("read bio, sector: %d, nr_sector: %d", bio_get_sector(bio), bio_sectors(bio));
        // while(bio_sectors(bio)>1) {
        //     sector_bio = bio_split(bio, 1, GFP_NOIO, mdt->bio_set);
        //     r = map_read_bio(mdt, sector_bio);
        //     if (r)
        //         goto exit;
        // }
        // r = map_read_bio(mdt, bio);
        // if (r)
        //     goto exit;
        r = mdt->seg_buffer.mt.get(&mdt->seg_buffer.mt, bio_get_sector(bio), &mv);
        if (r) 
            goto exit;
        bio_set_sector(bio, mv.psa);
        submit_bio(bio);
        return DM_MAPIO_SUBMITTED;
    }

exit:
    return DM_MAPIO_REMAPPED;
}

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

    if (dm_get_device(target, argv[0], dm_table_get_mode(target->table), &mdt->data_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto out;
    }
    if (dm_get_device(target, argv[1], dm_table_get_mode(target->table), &mdt->metadata_dev)) {
            target->error = "dm-basic_target: Device lookup failed";
            goto out;
    }
    may_format = 0;
    cmd = dm_sworndisk_metadata_open(mdt->metadata_dev->bdev, DM_SWORNDISK_METADATA_BLOCK_SIZE, may_format, 1, NR_SEGMENT, SEC_PER_SEG);
    if (IS_ERR(cmd)) {
        DMERR("open metadata device error");
        goto out;
    }
    mdt->cmd = cmd;
    mdt->wq = alloc_workqueue("dm-" DM_MSG_PREFIX, WQ_MEM_RECLAIM, 0);
	if (!mdt->wq) {
		target->error = "could not create workqueue for metadata object";
		goto out;
	}

	INIT_WORK(&mdt->deferred_bio_worker, process_deferred_bios);
    target->private = mdt;
    spin_lock_init(&mdt->lock);
	bio_list_init(&mdt->deferred_bios);
    segbuf_init(&mdt->seg_buffer);
    sa_init(&mdt->seg_buffer.sa, mdt->cmd, NR_SEGMENT);
    mdt->bio_set = bioset_create(BIO_POOL_SIZE, 0, BIOSET_NEED_BVECS);
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
    dm_put_device(ti, mdt->data_dev);
    dm_put_device(ti, mdt->metadata_dev);
    dm_sworndisk_metadata_close(mdt->cmd);
    kfree(mdt);
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
    result = dm_register_target(&dm_sworndisk_target);
    if (result < 0) {
        DMERR("Error in registering target");
    } else {
        DMINFO("Target registered");
    }
    return 0;
}


static void cleanup_dm_sworndisk_target(void)
{
    dm_unregister_target(&dm_sworndisk_target);
}

// void sworndisk_segment_background_cleaning(struct work_struct *work) {
//     struct dm_sworndisk_target* mdt = container_of(work, struct dm_sworndisk_target, segment_background_cleaning_work);
//     DMINFO("hello, 1s");
// }

module_init(init_dm_sworndisk_target);
module_exit(cleanup_dm_sworndisk_target);
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("lnhoo");
