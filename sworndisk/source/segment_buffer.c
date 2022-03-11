#include <linux/bio.h>

#include "../include/dm_sworndisk.h"
#include "../include/segment_buffer.h"
#include "../include/bio_operate.h"
#include "../include/crypto.h"

#define DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE struct default_segment_buffer* this; \
                this = container_of(buf, struct default_segment_buffer, segment_buffer);

int segbuf_push_bio(struct segment_buffer* buf, struct bio *bio) {
    int r;
    sector_t lba;
    sector_t pba;
    bool should_flush;
    struct default_segment_buffer* buf_instance;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    r = this->sa->alloc_sectors(this->sa, bio, &pba, &should_flush);
    if (r) {
        DMERR("alloc_sectors error");
        return r;
    }
        

    // if (should_flush) 
        // buf->flush_bios(buf);


    // rediret bio
    lba = bio_get_sector(bio);
    bio_set_sector(bio, pba);
    // encrypt bio
    buf_instance = (struct default_segment_buffer*)(buf->implementer(buf));
    buf->encrypt_bio(buf, bio, buf_instance->mt, lba, pba);
    // update reverse index table
    this->sa->write_reverse_index_table(this->sa, pba, lba);

	bio_list_add(&this->bios, bio);

    buf->flush_bios(buf);
    return 0;
}

void segbuf_flush_bios(struct segment_buffer* buf) {
    struct bio *bio;
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    while ((bio = bio_list_pop(&this->bios))) {
        DMINFO("flush bio, pba: %d", bio_get_sector(bio));
        submit_bio(bio);
    }
}

int segbuf_encrypt_bio(struct segment_buffer* buf, struct bio* bio, struct memtable* mt, int lba, int pba) {
    int r;
    char* key;
    char* iv;
    char* mac;
    struct mt_value *mv;
    char* kaddr;
    struct default_segment_buffer* buf_instance;

    buf_instance = (struct default_segment_buffer*)(buf->implementer(buf));
    r = buf_instance->cipher->get_random_key(&key, AES_GCM_KEY_SIZE);
    if (r)
        goto exit;
    r = buf_instance->cipher->get_random_iv(&iv, AES_GCM_IV_SIZE);
    if (r)
        goto exit;
    mac = kmalloc(AES_GCM_AUTH_SIZE, GFP_KERNEL);
    if (IS_ERR_OR_NULL(mac)) {
        r = PTR_ERR(mac);
        goto exit;
    }

    kaddr = kmap_atomic(bio_page(bio));
    r = buf_instance->cipher->encrypt(buf_instance->cipher, kaddr+bio_offset(bio), bio_cur_bytes(bio), key, AES_GCM_KEY_SIZE, iv, mac, AES_GCM_AUTH_SIZE, lba);
    if (r)
        goto exit;
    
    mv = mt_value_create(pba, key, iv, mac);
    if (!mv) {
        r = -ENOMEM;
        goto exit;
    } 
    mt->put(mt, lba, mv);
exit:
    kunmap_atomic(kaddr);
    return r;
}

void* segbuf_implementer(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    return this;
}

void segbuf_destroy(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINT_DECLARE

    if (this->sa)
        this->sa->destroy(this->sa);
    kfree(this);
}

struct segment_buffer* segbuf_init(struct default_segment_buffer *buf, struct dm_sworndisk_metadata *metadata, size_t nr_segment) {
    if (IS_ERR_OR_NULL(buf))
        return NULL;

    bio_list_init(&buf->bios);
    buf->mt = hash_memtable_init(kmalloc(sizeof(struct hash_memtable), GFP_KERNEL));
    if (!buf->mt)
        return NULL;
    buf->cipher = aes_gcm_cipher_init(kmalloc(sizeof(struct aes_gcm_cipher), GFP_KERNEL));
    if (IS_ERR_OR_NULL(buf->cipher))
        return NULL; 
    buf->sa = sa_init(kmalloc(sizeof(struct default_segment_allocator), GFP_KERNEL), metadata, nr_segment);
    if (IS_ERR_OR_NULL(buf->sa))
        return NULL; 

    buf->segment_buffer.push_bio = segbuf_push_bio;
    buf->segment_buffer.flush_bios = segbuf_flush_bios;
    buf->segment_buffer.encrypt_bio = segbuf_encrypt_bio;
    buf->segment_buffer.implementer = segbuf_implementer;
    buf->segment_buffer.destroy = segbuf_destroy;
    return &buf->segment_buffer;
};
