#include <linux/bio.h>

#include "../include/dm_sworndisk.h"
#include "../include/metadata.h"
#include "../include/segment_buffer.h"
#include "../include/bio_operate.h"
#include "../include/crypto.h"

#define DEFAULT_SEGMENT_BUFFER_THIS_POINTER_DECLARE struct default_segment_buffer* this; \
                struct dm_sworndisk_target* sworndisk; \
                  this = container_of(buf, struct default_segment_buffer, segment_buffer); \
                    sworndisk = this->sworndisk;

void btox(char *xp, const char *bb, int n)  {
    const char xx[]= "0123456789ABCDEF";
    while (--n >= 0) xp[n] = xx[(bb[n>>1] >> ((1 - (n&1)) << 2)) & 0xF];
}

int segbuf_push_bio(struct segment_buffer* buf, struct bio *bio) {
    int err = 0;
    void *buffer, *pipe;
    struct record record = {0};
    dm_block_t lba = bio_get_block_address(bio);
    DEFAULT_SEGMENT_BUFFER_THIS_POINTER_DECLARE

    buffer = this->buffer + this->cur_sector * SECTOR_SIZE;
    pipe = this->pipe + this->cur_sector * SECTOR_SIZE;

    if (bio_sectors(bio) >= SECTORS_PER_BLOCK)
        goto fill_buffer;

    err = sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &record);
    if (!err) {
        dm_block_t buf_begin, buf_end;

        buf_begin = this->cur_segment * BLOCKS_PER_SEGMENT;
        buf_end = buf_begin + this->cur_sector / SECTORS_PER_BLOCK;
        if (record.pba < buf_begin || record.pba >= buf_end) {
            loff_t addr;

            addr = record.pba * DATA_BLOCK_SIZE;
            kernel_read(sworndisk->data_region, buffer, DATA_BLOCK_SIZE, &addr);
            sworndisk->cipher->decrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, 
                record.key, record.iv, record.mac, record.pba, buffer);
        } else {
#ifdef DEBUG_CRYPT
            char str[512] = {0}, mac_hex[(AES_GCM_AUTH_SIZE << 1) + 1] = {0};
            char key_hex[(AES_GCM_KEY_SIZE << 1) + 1] = {0};
            char iv_hex[(AES_GCM_IV_SIZE << 1) + 1] = {0};
#endif

            buffer = this->buffer + (record.pba - buf_begin) * DATA_BLOCK_SIZE;
            pipe = this->pipe + (record.pba - buf_begin) * DATA_BLOCK_SIZE;
            bio_get_data(bio, buffer + bio_block_sector_offset(bio) * SECTOR_SIZE, bio_get_data_len(bio));
            sworndisk->cipher->encrypt(sworndisk->cipher, buffer, DATA_BLOCK_SIZE, 
                record.key, record.iv, record.mac, record.pba, pipe);
            sworndisk->lsm_tree->put(sworndisk->lsm_tree, lba, record_copy(&record));
#ifdef DEBUG_CRYPT
            btox(key_hex, record.key, AES_GCM_KEY_SIZE << 1);
            btox(iv_hex, record.iv, AES_GCM_IV_SIZE << 1);
            btox(mac_hex, record.mac, AES_GCM_AUTH_SIZE << 1);
            sprintf(str, "pba: %lld, key: %s, iv: %s, mac: %s, checksum: %u\n", 
                record.pba, key_hex, iv_hex, mac_hex, dm_bm_checksum(pipe, DATA_BLOCK_SIZE, 0));
            kernel_write(this->crypt_info, str, strlen(str), &this->crypt_info_pos);
#endif
            return MODIFY_IN_MEM_BUFFER;
        }
    }

fill_buffer:
    bio_get_data(bio, buffer + bio_block_sector_offset(bio) * SECTOR_SIZE, bio_get_data_len(bio));
    buf->push_block(buf, lba, buffer);
    return PUSH_NEW_BLOCK;
}

void segbuf_push_block(struct segment_buffer* buf, dm_block_t lba, void* buffer) {
    dm_block_t pba;
    void *pipe = NULL, *block = NULL;
    bool exists = false;
    struct record *record, pre;

#ifdef DEBUG_CRYPT
    char str[512] = {0};
    char mac_hex[(AES_GCM_AUTH_SIZE << 1) + 1] = {0};
    char key_hex[(AES_GCM_KEY_SIZE << 1) + 1] = {0};
    char iv_hex[(AES_GCM_IV_SIZE << 1) + 1] = {0};
#endif
    DEFAULT_SEGMENT_BUFFER_THIS_POINTER_DECLARE

    exists = !(sworndisk->lsm_tree->search(sworndisk->lsm_tree, lba, &pre));

    pba = (this->cur_segment * SECTOES_PER_SEGMENT + this->cur_sector) / SECTORS_PER_BLOCK;
    record = record_create(pba, NULL, NULL, NULL);
    block = this->buffer + this->cur_sector * SECTOR_SIZE;
    memmove(block, buffer, DATA_BLOCK_SIZE);
    pipe = this->pipe + this->cur_sector * SECTOR_SIZE;
    sworndisk->cipher->encrypt(sworndisk->cipher, block, DATA_BLOCK_SIZE, 
        record->key, record->iv, record->mac, record->pba, pipe);

#ifdef DEBUG_CRYPT
    btox(key_hex, record->key, AES_GCM_KEY_SIZE << 1);
    btox(iv_hex, record->iv, AES_GCM_IV_SIZE << 1);
    btox(mac_hex, record->mac, AES_GCM_AUTH_SIZE << 1);
    sprintf(str, "lba: %lld, pba: %lld, key: %s, iv: %s, mac: %s, checksum: %u\n", 
        lba, record->pba, key_hex, iv_hex, mac_hex, dm_bm_checksum(pipe, DATA_BLOCK_SIZE, 0));
    kernel_write(this->crypt_info, str, strlen(str), &this->crypt_info_pos);
#endif

    sworndisk->lsm_tree->put(sworndisk->lsm_tree, lba, record);
    sworndisk->meta->rit->set(sworndisk->meta->rit, pba, lba);
    if (exists)
        sworndisk->meta->dst->return_block(sworndisk->meta->dst, pre.pba);

    this->cur_sector += SECTORS_PER_BLOCK;
    if (this->cur_sector >= SECTOES_PER_SEGMENT) {
        buf->flush_bios(buf);
        this->cur_sector = 0;
        sworndisk->seg_allocator->get_next_free_segment(sworndisk->seg_allocator, &this->cur_segment);
    }
}

void segbuf_flush_bios(struct segment_buffer* buf) {
    int size = 0;
    loff_t addr;
    DEFAULT_SEGMENT_BUFFER_THIS_POINTER_DECLARE

    addr = this->cur_segment * BLOCKS_PER_SEGMENT * DATA_BLOCK_SIZE;
    size = kernel_write(sworndisk->data_region, this->pipe, SEGMENT_BUFFER_SIZE, &addr);
    if (size != SEGMENT_BUFFER_SIZE)
        DMERR("segbuf flush bio error, transferred: %d", size);
}

int segbuf_query_bio(struct segment_buffer* buf, struct bio* bio) {
    sector_t bi_sector, begin, end;
    DEFAULT_SEGMENT_BUFFER_THIS_POINTER_DECLARE

    bi_sector = bio_get_sector(bio);
    begin = this->cur_segment * SECTOES_PER_SEGMENT;
    end = begin + this->cur_sector;

    if (bi_sector < begin || bi_sector + bio_sectors(bio) > end)
        return -ENODATA;

    bio_set_data(bio, this->buffer + (bi_sector - begin) * SECTOR_SIZE, bio_get_data_len(bio));
    return 0;
}

void* segbuf_implementer(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINTER_DECLARE

    return this;
}

void segbuf_destroy(struct segment_buffer* buf) {
    DEFAULT_SEGMENT_BUFFER_THIS_POINTER_DECLARE

    buf->flush_bios(buf);
    vfree(this->buffer);
    vfree(this->pipe);
#ifdef DEBUG_CRYPT
    filp_close(this->crypt_info, NULL);
#endif
    kfree(this);
}

int segbuf_init(struct default_segment_buffer *buf, struct dm_sworndisk_target* sworndisk) {
    int err;

    err = sworndisk->seg_allocator->get_next_free_segment(sworndisk->seg_allocator, &buf->cur_segment);
    if (err)
        return err;

    buf->cur_sector = 0;
    buf->sworndisk = sworndisk;

    buf->buffer = vmalloc(SEGMENT_BUFFER_SIZE);
    if (!buf->buffer) {
        err = -ENOMEM;
        goto bad;
    }

    buf->pipe = vmalloc(SEGMENT_BUFFER_SIZE);
    if (!buf->pipe) {
        err = -ENOMEM;
        goto bad;
    }
         
#ifdef DEBUG_CRYPT
    buf->crypt_info_pos = 0;
    buf->crypt_info = filp_open("/home/lnhoo/crypt_info", O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
#endif

    buf->segment_buffer.push_bio = segbuf_push_bio;
    buf->segment_buffer.push_block = segbuf_push_block;
    buf->segment_buffer.query_bio = segbuf_query_bio;
    buf->segment_buffer.flush_bios = segbuf_flush_bios;
    buf->segment_buffer.implementer = segbuf_implementer;
    buf->segment_buffer.destroy = segbuf_destroy;

    return 0;

bad:
    if (buf->buffer)
        vfree(buf->buffer);
    if (buf->pipe)
        vfree(buf->pipe);
#ifdef DEBUG_CRYPT
    if (buf->crypt_info)
        filp_close(buf->crypt_info, NULL);
#endif
    return err;
};

struct segment_buffer* segbuf_create(struct dm_sworndisk_target* sworndisk) {
    int r;
    struct default_segment_buffer* buf;

    buf = kzalloc(sizeof(struct default_segment_buffer), GFP_KERNEL);
    if (!buf)
        return NULL;
    
    r = segbuf_init(buf, sworndisk);
    if (r)
        return NULL;
    return &buf->segment_buffer;
}