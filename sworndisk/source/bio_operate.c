#include <linux/slab.h>

#include "../include/dm_sworndisk.h"
#include "../include/bio_operate.h"

void bio_decrypt(struct bio* bio);

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

void crypt_bio_endio(struct bio* bio) {
    struct bio_crypt_context* ctx;

    ctx = bio->bi_private;
    bio->bi_iter = ctx->bi_iter;
    switch (bio_op(bio)) {
        case REQ_OP_READ:
            bio_decrypt(bio);
            break;
        case REQ_OP_WRITE:
            bio_free_pages(bio);
            break;
    }
    ctx->origin->bi_status = bio->bi_status;
    bio_endio(ctx->origin);
    if (ctx)
        kfree(ctx);
}

struct page* page_deepcopy_data(struct page* src, size_t offset, size_t len) {
    struct page* dst;
    char* s_addr;
    char* d_addr;

    dst = alloc_page(GFP_NOIO);
    if (IS_ERR_OR_NULL(dst))
        return NULL;

    s_addr = kmap_atomic(src);
    d_addr = kmap_atomic(dst);
    memcpy(d_addr+offset, s_addr+offset, len);
    kunmap_atomic(s_addr);
    kunmap_atomic(d_addr);

    return dst;
}

struct bio* bio_deepcopy_data(struct bio* src, gfp_t mask, struct bio_set* bs) {
    struct bio* dst;
    struct bio_vec bvec;
    struct bvec_iter bi_iter;
    size_t nr_segment;
    struct page* page;

    nr_segment = bio_segments(src);
    dst = bio_alloc_bioset(mask, nr_segment, bs);
    if (IS_ERR_OR_NULL(dst))
        return NULL;
    bio_for_each_segment(bvec, src, bi_iter) {
        page = page_deepcopy_data(bvec.bv_page, bvec.bv_offset, bvec.bv_len);
        if (IS_ERR_OR_NULL(page))
            return NULL;
        bio_add_page(dst, page, bvec.bv_len, bvec.bv_offset);
    }
    return dst;
}

struct bio* bio_copy(struct bio* src, gfp_t mask, struct bio_set* bs) {
    struct bio* dst;

    dst = (bio_op(src) == REQ_OP_WRITE ? bio_deepcopy_data(src, mask, bs) : bio_clone_fast(src, mask, bs));
    if (IS_ERR_OR_NULL(dst)) 
        return NULL;

    dst->bi_disk = src->bi_disk;
	dst->bi_opf = src->bi_opf;
	dst->bi_write_hint = src->bi_write_hint;
	dst->bi_iter.bi_sector = src->bi_iter.bi_sector;
	dst->bi_iter.bi_size = src->bi_iter.bi_size;
    dst->bi_end_io = crypt_bio_endio;
    return dst;
}

void bio_crypt_context_init(struct bio_crypt_context* ctx, sector_t lba, char* key, 
  char* iv, char* mac, struct bio* origin, struct aead_cipher* cipher) {
      ctx->lba = lba;
      ctx->key = key;
      ctx->iv = iv;
      ctx->mac = mac;
      ctx->origin = origin;
      ctx->bi_iter = origin->bi_iter;
      ctx->cipher = cipher;
}

struct bio_crypt_context* bio_crypt_context_create(sector_t lba, char* key, 
  char* iv, char* mac, struct bio* origin, struct aead_cipher* cipher) {
    struct bio_crypt_context* ctx;

    ctx = kmalloc(sizeof(struct bio_crypt_context), GFP_KERNEL);
    if (!ctx) {
        DMERR("bio_crypt_context_create alloc mem error\n");
        return NULL;
    }

    bio_crypt_context_init(ctx, lba, key, iv, mac, origin, cipher);
    return ctx;
}

void bio_decrypt(struct bio* bio) {
    int r;
    char* key;
    char* iv;
    char* mac;
    char* kaddr;
    sector_t lba;
    struct aead_cipher* cipher;
    struct bio_crypt_context* ctx;

    ctx = bio->bi_private;
    lba = ctx->lba;
    key = ctx->key;
    iv = ctx->iv;
    mac = ctx->mac;
    cipher = ctx->cipher;

    kaddr = kmap_atomic(bio_page(bio));
    r = cipher->decrypt(cipher, kaddr+bio_offset(bio), bio_cur_bytes(bio), key, AES_GCM_KEY_SIZE, iv, mac, AES_GCM_AUTH_SIZE, lba);
    if (r) {
        DMINFO("bio_decrypt error");
        goto exit;
    }
exit:
    kunmap_atomic(kaddr);
}