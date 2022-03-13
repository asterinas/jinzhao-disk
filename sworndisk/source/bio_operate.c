#include <linux/slab.h>

#include "../include/dm_sworndisk.h"
#include "../include/bio_operate.h"

void bio_crypt(struct bio* bio);
void bio_async_io_context_destroy(struct bio_async_io_context* ctx);

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

void bio_async_io_work_complete(struct work_struct* ws) {
    char* data;
    sector_t lba;
    sector_t pba;
    struct bio* bio;
    struct mt_value* mv;
    struct memtable* mt;
    struct cache_entry* entry;
    struct generic_cache* cache;
    struct bio_crypt_context* crypt_ctx;
    struct bio_async_io_context* io_ctx;

    io_ctx = container_of(ws, struct bio_async_io_context, complete);
    crypt_ctx = io_ctx->crypt_ctx;
    lba = crypt_ctx->lba;
    bio = io_ctx->bio;
    bio->bi_iter = io_ctx->bi_iter;
    cache = io_ctx->cache;
    mt = io_ctx->mt;
    pba = io_ctx->pba;

    if (bio_op(bio) == REQ_OP_READ) {
        bio_crypt(bio);
        data = bio_data_buffer_copy(bio);
        entry = cache_entry_create(lba, data, bio_get_data_len(bio), false);
        cache->set(cache, lba, entry);
        bio_endio(io_ctx->origin);
    }

    if (bio_op(bio) == REQ_OP_WRITE) {
        mv = mt_value_create(pba, crypt_ctx->key, crypt_ctx->iv, crypt_ctx->mac);
        if (IS_ERR_OR_NULL(mv))
            goto cleanup;
        mt->put(mt, lba, mv);
cleanup:
        cache->unlock(cache, lba);
        bio_free_pages(bio);
    }

    bio_async_io_context_destroy(io_ctx);
}

void crypt_bio_endio(struct bio* bio) {
   struct bio_async_io_context* io_ctx;

   io_ctx = bio->bi_private;
   queue_work(io_ctx->wq, &io_ctx->complete);
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

void bio_crypt_context_init(struct bio_crypt_context* ctx, sector_t lba, char* key, char* iv, char* mac, struct aead_cipher* cipher) {
    ctx->lba = lba;
    ctx->key = key;
    ctx->iv = iv;
    ctx->mac = mac;
    ctx->cipher = cipher;
}

void bio_crypt_context_destroy(struct bio_crypt_context* ctx) {
    if (ctx)
        kfree(ctx);
}

struct bio_crypt_context* bio_crypt_context_create(sector_t lba, char* key, 
  char* iv, char* mac, struct aead_cipher* cipher) {
    struct bio_crypt_context* ctx;

    ctx = kmalloc(sizeof(struct bio_crypt_context), GFP_KERNEL);
    if (!ctx) {
        DMERR("bio_crypt_context_create alloc mem error\n");
        return NULL;
    }

    if (key == NULL)
        cipher->get_random_key(&key, AES_GCM_KEY_SIZE);
    if (iv == NULL)
        cipher->get_random_iv(&iv, AES_GCM_IV_SIZE);
    if (mac == NULL)
        mac = kmalloc(AES_GCM_AUTH_SIZE, GFP_KERNEL);
    
    if (!key || !iv || !mac)
        return NULL;

    bio_crypt_context_init(ctx, lba, key, iv, mac, cipher);
    return ctx;
}

void bio_crypt(struct bio* bio) {
    int r;
    char* key;
    char* iv;
    char* mac;
    char* kaddr;
    sector_t lba;
    struct aead_cipher* cipher;
    struct bio_async_io_context* io_ctx;
    struct bio_crypt_context* crypt_ctx;

    io_ctx = bio->bi_private;
    crypt_ctx = io_ctx->crypt_ctx;
    lba = crypt_ctx->lba;
    key = crypt_ctx->key;
    iv = crypt_ctx->iv;
    mac = crypt_ctx->mac;
    cipher = crypt_ctx->cipher;

    kaddr = kmap_atomic(bio_page(bio));
    r = (bio_op(bio) == REQ_OP_READ ? cipher->decrypt : cipher->encrypt)
      (cipher, kaddr+bio_offset(bio), bio_cur_bytes(bio), key, AES_GCM_KEY_SIZE, iv, mac, AES_GCM_AUTH_SIZE, lba);
    if (r) {
        DMINFO("bio_crypt error: %ld", lba);
        goto exit;
    }
exit:
    kunmap_atomic(kaddr);
}

void bio_async_io_context_destroy(struct bio_async_io_context* ctx) {
    if (ctx && ctx->crypt_ctx)
        bio_crypt_context_destroy(ctx->crypt_ctx);
    if (ctx)
        kfree(ctx);
}

void bio_async_io_work(struct work_struct* ws) {
    struct bio_async_io_context* io_ctx;

    io_ctx = container_of(ws, struct bio_async_io_context, work);
    bio_crypt(io_ctx->bio);
    submit_bio(io_ctx->bio);
}

void bio_async_io_context_init(struct bio_async_io_context* ctx, struct bio* bio, 
  struct bio* origin, struct memtable* mt, struct generic_cache* cache, struct bio_crypt_context* crypt_ctx`) {
    ctx->bio = bio;
    ctx->origin = origin;
    ctx->mt = mt;
    ctx->bi_iter = origin->bi_iter;
    ctx->cache = cache;
    ctx->crypt_ctx = crypt_ctx;
    INIT_WORK(&ctx->work, bio_async_io_work);
    INIT_WORK(&ctx->complete, bio_async_io_work_complete);
}

struct bio_async_io_context* bio_async_io_context_create(struct bio* bio, 
  struct bio* origin, struct memtable* mt, struct generic_cache* cache, struct bio_crypt_context* crypt_ctx) {
    struct bio_async_io_context* ctx;

    ctx = kmalloc(sizeof(struct bio_async_io_context), GFP_KERNEL);
    if (!ctx)
        return NULL;
    bio_async_io_context_init(ctx, bio, origin, mt, cache, crypt_ctx);
    return ctx;
}

char* bio_data_buffer_copy(struct bio* bio) {
    size_t len;
    char* buffer;
    char* kaddr;
    size_t offset;
    struct bio_vec bvec;
    struct bvec_iter bi_iter;

    len = bio_get_data_len(bio);
    buffer = kmalloc(len, GFP_KERNEL);
    if (!buffer)
        return NULL;
    
    offset = 0;
    bio_for_each_segment(bvec, bio, bi_iter) {
        kaddr = kmap_atomic(bvec.bv_page);
        memcpy(buffer+offset, kaddr+bvec.bv_offset, bvec.bv_len);
        kunmap_atomic(kaddr);
        offset += bvec.bv_len;
    }

    return buffer;
}

int bio_fill_data_buffer(struct bio* bio, char* buffer, size_t len) {
    char* kaddr;
    size_t offset;
    struct bio_vec bvec;
    struct bvec_iter bi_iter;

    if (len > bio_get_data_len(bio))
        return -EAGAIN;

    offset = 0;
    bio_for_each_segment(bvec, bio, bi_iter) {
        kaddr = kmap_atomic(bvec.bv_page);
        memcpy(kaddr+bvec.bv_offset, buffer+offset, bvec.bv_len);
        kunmap_atomic(kaddr);
        offset += bvec.bv_len;
    }

    return 0;
}