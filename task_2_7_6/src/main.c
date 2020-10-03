#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>


// -------------------------------------- Buddy allocator ------------------------------------------

size_t get_slab_size(size_t order) {
    static const size_t MIN_SLAB_ORDER = 12;
    return 1 << (order + MIN_SLAB_ORDER);
}

void* alloc_slab(int order) {
    size_t size = get_slab_size(order);
    void* ptr = aligned_alloc(size, size);
    return ptr;
}

void free_slab(void* ptr) {
    free(ptr);
}

// ------------------------------------ Chunks ----------------------------------------------------

// chunk layout
// | prev | next | size | is_free | data | start |
// chunk_ptr prev - points to the previous free chunk
// chunk_ptr next - points to the next free chunk
// size_r size - size of the whole chunk including fields (prev, next, size, is_free, start)
// char is_free - flag indicating that chunk is free
// chunk_ptr start - pointer to the begining of the chunk

typedef char* chunk_ptr;

const size_t PREV_FIELD_SIZE = sizeof(chunk_ptr);
const size_t NEXT_FIELD_SIZE = sizeof(chunk_ptr);
const size_t SIZE_FIELD_SIZE = sizeof(size_t);
const size_t IS_FREE_FIELD_SIZE = sizeof(char);
const size_t START_FIELD_SIZE = sizeof(chunk_ptr);
const size_t FIELDS_SIZE = PREV_FIELD_SIZE + NEXT_FIELD_SIZE
    + SIZE_FIELD_SIZE + IS_FREE_FIELD_SIZE + START_FIELD_SIZE;

chunk_ptr get_chunk_prev(chunk_ptr pchunk) {
    chunk_ptr* pprev = (chunk_ptr*)((char*)(pchunk));
    return *pprev;
}

void set_chunk_prev(chunk_ptr pchunk, chunk_ptr prev) {
    chunk_ptr* pprev = (chunk_ptr*)((char*)(pchunk));
    *pprev = prev;
}

chunk_ptr get_chunk_next(chunk_ptr pchunk) {
    chunk_ptr* pnext = (chunk_ptr*)((char*)(pchunk) + PREV_FIELD_SIZE);
    return *pnext;
}

void set_chunk_next(chunk_ptr pchunk, chunk_ptr next) {
    chunk_ptr* pnext = (chunk_ptr*)((char*)(pchunk) + PREV_FIELD_SIZE);
    *pnext = next;
}

size_t get_chunk_size(chunk_ptr pchunk) {
    size_t* psize = (size_t*)((char*)(pchunk) + PREV_FIELD_SIZE + NEXT_FIELD_SIZE);
    return *psize;
}

void set_chunk_size(chunk_ptr pchunk, size_t size) {
    size_t* psize = (size_t*)((char*)(pchunk) + PREV_FIELD_SIZE + NEXT_FIELD_SIZE);
    *psize = size;
}

char get_chunk_is_free(chunk_ptr pchunk) {
    char* pis_free = (char*)(
        (char*)(pchunk) + PREV_FIELD_SIZE + NEXT_FIELD_SIZE + SIZE_FIELD_SIZE);
    return *pis_free;
}

void set_chunk_is_free(chunk_ptr pchunk, char is_free) {
    char* pis_free = (char*)(
        (char*)(pchunk) + PREV_FIELD_SIZE + NEXT_FIELD_SIZE + SIZE_FIELD_SIZE);
    *pis_free = is_free;
}

chunk_ptr get_chunk_start(chunk_ptr pchunk) {
    chunk_ptr* pstart = (chunk_ptr*)((char*)(pchunk) + get_chunk_size(pchunk) - START_FIELD_SIZE);
    return *pstart;
}

void set_chunk_start(chunk_ptr pchunk, chunk_ptr start) {
    chunk_ptr* pstart = (chunk_ptr*)((char*)(pchunk) + get_chunk_size(pchunk) - START_FIELD_SIZE);
    *pstart = start;
}

char* get_chunk_begin(chunk_ptr pchunk) {
    return (char*)(pchunk);
}

char* get_chunk_end(chunk_ptr pchunk) {
    return get_chunk_begin(pchunk) + get_chunk_size(pchunk);
}


chunk_ptr get_chunk_ptr_from_data(void* data) {
    return (chunk_ptr)(
        (char*)(data) - PREV_FIELD_SIZE - NEXT_FIELD_SIZE - SIZE_FIELD_SIZE - IS_FREE_FIELD_SIZE);
}

void* get_chunk_data(chunk_ptr pchunk) {
    return (void*)(
        (char*)(pchunk) + PREV_FIELD_SIZE + NEXT_FIELD_SIZE + SIZE_FIELD_SIZE + IS_FREE_FIELD_SIZE);
}

chunk_ptr get_left_chunk(chunk_ptr pchunk) {
    char* begin = (char*)(pchunk);
    chunk_ptr* pstart = (chunk_ptr*)(begin - START_FIELD_SIZE);
    return *pstart;
}

chunk_ptr get_right_chunk(chunk_ptr pchunk) {
    char* begin = (char*)(pchunk);
    return (chunk_ptr)(begin + get_chunk_size(pchunk));
}

chunk_ptr init_chunk_at(
        char* ptr, chunk_ptr prev, chunk_ptr next, size_t size, char is_free) {
    assert(size >= FIELDS_SIZE);
    chunk_ptr pchunk = (chunk_ptr)(ptr);
    set_chunk_prev(pchunk, prev);
    set_chunk_next(pchunk, next);
    set_chunk_size(pchunk, size);
    set_chunk_is_free(pchunk, is_free);
    set_chunk_start(pchunk, pchunk);
    return pchunk;
}

// ------------------------------------ Chunk List -------------------------------------------------

struct ChunkList {
    chunk_ptr head;
    chunk_ptr tail;
};

chunk_ptr get_begin(struct ChunkList* pchunks) {
    return pchunks->head;
}

chunk_ptr get_end(struct ChunkList* pchunks) {
    return pchunks->tail;
}

int is_empty(const struct ChunkList* pchunks) {
    return pchunks->head == pchunks->tail;
}

void insert_chunk_in_list_at(struct ChunkList* pchunks, chunk_ptr pwhere, chunk_ptr pchunk) {
    assert(pwhere != NULL);
    assert(pchunk != NULL);
    chunk_ptr pprev_chunk = get_chunk_prev(pwhere);
    set_chunk_prev(pchunk, pprev_chunk);
    if (pprev_chunk != NULL) {
        set_chunk_next(pprev_chunk, pchunk);
    }
    set_chunk_prev(pwhere, pchunk);
    set_chunk_next(pchunk, pwhere);
    if (pchunks->head == pwhere) {
        pchunks->head = pchunk;
    }
}

chunk_ptr erase_chunk_from_list_at(struct ChunkList* pchunks, chunk_ptr pwhere) {
    assert(!is_empty(pchunks));
    assert(pwhere != pchunks->tail);
    chunk_ptr pprev_chunk = get_chunk_prev(pwhere);
    chunk_ptr pnext_chunk = get_chunk_next(pwhere);
    if (pprev_chunk != NULL) {
        set_chunk_next(pprev_chunk, pnext_chunk);
    }
    set_chunk_prev(pnext_chunk, pprev_chunk);
    set_chunk_prev(pwhere, NULL);
    set_chunk_next(pwhere, NULL);
    if (pchunks->head == pwhere) {
        pchunks->head = pnext_chunk;
    }
    return pnext_chunk;
}

// -------------------------------------- Arena ----------------------------------------------------

struct Arena {
    void* buffer;
    size_t size;
    struct ChunkList chunks;
};

char* get_arena_begin(struct Arena* parena) {
    return (char*)(parena->buffer);
}

char* get_arena_end(struct Arena* parena) {
    return (char*)(parena->buffer) + parena->size;
}

void init_chunk_list(struct ChunkList* pchunks, chunk_ptr pchunk) {
    pchunks->head = pchunk;
    pchunks->tail = pchunk;
}

chunk_ptr get_zero_chunk(struct Arena* parena) {
    assert(parena->size >= FIELDS_SIZE);
    char* begin = (char*)(parena->buffer);
    return init_chunk_at(begin + parena->size - FIELDS_SIZE, NULL, NULL, FIELDS_SIZE, 1);
}

chunk_ptr get_initial_chunk(struct Arena* parena) {
    assert(parena->size >= FIELDS_SIZE);
    char* begin = (char*)(parena->buffer);
    return init_chunk_at(begin, NULL, NULL, parena->size - FIELDS_SIZE, 1);
}

void init_arena(struct Arena* parena) {
    init_chunk_list(&parena->chunks, get_zero_chunk(parena));
    insert_chunk_in_list_at(&parena->chunks, get_begin(&parena->chunks), get_initial_chunk(parena));
}

void setup_arena_impl(struct Arena* arena, void* buf, size_t size) {
    arena->buffer = buf;
    arena->size = size;
    init_arena(arena);
}

int can_allocate(chunk_ptr pchunk, size_t size) {
    return get_chunk_size(pchunk) >= size + FIELDS_SIZE && get_chunk_is_free(pchunk);
}

chunk_ptr alloc_from_chunk(chunk_ptr pchunk, size_t size, chunk_ptr* presidual) {
    assert(can_allocate(pchunk, size));
    size_t pchunk_size = get_chunk_size(pchunk);
    size_t presidual_size = pchunk_size - size - FIELDS_SIZE;
    chunk_ptr palloc_chunk = NULL;
    if (presidual_size > FIELDS_SIZE) {
        char* begin = (char*)(pchunk);
        *presidual = init_chunk_at(begin, NULL, NULL, presidual_size, 1);
        palloc_chunk = init_chunk_at(
            begin + presidual_size, NULL, NULL, pchunk_size - presidual_size, 0);
    } else {
        *presidual = NULL;
        set_chunk_is_free(pchunk, 0);
        palloc_chunk = pchunk;
    }
    return palloc_chunk;
}

void* alloc_arena_impl(struct Arena* parena, size_t size) {
    void* ptr = NULL;
    chunk_ptr pchunk = get_begin(&parena->chunks);
    while (pchunk != get_end(&parena->chunks)) {
        if (can_allocate(pchunk, size)) {
            chunk_ptr presidual = NULL;
            chunk_ptr pwhere = erase_chunk_from_list_at(&parena->chunks, pchunk);
            chunk_ptr palloc_chunk = alloc_from_chunk(pchunk, size, &presidual);
            assert(palloc_chunk != NULL);
            if (presidual != NULL) {
                insert_chunk_in_list_at(&parena->chunks, pwhere, presidual);
            }
            ptr = get_chunk_data(palloc_chunk);
            break;
        } else {
            pchunk = get_chunk_next(pchunk);
        }
    }
    return ptr;
}

chunk_ptr get_left_chunk_in_arena(struct Arena* parena, chunk_ptr pchunk) {
    char* arena_left_tip = get_arena_begin(parena);
    if (arena_left_tip == get_chunk_begin(pchunk)) {
        return NULL;
    }
    return get_left_chunk(pchunk);
}

chunk_ptr get_right_chunk_in_arena(struct Arena* parena, chunk_ptr pchunk) {
    // arena_right_tip must be adjusted because we use one chunk for chunks.tail
    char* arena_right_tip = get_arena_end(parena) - FIELDS_SIZE;
    if (arena_right_tip == get_chunk_end(pchunk)) {
        return NULL;
    }
    return get_right_chunk(pchunk);
}

void free_arena_impl(struct Arena* parena, void* ptr) {
    if (ptr == NULL) {
        return;
    }
    chunk_ptr pchunk = get_chunk_ptr_from_data(ptr);
    assert(!get_chunk_is_free(pchunk));
    chunk_ptr pleft_chunk = get_left_chunk_in_arena(parena, pchunk);
    chunk_ptr pright_chunk = get_right_chunk_in_arena(parena, pchunk);
    char* left_tip = get_chunk_begin(pchunk);
    char* right_tip = get_chunk_end(pchunk);
    if (pleft_chunk != NULL && get_chunk_is_free(pleft_chunk)) {
        left_tip = get_chunk_begin(pleft_chunk);
        erase_chunk_from_list_at(&parena->chunks, pleft_chunk);
    }
    if (pright_chunk != NULL && get_chunk_is_free(pright_chunk)) {
        right_tip = get_chunk_end(pright_chunk);
        erase_chunk_from_list_at(&parena->chunks, pright_chunk);
    }
    assert(left_tip <= right_tip);
    size_t new_chunk_size = right_tip - left_tip;
    chunk_ptr pnew_chunk = init_chunk_at(left_tip, NULL, NULL, new_chunk_size, 1);
    insert_chunk_in_list_at(&parena->chunks, get_begin(&parena->chunks), pnew_chunk);
}

void release_arena_impl(struct Arena* arena) {
    free_slab(arena->buffer);
    arena->buffer = NULL;
    arena->size = 0;
}

struct Arena ARENA;

void setup_arena(void* buf, size_t size) {
    setup_arena_impl(&ARENA, buf, size);
}

void* alloc_arena(size_t size) {
    void* ptr = alloc_arena_impl(&ARENA, size);
    return ptr;
}

void free_arena(void* p) {
    free_arena_impl(&ARENA, p);
}

void release_arena() {
    release_arena_impl(&ARENA);
}

// -------------------------------------- Slab entry ------------------------------------------------

struct slab;

typedef char* slab_entry_ptr;

slab_entry_ptr get_slab_entry_next(slab_entry_ptr ptr) {
    slab_entry_ptr* pnext = (slab_entry_ptr*)(ptr);
    return *pnext;
}

void set_slab_entry_next(slab_entry_ptr ptr, slab_entry_ptr next) {
    slab_entry_ptr* pnext = (slab_entry_ptr*)(ptr);
    *pnext = next;
}

void* get_slab_entry_data(slab_entry_ptr ptr) {
    return (void*)(ptr + sizeof(slab_entry_ptr));
}

slab_entry_ptr get_data_slab_entry(void* ptr) {
    return (slab_entry_ptr)((char*)ptr - sizeof(slab_entry_ptr));
}

struct slab* get_data_owner_from_slab_header(void* data) {
    struct slab** powner = (struct slab**)(data);
    return *powner;
}

void set_data_owner_to_slab_header(void* data, struct slab* owner) {
    struct slab** powner = (struct slab**)(data);
    *powner = owner;
}

// -------------------------------------- Slabs ----------------------------------------------------

size_t get_slab_header_size() {
    return sizeof(struct slab*);
}

size_t get_slab_entry_size(size_t object_size) {
    return object_size + sizeof(slab_entry_ptr);
}

size_t get_slab_capacity(size_t object_size, size_t slab_order) {
    size_t slab_size = get_slab_size(slab_order);
    size_t header_size = get_slab_header_size();
    if (slab_size < header_size) {
        return 0;
    }
    return (slab_size - header_size) / get_slab_entry_size(object_size);
}


struct slab_node;

struct slab {
    size_t object_size;
    size_t slab_order;
    size_t objects_count;
    struct slab_node* owner;
    slab_entry_ptr head;
    void* data;
};

void slab_setup(struct slab* slb, size_t object_size, size_t slab_order, struct slab_node* owner) {
    assert(slb != NULL);
    slb->object_size = object_size;
    slb->slab_order = slab_order;
    slb->objects_count = 0;
    slb->owner = owner;
    slb->data = alloc_slab(slb->slab_order);

    size_t entry_size = get_slab_entry_size(slb->object_size);
    size_t header_size = get_slab_header_size();

    set_data_owner_to_slab_header(slb->data, slb);

    slb->head = (slab_entry_ptr)(slb->data) + header_size;
    slab_entry_ptr current = slb->head;
    slab_entry_ptr end = (slab_entry_ptr)slb->data + get_slab_size(slb->slab_order);
    while (current + entry_size < end) {
        set_slab_entry_next(current, current + entry_size);
        current = current + entry_size;
    }
    set_slab_entry_next(current, NULL);
}

void slab_release(struct slab* slb) {
    assert(slb != NULL);
    slb->object_size = 0;
    slb->slab_order = 0;
    slb->objects_count = 0;
    slb->owner = NULL;
    slb->head = NULL;
    free_slab(slb->data);
}

struct slab* slab_create(size_t object_size, size_t slab_order, struct slab_node* owner) {
    struct slab* slb = (struct slab*)alloc_arena(sizeof(struct slab));
    slab_setup(slb, object_size, slab_order, owner);
    return slb;
}

void slab_destroy(struct slab* slb) {
    assert(slb != NULL);
    slab_release(slb);
    free_arena(slb);
}

bool is_empty_slab(struct slab* slb) {
    assert(slb != NULL);
    return slb->objects_count == 0;
}


bool is_full_slab(struct slab* slb) {
    assert(slb != NULL);
    return slb->objects_count >= get_slab_capacity(slb->object_size, slb->slab_order);
}

void* allocate_from_slab(struct slab* slb) {
    assert(slb != NULL);
    if (slb->head == NULL) {
        return NULL;
    }
    slab_entry_ptr head = slb->head;
    slb->head = get_slab_entry_next(slb->head);
    ++slb->objects_count;
    return get_slab_entry_data(head);
}

void free_from_slab(struct slab* slb, void* ptr) {
    assert(slb != NULL);
    if (ptr == NULL) {
        return;
    }
    assert(!is_empty_slab(slb));
    slab_entry_ptr entry = get_data_slab_entry(ptr);
    set_slab_entry_next(entry, slb->head);
    slb->head = entry;
    --slb->objects_count;
}

struct slab* find_slab(void* ptr, size_t slab_order) {
    assert(ptr != NULL);
    slab_entry_ptr entry = get_data_slab_entry(ptr);
    void* data = (void*)((size_t)(entry) & ~(get_slab_size(slab_order) - 1));
    return get_data_owner_from_slab_header(data);
}

struct slab_node* get_owner_slab_node(struct slab* slb) {
    assert(slb != NULL);
    return slb->owner;
}
// -------------------------------------- Slab node ------------------------------------------------

struct slab_list;

struct slab_node {
    struct slab* slab;
    struct slab_list* owner;
    struct slab_node* prev;
    struct slab_node* next;
};


void slab_node_setup(
    struct slab_node* slb_node, struct slab* slb, struct slab_list* owner,
    struct slab_node* prev, struct slab_node* next) {
    assert(slb_node != NULL);
    slb_node->slab = slb;
    if (slb_node->slab != NULL) {
        slb_node->slab->owner = slb_node;
    }
    slb_node->owner = owner;
    slb_node->prev = prev;
    slb_node->next = next;
}

void slab_node_release(struct slab_node* slb_node) {
    assert(slb_node != NULL);
    if (slb_node->slab != NULL) {
        slab_release(slb_node->slab);
    }
    slb_node->owner = NULL;
    slb_node->prev = NULL;
    slb_node->next = NULL;
}

struct slab_node* slab_node_create(struct slab* slb, struct slab_list* owner) {
    struct slab_node* slb_node = (struct slab_node*)alloc_arena(sizeof(struct slab_node));
    slab_node_setup(slb_node, slb, owner, NULL, NULL);
    return slb_node;
}

void slab_node_destroy(struct slab_node* slb_node) {
    assert(slb_node != NULL);
    slab_node_release(slb_node);
    free_arena(slb_node);
}


// -------------------------------------- Slabs list --------------------------------------------

struct slabs_storage;

struct slab_list {
    struct slab_node* head;
    struct slab_node* tail;
    struct slabs_storage* owner;
};

void slab_list_setup(struct slab_list* collection, struct slabs_storage* storage) {
    assert(collection != NULL);
    collection->tail = slab_node_create(NULL, collection);
    collection->head = collection->tail;
    collection->owner = storage;
}

bool is_empty_slab_list(struct slab_list* collection) {
    assert(collection != NULL);
    return collection->head == collection->tail;
}

struct slab_node* get_slab_list_begin(struct slab_list* collection) {
    return collection->head;
}

struct slab_node* get_slab_list_end(struct slab_list* collection) {
    return collection->tail;
}

struct slabs_storage* get_owner_slabs_storage(struct slab_node* slb_node) {
    if (slb_node->owner != NULL) {
        return slb_node->owner->owner;
    }
    return NULL;
}

struct slab_node* insert_slab_node_into_slab_list(
    struct slab_list* collection, struct slab_node* where, struct slab_node* what) {
    assert(collection != NULL);
    assert(where != NULL);
    assert(what != NULL);
    if (where->prev == NULL) {
        collection->head = what;
    }
    what->prev = where->prev;
    if (where->prev != NULL) {
        where->prev->next = what;
    }
    what->next = where;
    where->prev = what;
    what->owner = collection;
    return what;
}

struct slab_node* extract_slab_node_from_slab_list(
    struct slab_list* collection, struct slab_node* where) {
    assert(collection != NULL);
    assert(where != NULL);
    assert(where != get_slab_list_end(collection));
    if (where == get_slab_list_begin(collection)) {
        collection->head = where->next;
    }
    struct slab_node* prev = where->prev;
    if (prev != NULL) {
        prev->next = where->next;
    }
    where->next->prev = prev;
    struct slab_node* there = where->next;
    where->next = NULL;
    where->prev = NULL;
    where->owner = NULL;
    return there;
}

struct slab_node* erase_slab_node_from_slab_list(
    struct slab_list* collection, struct slab_node* where) {
    struct slab_node* next = extract_slab_node_from_slab_list(collection, where);
    slab_node_destroy(where);
    return next;
}

void splice_slab_lists(
    struct slab_node* what, struct slab_list* src_collection,
    struct slab_node* where, struct slab_list* dest_collection) {
    extract_slab_node_from_slab_list(src_collection, what);
    insert_slab_node_into_slab_list(dest_collection, where, what);
}

void clear_slab_list(struct slab_list* collection) {
    struct slab_node* begin = get_slab_list_begin(collection);
    struct slab_node* end = get_slab_list_end(collection);
    while (begin != end) {
        begin = erase_slab_node_from_slab_list(collection, begin);
    }
}

void slab_list_release(struct slab_list* collection) {
    assert(collection != NULL);
    clear_slab_list(collection);
    slab_node_destroy(collection->tail);
    collection->head = NULL;
    collection->tail = NULL;
    collection->owner = NULL;
}


// -------------------------------------- Slabs storage --------------------------------------------

enum slabs_storage_type { FREE_SLABS = 0, FILL_SLABS = 1, FULL_SLABS = 2};

struct slabs_storage {
    struct slab_list collection;
    enum slabs_storage_type type;
};

void slabs_storage_setup(struct slabs_storage* storage, enum slabs_storage_type type) {
    assert(storage != NULL);
    slab_list_setup(&storage->collection, storage);
    storage->type = type;
}

void slabs_storage_release(struct slabs_storage* storage) {
    assert(storage != NULL);
    slab_list_release(&storage->collection);
}

bool is_empty_slabs_storage(struct slabs_storage* storage) {
    assert(storage != NULL);
    return is_empty_slab_list(&storage->collection);
}

void push_slab_node_to_slabs_storage(struct slabs_storage* storage, struct slab_node* slb_node) {
    assert(storage != NULL);
    insert_slab_node_into_slab_list(
        &storage->collection, get_slab_list_begin(&storage->collection), slb_node);
}

void move_slab_node_between_slabs_storages(
    struct slab_node* slb_node, struct slabs_storage* src_storage,
    struct slab_node* where, struct slabs_storage* dest_storage) {
    assert(slb_node != NULL);
    assert(src_storage != NULL);
    assert(where != NULL);
    assert(dest_storage != NULL);
    splice_slab_lists(slb_node, &src_storage->collection, where, &dest_storage->collection);
}

struct slab_node* get_slabs_storage_begin(struct slabs_storage* storage) {
    assert(storage != NULL);
    return get_slab_list_begin(&storage->collection);
}

struct slab_node* get_slabs_storage_end(struct slabs_storage* storage) {
    assert(storage != NULL);
    return get_slab_list_end(&storage->collection);
}

void clear_slabs_storage(struct slabs_storage* storage) {
    assert(storage != NULL);
    clear_slab_list(&storage->collection);
}

// -------------------------------------- Cache ----------------------------------------------------

struct cache {
    size_t object_size;
    size_t min_objects_count_per_slab;
    size_t slab_order;
    struct slabs_storage free_slabs;
    struct slabs_storage fill_slabs;
    struct slabs_storage full_slabs;
};

void cache_setup(struct cache* cache, size_t object_size) {
    assert(cache != NULL);
    size_t arena_order = 8;
    setup_arena(alloc_slab(arena_order), get_slab_size(arena_order));
    cache->object_size = object_size;
    cache->min_objects_count_per_slab = 64;
    assert(cache->min_objects_count_per_slab > 1);
    cache->slab_order = 0;
    while (
        cache->min_objects_count_per_slab
        > get_slab_capacity(cache->object_size, cache->slab_order)) {
        ++cache->slab_order;
    }
    slabs_storage_setup(&cache->free_slabs, FREE_SLABS);
    slabs_storage_setup(&cache->fill_slabs, FILL_SLABS);
    slabs_storage_setup(&cache->full_slabs, FULL_SLABS);
}

void cache_release(struct cache *cache) {
    assert(cache != NULL);
    slabs_storage_release(&cache->free_slabs);
    slabs_storage_release(&cache->fill_slabs);
    slabs_storage_release(&cache->full_slabs);
    cache->object_size = 0;
    cache->min_objects_count_per_slab = 0;
    cache->slab_order = 0;
    release_arena();
}

void* cache_alloc(struct cache* cache) {
    assert(cache != NULL);
    if (is_empty_slabs_storage(&cache->fill_slabs)) {
        if (is_empty_slabs_storage(&cache->free_slabs)) {
            struct slab* slb = slab_create(cache->object_size, cache->slab_order, NULL);
            struct slab_node* slb_node = slab_node_create(slb, NULL);
            push_slab_node_to_slabs_storage(&cache->free_slabs, slb_node);
        }
        move_slab_node_between_slabs_storages(
            get_slabs_storage_begin(&cache->free_slabs), &cache->free_slabs,
            get_slabs_storage_begin(&cache->fill_slabs), &cache->fill_slabs);
    }
    struct slab_node* slb_node = get_slabs_storage_begin(&cache->fill_slabs);
    assert(!is_full_slab(slb_node->slab));
    void* ptr = allocate_from_slab(slb_node->slab);
    assert(ptr != NULL);
    if (is_full_slab(slb_node->slab)) {
        move_slab_node_between_slabs_storages(
            slb_node, &cache->fill_slabs,
            get_slabs_storage_begin(&cache->full_slabs), &cache->full_slabs);
    }
    return ptr;
}

void cache_free(struct cache* cache, void* ptr) {
    assert(cache != NULL);
    if (ptr == NULL) {
        return;
    }
    struct slab* slb = find_slab(ptr, cache->slab_order);
    struct slab_node* slb_node = get_owner_slab_node(slb);
    struct slabs_storage* storage = get_owner_slabs_storage(slb_node);
    free_from_slab(slb, ptr);
    if (storage->type == FULL_SLABS) {
        assert(storage == &cache->full_slabs);
        move_slab_node_between_slabs_storages(
            slb_node, storage,
            get_slabs_storage_begin(&cache->fill_slabs), &cache->fill_slabs);
    } else if (storage->type == FILL_SLABS) {
        assert(storage == &cache->fill_slabs);
        if (is_empty_slab(slb_node->slab)) {
            move_slab_node_between_slabs_storages(
                slb_node, storage,
                get_slabs_storage_begin(&cache->free_slabs), &cache->free_slabs);
        }
    } else if (storage == &cache->free_slabs) {
        assert(false);
    } else {
        assert(false);
    }
}

void cache_shrink(struct cache* cache) {
    assert(cache != NULL);
    clear_slabs_storage(&cache->free_slabs);
}


int main() {
    srand(4);

    struct cache csh;
    size_t object_size = 10;
    cache_setup(&csh, object_size);

    const size_t ALLOCATION_COUNT = 1000;
    void* allocated_addresses[ALLOCATION_COUNT];
    size_t allocations = 0;
    for (int attempt = 0; attempt < ALLOCATION_COUNT; ++attempt) {
        printf("attempt = %d\n", attempt);
        int try_allocate = rand() % 10;
        if (try_allocate > 6) {
            void* ptr = cache_alloc(&csh);
            printf("%p = cache_alloc()\n", ptr);
            allocated_addresses[allocations] = ptr;
            ++allocations;
        } else {
            if (allocations > 0) {
                void* ptr = allocated_addresses[allocations - 1];
                printf("cache_free(%p)\n", ptr);
                cache_free(&csh, ptr);
                --allocations;
            }
        }

        int try_shrink = rand() % 10;
        if (try_shrink < 1) {
            printf("cache_shrink()\n");
            cache_shrink(&csh);
        }
    }
    cache_release(&csh);
    return 0;
}
