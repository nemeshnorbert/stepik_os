#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

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

void* alloc_arena(struct Arena* parena, size_t size) {
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

void free_arena(struct Arena* parena, void* ptr) {
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

struct Arena ARENA;

void mysetup(void* buf, size_t size) {
    ARENA.buffer = buf;
    ARENA.size = size;
    init_arena(&ARENA);
}

void* myalloc(size_t size) {
    return alloc_arena(&ARENA, size);
}

void myfree(void* p) {
    free_arena(&ARENA, p);
}

#include <stdio.h>


int main(int argc, char* argv[]) {
    const size_t BUFFER_SIZE = 10000;
    char buffer[BUFFER_SIZE];
    mysetup((void*)buffer, BUFFER_SIZE);

    const size_t ALLOCATION_COUNT = 1000;
    const size_t MAX_ALLOCATION_SIZE = 1.1 * BUFFER_SIZE;
    void* allocated_addresses[ALLOCATION_COUNT];
    size_t allocations = 0;
    for (int attempt = 0; attempt < ALLOCATION_COUNT; ++attempt) {
        int try_allocate = rand() % 2;
        if (try_allocate) {
            size_t allocation_size = rand() % MAX_ALLOCATION_SIZE;
            allocated_addresses[allocations] = myalloc(allocation_size);
            ++allocations;
        } else {
            if (allocations > 0) {
                myfree(allocated_addresses[allocations - 1]);
                --allocations;
            }
        }
    }
    return 0;
}
