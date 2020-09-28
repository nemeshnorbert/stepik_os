#include <cassert>

namespace {

// ------------------------------------ Chunks ----------------------------------------------------

// chunk layout
// | prev | next | size | is_free | data | start |
// chunk_ptr prev - points to the previous free chunk
// chunk_ptr next - points to the next free chunk
// std::size_r size - size of the whole chunk including fields (prev, next, size, is_free, start)
// bool is_free - flag indicating that chunk is free
// chunk_ptr start - pointer to the begining of the chunk

using chunk_ptr = std::uint8_t*;

constexpr std::size_t PREV_FIELD_SIZE = sizeof(chunk_ptr);
constexpr std::size_t NEXT_FIELD_SIZE = sizeof(chunk_ptr);
constexpr std::size_t SIZE_FIELD_SIZE = sizeof(std::size_t);
constexpr std::size_t IS_FREE_FIELD_SIZE = sizeof(bool);
constexpr std::size_t START_FIELD_SIZE = sizeof(chunk_ptr);
constexpr std::size_t FIELDS_SIZE = PREV_FIELD_SIZE + NEXT_FIELD_SIZE
    + SIZE_FIELD_SIZE + IS_FREE_FIELD_SIZE + START_FIELD_SIZE;

chunk_ptr get_chunk_prev(chunk_ptr pchunk) {
    chunk_ptr* pprev = reinterpret_cast<chunk_ptr*>(reinterpret_cast<std::uint8_t*>(pchunk));
    return *pprev;
}

void set_chunk_prev(chunk_ptr pchunk, chunk_ptr prev) {
    chunk_ptr* pprev = reinterpret_cast<chunk_ptr*>(reinterpret_cast<std::uint8_t*>(pchunk));
    *pprev = prev;
}

chunk_ptr get_chunk_next(chunk_ptr pchunk) {
    chunk_ptr* pnext = reinterpret_cast<chunk_ptr*>(
        reinterpret_cast<std::uint8_t*>(pchunk) + PREV_FIELD_SIZE);
    return *pnext;
}

void set_chunk_next(chunk_ptr pchunk, chunk_ptr next) {
    chunk_ptr* pnext = reinterpret_cast<chunk_ptr*>(
        reinterpret_cast<std::uint8_t*>(pchunk) + PREV_FIELD_SIZE);
    *pnext = next;
}

std::size_t get_chunk_size(chunk_ptr pchunk) {
    std::size_t* psize = reinterpret_cast<std::size_t*>(
        reinterpret_cast<std::uint8_t*>(pchunk) + PREV_FIELD_SIZE + NEXT_FIELD_SIZE);
    return *psize;
}

void set_chunk_size(chunk_ptr pchunk, std::size_t size) {
    std::size_t* psize = reinterpret_cast<std::size_t*>(
        reinterpret_cast<std::uint8_t*>(pchunk) + PREV_FIELD_SIZE + NEXT_FIELD_SIZE);
    *psize = size;
}

bool get_chunk_is_free(chunk_ptr pchunk) {
    bool* pis_free = reinterpret_cast<bool*>(
        reinterpret_cast<std::uint8_t*>(pchunk)
        + PREV_FIELD_SIZE + NEXT_FIELD_SIZE + SIZE_FIELD_SIZE);
    return *pis_free;
}

void set_chunk_is_free(chunk_ptr pchunk, bool is_free) {
    bool* pis_free = reinterpret_cast<bool*>(
        reinterpret_cast<std::uint8_t*>(pchunk)
        + PREV_FIELD_SIZE + NEXT_FIELD_SIZE + SIZE_FIELD_SIZE);
    *pis_free = is_free;
}

chunk_ptr get_chunk_start(chunk_ptr pchunk) {
    chunk_ptr* pstart = reinterpret_cast<chunk_ptr*>(
        reinterpret_cast<std::uint8_t*>(pchunk) + get_chunk_size(pchunk) - START_FIELD_SIZE);
    return *pstart;
}

void set_chunk_start(chunk_ptr pchunk, chunk_ptr start) {
    chunk_ptr* pstart = reinterpret_cast<chunk_ptr*>(
        reinterpret_cast<std::uint8_t*>(pchunk) + get_chunk_size(pchunk) - START_FIELD_SIZE);
    *pstart = start;
}

std::uint8_t* get_chunk_begin(chunk_ptr pchunk) {
    return reinterpret_cast<std::uint8_t*>(pchunk);
}

std::uint8_t* get_chunk_end(chunk_ptr pchunk) {
    return get_chunk_begin(pchunk) + get_chunk_size(pchunk);
}


chunk_ptr get_chunk_ptr_from_data(void* data) {
    return reinterpret_cast<chunk_ptr>(
        reinterpret_cast<std::uint8_t*>(data)
        - PREV_FIELD_SIZE - NEXT_FIELD_SIZE - SIZE_FIELD_SIZE - IS_FREE_FIELD_SIZE);
}

void* get_chunk_data(chunk_ptr pchunk) {
    return reinterpret_cast<void*>(
        reinterpret_cast<std::uint8_t*>(pchunk)
        + PREV_FIELD_SIZE + NEXT_FIELD_SIZE + SIZE_FIELD_SIZE + IS_FREE_FIELD_SIZE);
}

chunk_ptr get_left_chunk(chunk_ptr pchunk) {
    std::uint8_t* begin = reinterpret_cast<std::uint8_t*>(pchunk);
    chunk_ptr* pstart = reinterpret_cast<chunk_ptr*>(begin - START_FIELD_SIZE);
    return *pstart;
}

chunk_ptr get_right_chunk(chunk_ptr pchunk) {
    std::uint8_t* begin = reinterpret_cast<std::uint8_t*>(pchunk);
    return reinterpret_cast<chunk_ptr>(begin + get_chunk_size(pchunk));
}

chunk_ptr init_chunk_at(
        std::uint8_t* ptr, chunk_ptr prev, chunk_ptr next, std::size_t size, bool is_free) {
    assert(size >= FIELDS_SIZE);
    chunk_ptr pchunk = reinterpret_cast<chunk_ptr>(ptr);
    set_chunk_prev(pchunk, prev);
    set_chunk_next(pchunk, next);
    set_chunk_size(pchunk, size);
    set_chunk_is_free(pchunk, is_free);
    set_chunk_start(pchunk, pchunk);
    return pchunk;
}

// ------------------------------------ Chunk List -------------------------------------------------

struct ChunkList {
    chunk_ptr head = nullptr;
    chunk_ptr tail = nullptr;
};

chunk_ptr get_begin(ChunkList& chunks) {
    return chunks.head;
}

chunk_ptr get_end(ChunkList& chunks) {
    return chunks.tail;
}

bool is_empty(const ChunkList& chunks) {
    return chunks.head == chunks.tail;
}

void insert_chunk_in_list_at(ChunkList& chunks, chunk_ptr pwhere, chunk_ptr pchunk) {
    assert(pwhere != nullptr);
    assert(pchunk != nullptr);
    chunk_ptr pprev_chunk = get_chunk_prev(pwhere);
    set_chunk_prev(pchunk, pprev_chunk);
    if (pprev_chunk != nullptr) {
        set_chunk_next(pprev_chunk, pchunk);
    }
    set_chunk_prev(pwhere, pchunk);
    set_chunk_next(pchunk, pwhere);
    if (chunks.head == pwhere) {
        chunks.head = pchunk;
    }
}

chunk_ptr erase_chunk_from_list_at(ChunkList& chunks, chunk_ptr pwhere) {
    assert(!is_empty(chunks));
    assert(pwhere != chunks.tail);
    chunk_ptr pprev_chunk = get_chunk_prev(pwhere);
    chunk_ptr pnext_chunk = get_chunk_next(pwhere);
    if (pprev_chunk != nullptr) {
        set_chunk_next(pprev_chunk, pnext_chunk);
    }
    set_chunk_prev(pnext_chunk, pprev_chunk);
    set_chunk_prev(pwhere, nullptr);
    set_chunk_next(pwhere, nullptr);
    if (chunks.head == pwhere) {
        chunks.head = pnext_chunk;
    }
    return pnext_chunk;
}

// -------------------------------------- Arena ----------------------------------------------------

struct Arena {
    void* buffer = nullptr;
    std::size_t size = 0;
    ChunkList chunks;
};

std::uint8_t* get_arena_begin(Arena& arena) {
    return reinterpret_cast<std::uint8_t*>(arena.buffer);
}

std::uint8_t* get_arena_end(Arena& arena) {
    return reinterpret_cast<std::uint8_t*>(arena.buffer) + arena.size;
}

void init_chunk_list(ChunkList& chunks, chunk_ptr pchunk) {
    chunks.head = pchunk;
    chunks.tail = pchunk;
}

chunk_ptr get_zero_chunk(Arena& arena) {
    assert(arena.size >= FIELDS_SIZE);
    std::uint8_t* begin = reinterpret_cast<std::uint8_t*>(arena.buffer);
    return init_chunk_at(begin + arena.size - FIELDS_SIZE, nullptr, nullptr, FIELDS_SIZE, true);
}

chunk_ptr get_initial_chunk(Arena& arena) {
    assert(arena.size >= FIELDS_SIZE);
    std::uint8_t* begin = reinterpret_cast<std::uint8_t*>(arena.buffer);
    return init_chunk_at(begin, nullptr, nullptr, arena.size - FIELDS_SIZE, true);
}

void init_arena(Arena& arena) {
    arena.chunks = ChunkList{};
    init_chunk_list(arena.chunks, get_zero_chunk(arena));
    insert_chunk_in_list_at(arena.chunks, get_begin(arena.chunks), get_initial_chunk(arena));
}

bool can_allocate(chunk_ptr pchunk, std::size_t size) {
    return get_chunk_size(pchunk) >= size + FIELDS_SIZE && get_chunk_is_free(pchunk);
}

chunk_ptr alloc_from_chunk(chunk_ptr pchunk, std::size_t size, chunk_ptr& presidual) {
    assert(can_allocate(pchunk, size));
    std::size_t pchunk_size = get_chunk_size(pchunk);
    std::size_t presidual_size = pchunk_size - size - FIELDS_SIZE;
    chunk_ptr palloc_chunk = nullptr;
    if (presidual_size > FIELDS_SIZE) {
        std::uint8_t* begin = reinterpret_cast<std::uint8_t*>(pchunk);
        presidual = init_chunk_at(begin, nullptr, nullptr, presidual_size, true);
        palloc_chunk = init_chunk_at(
            begin + presidual_size, nullptr, nullptr, pchunk_size - presidual_size, false);
    } else {
        presidual = nullptr;
        set_chunk_is_free(pchunk, false);
        palloc_chunk = pchunk;
    }
    return palloc_chunk;
}

void* alloc_arena(Arena& arena, std::size_t size) {
    void* ptr = nullptr;
    chunk_ptr pchunk = get_begin(arena.chunks);
    while (pchunk != get_end(arena.chunks)) {
        if (can_allocate(pchunk, size)) {
            chunk_ptr presidual = nullptr;
            chunk_ptr pwhere = erase_chunk_from_list_at(arena.chunks, pchunk);
            chunk_ptr palloc_chunk = alloc_from_chunk(pchunk, size, presidual);
            assert(palloc_chunk != nullptr);
            if (presidual != nullptr) {
                insert_chunk_in_list_at(arena.chunks, pwhere, presidual);
            }
            ptr = get_chunk_data(palloc_chunk);
            break;
        } else {
            pchunk = get_chunk_next(pchunk);
        }
    }
    return ptr;
}

chunk_ptr get_left_chunk_in_arena(Arena& arena, chunk_ptr pchunk) {
    std::uint8_t* arena_left_tip = get_arena_begin(arena);
    if (arena_left_tip == get_chunk_begin(pchunk)) {
        return nullptr;
    }
    return get_left_chunk(pchunk);
}

chunk_ptr get_right_chunk_in_arena(Arena& arena, chunk_ptr pchunk) {
    // arena_right_tip must be adjusted because we use one chunk for chunks.tail
    std::uint8_t* arena_right_tip = get_arena_end(arena) - FIELDS_SIZE;
    if (arena_right_tip == get_chunk_end(pchunk)) {
        return nullptr;
    }
    return get_right_chunk(pchunk);
}

void free_arena(Arena& arena, void* ptr) {
    if (ptr == nullptr) {
        return;
    }
    chunk_ptr pchunk = get_chunk_ptr_from_data(ptr);
    assert(!get_chunk_is_free(pchunk));
    chunk_ptr pleft_chunk = get_left_chunk_in_arena(arena, pchunk);
    chunk_ptr pright_chunk = get_right_chunk_in_arena(arena, pchunk);
    std::uint8_t* left_tip = get_chunk_begin(pchunk);
    std::uint8_t* right_tip = get_chunk_end(pchunk);
    if (pleft_chunk != nullptr && get_chunk_is_free(pleft_chunk)) {
        left_tip = get_chunk_begin(pleft_chunk);
        erase_chunk_from_list_at(arena.chunks, pleft_chunk);
    }
    if (pright_chunk != nullptr && get_chunk_is_free(pright_chunk)) {
        right_tip = get_chunk_end(pright_chunk);
        erase_chunk_from_list_at(arena.chunks, pright_chunk);
    }
    assert(left_tip <= right_tip);
    std::size_t new_chunk_size = right_tip - left_tip;
    chunk_ptr pnew_chunk = init_chunk_at(left_tip, nullptr, nullptr, new_chunk_size, true);
    insert_chunk_in_list_at(arena.chunks, get_begin(arena.chunks), pnew_chunk);
}

}; // namespace

Arena ARENA;

void mysetup(void* buf, std::size_t size) {
    ARENA.buffer = buf;
    ARENA.size = size;
    init_arena(ARENA);
}

void* myalloc(std::size_t size) {
    return alloc_arena(ARENA, size);
}

void myfree(void* p) {
    free_arena(ARENA, p);
}

// XXX
#include <vector>
#include <cstdlib>
// XXX

int main(int argc, char* argv[]) {
    const std::size_t BUFFER_SIZE = 10000;
    char buffer[BUFFER_SIZE];
    mysetup((void*)buffer, BUFFER_SIZE);

    std::vector<void*> allocated_addresses = std::vector<void*>{};
    for (int attempt = 0; attempt < 1000; ++attempt) {
        bool try_allocate = rand() % 2;
        if (try_allocate) {
            std::size_t allocation_size = rand() % std::size_t(1.1 * BUFFER_SIZE);
            allocated_addresses.push_back(myalloc(allocation_size));
        } else {
            if (!allocated_addresses.empty()) {
                myfree(allocated_addresses.back());
                allocated_addresses.pop_back();
            }
        }
    }
    return 0;
}
