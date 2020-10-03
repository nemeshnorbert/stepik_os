#include <cassert>
#include <unordered_set>
#include <unordered_map>


size_t get_slab_size(size_t order) {
    constexpr size_t MIN_SLAB_ORDER = 12;
    return (1 << (order + MIN_SLAB_ORDER));
}

void* alloc_slab(int order) {
    size_t size = get_slab_size(order);
    return aligned_alloc(size, size);
}

void free_slab(void* ptr) {
    free(ptr);
}

namespace {

class slab {
private:
    using entry_ptr = uint8_t*;

public:
    slab()
        : object_size_(0)
        , slab_order_(0)
        , objects_count_(0)
        , head_(nullptr)
        , arena_(nullptr) {
    }

    slab(size_t object_size, size_t slab_order)
        : object_size_(object_size)
        , slab_order_(slab_order)
        , objects_count_(0)
        , head_(nullptr)
        , arena_(alloc_slab(slab_order))
    {
        this->head_ = reinterpret_cast<entry_ptr>(this->arena_);
        size_t entry_size = slab::get_entry_size(this->object_size_);
        size_t slab_size = get_slab_size(this->slab_order_);
        size_t shift = 0;
        entry_ptr start = reinterpret_cast<entry_ptr>(this->arena_);
        while (shift + entry_size < slab_size) {
            set_entry_next(start + shift, start + shift + entry_size);
            shift += entry_size;
        }
        set_entry_next(start + shift, nullptr);
    }

    slab(const slab& other) = delete;

    slab& operator = (const slab& other) = delete;

    slab& operator = (slab&& other) noexcept {
        this->swap(other);
        return *this;
    }

    slab(slab&& other) noexcept
        : object_size_(0)
        , slab_order_(0)
        , objects_count_(0)
        , head_(nullptr)
        , arena_(nullptr) {
        this->swap(other);
    }

    bool empty() const {
        return this->objects_count_ == 0;
    }

    bool full() const {
        return this->objects_count_ >= slab::get_capacity(this->object_size_, this->slab_order_);
    }

    void* allocate() {
        if (this->head_ == nullptr) {
            return nullptr;
        }
        entry_ptr next = get_entry_next(this->head_);
        this->head_ = next;
        ++this->objects_count_;
        return get_entry_data(next);
    }

    void free(void* ptr) {
        if (ptr == nullptr) {
            return;
        }
        assert(!this->empty());
        entry_ptr entry = get_data_entry(ptr);
        if (this->head_ == nullptr) {
            this->head_ = entry;
        }
        set_entry_next(entry, this->head_);
        this->head_ = entry;
        --this->objects_count_;
    }

    size_t get_descriptor() const {
        return reinterpret_cast<size_t>(this->arena_);
    }

    static size_t get_capacity(size_t object_size, size_t slab_order) {
        return get_slab_size(slab_order) / slab::get_entry_size(object_size);
    }

    static size_t get_entry_size(size_t object_size) {
        return object_size + sizeof(entry_ptr);
    }

    ~slab() {
        free_slab(this->arena_);
    }

private:
    void swap(slab& other) {
        std::swap(this->object_size_, other.object_size_);
        std::swap(this->slab_order_, other.slab_order_);
        std::swap(this->objects_count_, other.objects_count_);
        std::swap(this->arena_, other.arena_);
    }

    entry_ptr get_entry_next(entry_ptr ptr) {
        entry_ptr* pnext = reinterpret_cast<entry_ptr*>(ptr);
        return *pnext;
    }

    void set_entry_next(entry_ptr ptr, entry_ptr next) {
        entry_ptr* pnext = reinterpret_cast<entry_ptr*>(ptr);
        *pnext = next;
    }

    void* get_entry_data(entry_ptr ptr) {
        return reinterpret_cast<void*>(ptr + sizeof(entry_ptr));
    }

    entry_ptr get_data_entry(void* data) {
        return reinterpret_cast<entry_ptr>(reinterpret_cast<uint8_t*>(data) - sizeof(entry_ptr));
    }

private:
    size_t object_size_;
    size_t slab_order_;
    size_t objects_count_;
    entry_ptr head_;
    void* arena_;
};

/* ------------------------------------- Slab cache --------------------------------------------- */

class slabs_cache {
private:
    using slabs_storage = std::unordered_map<size_t, slab>;
    using descriptors_storage = std::unordered_set<size_t>;

public:
    void setup(size_t object_size, size_t min_objects_count_per_slab) {
        assert(min_objects_count_per_slab > 1);
        this->object_size_ = object_size;
        this->min_objects_count_per_slab_ = min_objects_count_per_slab;
        this->slab_order_ = 0;
        while (
            this->min_objects_count_per_slab_
            > slab::get_capacity(this->object_size_, this->slab_order_)) {
            ++this->slab_order_;
        }
    }

    void release() {
        free_slab_descriptors_.clear();
        fill_slab_descriptors_.clear();
        full_slab_descriptors_.clear();
        slabs_storage_.clear();
        this->object_size_ = 0;
        this->min_objects_count_per_slab_ = 0;
        this->slab_order_ = 0;
    }

    void* allocate() {
        // make sure we have a slab to allocate from
        if (this->fill_slab_descriptors_.empty()) {
            // make sure we have free slabs
            if (this->free_slab_descriptors_.empty()) {
                slab slb = slab(this->object_size_, this->slab_order_);
                size_t descriptor = slb.get_descriptor();
                this->slabs_storage_[descriptor] = std::move(slb);
                this->free_slab_descriptors_.insert(descriptor);
            }
            size_t descriptor = *this->free_slab_descriptors_.begin();
            this->free_slab_descriptors_.erase(descriptor);
            this->fill_slab_descriptors_.insert(descriptor);
        }
        // allocation
        void* ptr = nullptr;
        size_t descriptor = *this->fill_slab_descriptors_.begin();
        slabs_storage::iterator islab = this->slabs_storage_.find(descriptor);
        assert(islab != this->slabs_storage_.end());
        slab& slb = islab->second;
        assert(!slb.full());
        ptr = slb.allocate();
        assert(ptr != nullptr);
        if (slb.full()) {
            this->fill_slab_descriptors_.erase(descriptor);
            this->full_slab_descriptors_.insert(descriptor);
        }
        return ptr;
    }

    void free(void* ptr) {
        if (ptr == nullptr) {
            return;
        }
        size_t descriptor = get_slab_descriptor(ptr);
        slabs_storage::iterator islab = this->slabs_storage_.find(descriptor);
        assert(islab != this->slabs_storage_.end());
        slab& slb = islab->second;
        assert(!slb.empty());
        slb.free(ptr);
        if (this->full_slab_descriptors_.count(descriptor)) {
            this->full_slab_descriptors_.erase(descriptor);
            this->fill_slab_descriptors_.insert(descriptor);
        } else if (this->fill_slab_descriptors_.count(descriptor)) {
            if (islab->second.empty()) {
                this->fill_slab_descriptors_.erase(descriptor);
                this->free_slab_descriptors_.insert(descriptor);
            }
        } else if (this->free_slab_descriptors_.count(descriptor)) {
            assert(false);
        } else {
            assert(false);
        }
    }

    void shrink() {
        for (descriptors_storage::iterator idescriptor = this->free_slab_descriptors_.begin();
            idescriptor != this->free_slab_descriptors_.end();
            ++idescriptor) {
            slabs_storage::iterator islab = this->slabs_storage_.find(*idescriptor);
            assert(islab != this->slabs_storage_.end());
            this->slabs_storage_.erase(islab);
        }
        this->free_slab_descriptors_.clear();
    }

private:
    size_t get_slab_descriptor(void* ptr) {
        size_t addr = reinterpret_cast<size_t>(ptr);
        addr &= ~(get_slab_size(this->slab_order_) - 1);
        return addr;
    }

private:
    slabs_storage slabs_storage_;
    descriptors_storage free_slab_descriptors_;
    descriptors_storage fill_slab_descriptors_;
    descriptors_storage full_slab_descriptors_;
    size_t object_size_;
    size_t min_objects_count_per_slab_;
    size_t slab_order_;
};

};  // namespace

/* ------------------------------------- Cache -------------------------------------------------- */

struct cache {
public:
    void setup(size_t object_size) {
        size_t min_objects_count_per_slab = 64;
        impl.setup(object_size, min_objects_count_per_slab);
    }

    void release() {
        impl.release();
    }

    void* allocate() {
        return impl.allocate();
    }

    void free(void* ptr) {
        impl.free(ptr);
    }

    void shrink() {
        impl.shrink();
    }

private:
    slabs_cache impl;
};

void cache_setup(cache* cache, size_t object_size) {
    assert(cache != nullptr);
    cache->setup(object_size);
}

void cache_release(cache *cache) {
    assert(cache != nullptr);
    cache->release();
}

void* cache_alloc(cache* cache) {
    assert(cache != nullptr);
    return cache->allocate();
}

void cache_free(cache* cache, void* ptr) {
    assert(cache != nullptr);
    cache->free(ptr);
}


void cache_shrink(cache* cache) {
    assert(cache != nullptr);
    cache->shrink();
}

int main() {
    cache csh;
    size_t object_size = 10;
    cache_setup(&csh, object_size);
    void* p = cache_alloc(&csh);
    cache_free(&csh, p);
    cache_shrink(&csh);
    cache_release(&csh);
    return 0;
}
