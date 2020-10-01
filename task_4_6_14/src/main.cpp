#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdlib>
#include <mutex>


/* Wrap C++ synchronization primitives in the interface showed in videos. */
struct condition {
    std::condition_variable cv;
};

void condition_init(struct condition *cv) {
    ;
}

struct lock {
    std::mutex mtx;
};

void lock_init(struct lock *lock) {
    ;
}


void wait(struct condition *cv, struct lock *lock)
{
    std::unique_lock<std::mutex> guard(lock->mtx, std::adopt_lock_t());

    cv->cv.wait(guard);
    guard.release();
}

void notify_one(struct condition *cv)
{
    cv->cv.notify_one();
}

void notify_all(struct condition *cv)
{
    cv->cv.notify_all();
}


void lock(struct lock *lock)
{
    lock->mtx.lock();
}

void unlock(struct lock *lock)
{
    lock->mtx.unlock();
}


struct atomic_ullong {
    std::atomic<unsigned long long> value;
};

int atomic_fetch_add(struct atomic_ullong* atomic, int arg) {
    return atomic->value.fetch_add(arg);
}


struct wdlock_ctx;

struct wdlock {
    struct wdlock *next;
    const struct wdlock_ctx *owner;
    struct lock lock;
    struct condition cv;
};


struct wdlock_ctx {
    unsigned long long timestamp;
    struct wdlock *locks;
};


void wdlock_ctx_init(struct wdlock_ctx *ctx) {
    static atomic_ullong next;

    ctx->timestamp = atomic_fetch_add(&next, 1) + 1;
    ctx->locks = NULL;
}

void wdlock_init(struct wdlock *lock)
{
    lock_init(&lock->lock);
    condition_init(&lock->cv);
    lock->next = NULL;
    lock->owner = NULL;
}

int wdlock_lock(struct wdlock *l, struct wdlock_ctx *ctx)
{
    int success = 0;
    lock(&l->lock);
    // ? Пока мы держим блокировку, но не дёргнули wait не могут измениться поля l
    while (l->owner != NULL && l->owner->timestamp > ctx->timestamp)
        wait(&l->cv, &l->lock);
    if (l->owner == NULL) {
        l->owner = ctx;
        l->next = ctx->locks;
        ctx->locks = l;
        success = 1;
    }
    unlock(&l->lock);
    return success;
}

void wdlock_unlock(struct wdlock_ctx *ctx)
{
   struct wdlock* plock = ctx->locks;
    while (plock != NULL) {
        struct wdlock* next_lock = plock->next;
        plock->next = NULL;
        plock->owner = NULL;
        unlock(&plock->lock);  // Do unlock in the very end to prevent race conditions
        notify_one(&plock->cv);
        plock = next_lock;
    }
    ctx->locks = NULL;
}

int main() {
    return 0;
}
