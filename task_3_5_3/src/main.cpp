#include <deque>
#include <unordered_set>
#include <cassert>


std::deque<int> SCHEDULER_QUEUE;
std::unordered_set<int> BLOCKED_THREADS;
int TIMESLICE = 0;
int CURRENT_THREAD_ELAPSED_TIME = -1;

void scheduler_setup(int timeslice) {
    SCHEDULER_QUEUE.clear();
    BLOCKED_THREADS.clear();
    TIMESLICE = timeslice;
    CURRENT_THREAD_ELAPSED_TIME = -1;
}

void new_thread(int thread_id) {
    SCHEDULER_QUEUE.push_back(thread_id);
    if (SCHEDULER_QUEUE.size() == 1) {
        CURRENT_THREAD_ELAPSED_TIME = TIMESLICE;
    }
}

void exit_thread() {
    assert(!SCHEDULER_QUEUE.empty());
    SCHEDULER_QUEUE.pop_front();
    if (SCHEDULER_QUEUE.empty()) {
        CURRENT_THREAD_ELAPSED_TIME = -1;
    } else {
        CURRENT_THREAD_ELAPSED_TIME = TIMESLICE;
    }
}

void block_thread() {
    assert(!SCHEDULER_QUEUE.empty());
    int thread_id = SCHEDULER_QUEUE.front();
    SCHEDULER_QUEUE.pop_front();
    BLOCKED_THREADS.insert(thread_id);
    if (SCHEDULER_QUEUE.empty()) {
        CURRENT_THREAD_ELAPSED_TIME = -1;
    } else {
        CURRENT_THREAD_ELAPSED_TIME = TIMESLICE;
    }
}

void wake_thread(int thread_id) {
    assert(BLOCKED_THREADS.count(thread_id) > 0);
    BLOCKED_THREADS.erase(thread_id);
    SCHEDULER_QUEUE.push_back(thread_id);
}

void timer_tick() {
    if (SCHEDULER_QUEUE.empty()) {
        return;
    }
    int thread_id = SCHEDULER_QUEUE.front();
    --CURRENT_THREAD_ELAPSED_TIME;
    if (CURRENT_THREAD_ELAPSED_TIME == 0) {
        SCHEDULER_QUEUE.pop_front();
        SCHEDULER_QUEUE.push_back(thread_id);
        CURRENT_THREAD_ELAPSED_TIME = TIMESLICE;
    }
}

int current_thread() {
    int thread_id = SCHEDULER_QUEUE.empty() ? -1 : SCHEDULER_QUEUE.front();
    return thread_id;
}

void test_1() {
    scheduler_setup(2);
    current_thread();
    current_thread();
    current_thread();
    new_thread(0);
    current_thread();
    current_thread();
    block_thread();
    current_thread();
    timer_tick();
    current_thread();
    current_thread();
    new_thread(1);
    current_thread();
    current_thread();
    block_thread();
    current_thread();
    timer_tick();
    current_thread();
    wake_thread(0);
    current_thread();
    new_thread(2);
    current_thread();
    current_thread();
    block_thread();
    current_thread();
    timer_tick();
    current_thread();
    wake_thread(1);
    current_thread();
    new_thread(3);
    current_thread();
    current_thread();
    block_thread();
    current_thread();
    timer_tick();
    current_thread();

}

void test_2() {
    scheduler_setup(2);
    new_thread(0);
    block_thread();
    timer_tick();
    new_thread(1);
    block_thread();
    timer_tick();
    wake_thread(0);
    new_thread(2);
    block_thread();
    timer_tick();
    wake_thread(1);
    new_thread(3);
    block_thread();
    timer_tick();
    current_thread();
}


int main(int argc, char* argv[]) {
    test_2();
    return 0;
}
