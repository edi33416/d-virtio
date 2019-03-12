import spinlock_types_h : spinlock_t;
import list_head_h;
import spinlock_types_h : atomic_t;
import lockdep_map_h;


struct atomic64_t {
align(8):
    ulong counter;
}

struct optimistic_spin_queue {
    atomic_t tail;
}

version (CONFIG_64BIT) {
    enum int BITS_PER_LONG = 64;
}
else {
    enum int BITS_PER_LONG = 32;
}

static if (BITS_PER_LONG == 64) {
    alias atomic_long_t = atomic64_t;
}
else {
    alias atomic_long_t = atomic_t;
}

struct mutex {
    atomic_long_t owner;
    spinlock_t wait_lock;

    version(CONFIG_MUTEX_SPIN_ON_OWNER) {
        optimistic_spin_queue osq;
    }

    list_head wait_list;

    version(CONFIG_DEBUG_MUTEXES) {
        void *magic;
    }

    version(CONFIG_DEBUG_LOCK_ALLOC) {
        lockdep_map	dep_map;
    }
}
