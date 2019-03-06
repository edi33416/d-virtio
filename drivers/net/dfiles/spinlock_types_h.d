
struct spinlock {
    union {
        raw_spinlock rlock;
        version(CONFIG_DEBUG_LOCK_ALLOC) {
            enum LOCK_PADSIZE = raw_spinlock.dep_map.offsetof;
        }
        version(CONFIG_DEBUG_LOCK_ALLOC) {
            struct {
                ubyte[LOCK_PADSIZE] __padding;
                lockdep_map dep_map;
            };
        }
    }
}

alias spinlock_t = spinlock;

struct raw_spinlock {
    arch_spinlock_t raw_lock;

    version(CONFIG_DEBUG_SPINLOCK) {
        uint magic, owner_cpu;
        void *owner;
    }
    version(CONFIG_DEBUG_LOCK_ALLOC) {
        lockdep_map dep_map;
    }
}

alias raw_spinlock_t = raw_spinlock;

struct qspinlock {
    union {
        atomic_t val;

        version(__LITTLE_ENDIAN)
        {
            struct {
                ubyte locked;
                ubyte pending;
            };
            struct {
                ushort locked_pending;
                ushort tail;
            };
        }
        else {
            struct {
                ushort tail;
                ushort locked_pending;
            };
            struct {
                ubyte[2] reserved;
                ubyte ending;
                ubyte locked;
            };
        }
    };
}

alias arch_spinlock_t = qspinlock;

struct atomic_t {
    int counter;
}

