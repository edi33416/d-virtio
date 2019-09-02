import core.stdc.config : c_ulong;

struct lock_class_key;
struct lock_class;

enum NR_LOCKDEP_CACHING_CLASSES = 2;

struct lockdep_map {
    lock_class_key *key;
    lock_class*[NR_LOCKDEP_CACHING_CLASSES] class_cache;
    const char *name;

    version(CONFIG_LOCK_STAT) {
        int cpu;
        c_ulong ip;
    }
}
