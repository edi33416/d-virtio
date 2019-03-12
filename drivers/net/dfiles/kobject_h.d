import std.bitmanip : bitfields;
import list_head_h;
import spinlock_types_h : atomic_t;
import device_h : work_struct, timer_list;

struct kset;
struct kobj_type;
struct kernfs_node;
struct workqueue_struct;

struct refcount_struct {
    atomic_t refs;
}

alias refcount_t = refcount_struct;

struct kref {
    refcount_t refcount;
}

alias dstruct_kref = kref;
alias dstruct_kset = kset;

struct delayed_work {
    work_struct work;
    timer_list timer;

    workqueue_struct *wq;
    int cpu;
};


struct kobject {
    const char		*name;
    list_head	entry;
    kobject		*parent;
    dstruct_kset		*kset;
    kobj_type	*ktype;
    kernfs_node	*sd; /* sysfs directory entry */
    dstruct_kref		kref;

    version(CONFIG_DEBUG_KOBJECT_RELEASE) {
        delayed_work	release;
    }


    mixin(bitfields!(
                uint, "state_initialized", 1,
                uint, "state_in_sysfs", 1,
                uint, "state_add_uevent_sent", 1,
                uint, "state_remove_uevent_sent", 1,
                uint, "uevent_suppress", 1,
                uint, "", 3));
}
