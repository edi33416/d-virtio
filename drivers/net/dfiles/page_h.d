import core.stdc.config : c_ulong;
import std.bitmanip : bitfields;
import list_head_h : list_head;
import spinlock_types_h  : spinlock_t, atomic_t;
import bpf_prog_h : rcu_head;
import mutex_h : BITS_PER_LONG;

struct dev_pagemap;
struct address_space;
struct mm_struct;
struct kmem_cache;

alias pgtable_t = page *;

version(CONFIG_NODES_SHIFT) {
    enum NODES_SHIFT = CONFIG_NODES_SHIFT;
}
else {
    enum NODES_SHIFT = 0;
}

enum MAX_NR_ZONES = 4; /* __MAX_NR_ZONES */

static if (MAX_NR_ZONES < 2) {
    enum ZONES_SHIFT = 0;
}
else static if (MAX_NR_ZONES <= 2) {
    enum ZONES_SHIFT = 1;
}
else static if (MAX_NR_ZONES <= 4) {
    enum ZONES_SHIFT = 2;
}
else static if (MAX_NR_ZONES <= 8) {
    enum ZONES_SHIFT = 3;
}
else {
    pragma(msg, "ZONE_SHIFT -- too many zones configured adjust calculation");
}

version(CONFIG_NUMA_BALANCING) {
    enum LAST__PID_SHIFT = 8;
    enum LAST__PID_MASK = ((1 << LAST__PID_SHIFT)-1);
    enum LAST__CPU_SHIFT = NR_CPUS_BITS;
    enum LAST__CPU_MASK = ((1 << LAST__CPU_SHIFT)-1);
    enum LAST_CPUPID_SHIFT = (LAST__PID_SHIFT+LAST__CPU_SHIFT);
}
else {
    enum LAST_CPUPID_SHIFT = 0;
}

enum ZONES_WIDTH = ZONES_SHIFT;

version(CONFIG_SPARSEMEM) {
    version(CONFIG_SPARSEMEM_VMEMMAP) {
        enum SECTIONS_WIDTH = 0;
    }
    else {
        enum SECTIONS_WIDTH = SECTIONS_SHIFT;
    }
}
else {
    enum SECTIONS_WIDTH = 0;
}

enum NR_PAGEFLAGS = 22; /* __NR_PAGEFLAGS */

static if (SECTIONS_WIDTH+ZONES_WIDTH+NODES_SHIFT+LAST_CPUPID_SHIFT <= BITS_PER_LONG - NR_PAGEFLAGS) {
    enum LAST_CPUPID_WIDTH = LAST_CPUPID_SHIFT;
}
else {
    enum LAST_CPUPID_WIDTH = 0;
}

version(CONFIG_NUMA_BALANCING) {
    static if (LAST_CPUPID_WIDTH == 0) {
        enum LAST_CPUPID_NOT_IN_PAGE_FLAGS;
    }
}

enum SPINLOCK_SIZE = 56; /* sizeof(spinlock_t) */
enum ALLOC_SPLIT_PTLOCKS = (SPINLOCK_SIZE > BITS_PER_LONG/8);

version(CONFIG_HAVE_ALIGNED_STRUCT_PAGE) {

    align(2 * c_ulong.sizeof) struct page {
        c_ulong flags; /* Atomic flags, some possibly
                         * updated asynchronously */
        /*
         * Five words (20/40 bytes) are available in this union.
         * WARNING: bit 0 of the first word is used for PageTail(). That
         * means the other users of this union MUST NOT use the bit to
         * avoid collision and false-positive PageTail().
         */
        union {
            struct { /* Page cache and anonymous pages */
                /**
                 * @lru: Pageout list, eg. active_list protected by
                 * zone_lru_lock.  Sometimes used as a generic list
                 * by the page owner.
                 */
                list_head lru;
                /* See page-flags.h for PAGE_MAPPING_FLAGS */
                address_space *mapping;
                c_ulong index; /* Our offset within mapping. */
                /**
                 * @private: Mapping-private opaque data.
                 * Usually used for buffer_heads if PagePrivate.
                 * Used for swp_entry_t if PageSwapCache.
                 * Indicates order in the buddy system if PageBuddy.
                 */
                c_ulong d_alias_private;
            }
            struct {  /* slab, slob and slub */
                union {
                    list_head slab_list;	/* uses lru */
                    struct { /* Partial pages */
                        page *next;
                        version(CONFIG_64BIT) {
                            int pages;  /* Nr of pages left */
                            int pobjects;  /* Approximate count */
                        }
                        else
                        {
                            short pages;
                            short pobjects;
                        }
                    }
                }
                kmem_cache *slab_cache; /* not slob */
                /* Double-word boundary */
                void *freelist; /* first free object */
                union {
                    void *s_mem; /* slab: first object */
                    c_ulong counters; /* SLUB */
                    struct {  /* SLUB */
                        mixin(bitfields!(
                            uint, "inuse", 16
                            ));
                        mixin(bitfields!(
                            uint, "objects", 15,
                            uint, "frozen", 1
                            ));
                    }
                }
            }
            struct {  /* Tail pages of compound page */
                c_ulong compound_head;  /* Bit zero is set */

                /* First tail page only */
                //unsigned char
                ubyte compound_dtor;
                ubyte compound_order;
                atomic_t compound_mapcount;
            }
            struct {  /* Second tail page of compound page */
                c_ulong _compound_pad_1; /* compound_head */
                c_ulong _compound_pad_2;
                list_head deferred_list;
            }
            struct {  /* Page table pages */
                c_ulong _pt_pad_1;	/* compound_head */
                pgtable_t pmd_huge_pte; /* protected by page->ptl */
                c_ulong _pt_pad_2;	/* mapping */

                union {
                    mm_struct *pt_mm; /* x86 pgds only */
                    atomic_t pt_frag_refcount; /* powerpc */
                }

                static if (is(typeof(ALLOC_SPLIT_PTLOCKS)))
                {
                    spinlock_t *ptl;
                }
                else
                {
                    spinlock_t ptl;
                }

            }
            struct {   /* ZONE_DEVICE pages */
                /** @pgmap: Points to the hosting device page map. */
                dev_pagemap *pgmap;
                c_ulong hmm_data;
                c_ulong _zd_pad_1;  /* uses mapping */
            }

            /** @rcu_head: You can use this to free a page by RCU. */
            rcu_head d_alias_rcu_head;
        }

        union {   /* This union is 4 bytes in size. */
            /*
             * If the page can be mapped to userspace, encodes the number
             * of times this page is referenced by a page table.
             */
            atomic_t _mapcount;

            /*
             * If the page is neither PageSlab nor mappable to userspace,
             * the value stored here may help determine what this page
             * is used for.  See page-flags.h for a list of page types
             * which are currently stored here.
             */
            uint page_type;

            uint active;		/* SLAB */
            int units;			/* SLOB */
        }

        /* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
        atomic_t _refcount;

        version(CONFIG_MEMCG) {
            mem_cgroup *mem_cgroup;
        }

        /*
         * On machines where all RAM is mapped into kernel address space,
         * we can simply calculate the virtual address. On machines with
         * highmem some memory is mapped into kernel virtual memory
         * dynamically, so we need a place to store that address.
         * Note that this field could be 16 bits on x86 ... ;)
         *
         * Architectures with slow multiplication can define
         * WANT_PAGE_VIRTUAL in asm/page.h
         */
        static if (is(typeof(WANT_PAGE_VIRTUAL))) {
            void *virtual;     /* Kernel virtual address (NULL if
                               not kmapped, ie. highmem) */
        }

        static if (is(typeof(LAST_CPUPID_NOT_IN_PAGE_FLAGS))) {
            int _last_cpupid;
        }

    }

}
else {
    struct page {
        c_ulong flags; /* Atomic flags, some possibly
                         * updated asynchronously */
        /*
         * Five words (20/40 bytes) are available in this union.
         * WARNING: bit 0 of the first word is used for PageTail(). That
         * means the other users of this union MUST NOT use the bit to
         * avoid collision and false-positive PageTail().
         */
        union {
            struct { /* Page cache and anonymous pages */
                /**
                 * @lru: Pageout list, eg. active_list protected by
                 * zone_lru_lock.  Sometimes used as a generic list
                 * by the page owner.
                 */
                list_head lru;
                /* See page-flags.h for PAGE_MAPPING_FLAGS */
                address_space *mapping;
                c_ulong index; /* Our offset within mapping. */
                /**
                 * @private: Mapping-private opaque data.
                 * Usually used for buffer_heads if PagePrivate.
                 * Used for swp_entry_t if PageSwapCache.
                 * Indicates order in the buddy system if PageBuddy.
                 */
                c_ulong d_alias_private;
            }
            struct {  /* slab, slob and slub */
                union {
                    list_head slab_list;	/* uses lru */
                    struct { /* Partial pages */
                        page *next;
                        version(CONFIG_64BIT) {
                            int pages;  /* Nr of pages left */
                            int pobjects;  /* Approximate count */
                        }
                        else
                        {
                            short pages;
                            short pobjects;
                        }
                    }
                }
                kmem_cache *slab_cache; /* not slob */
                /* Double-word boundary */
                void *freelist; /* first free object */
                union {
                    void *s_mem; /* slab: first object */
                    c_ulong counters; /* SLUB */
                    struct {  /* SLUB */
                        mixin(bitfields!(
                            uint, "inuse", 16
                            ));
                        mixin(bitfields!(
                            uint, "objects", 15,
                            uint, "frozen", 1
                            ));
                    }
                }
            }
            struct {  /* Tail pages of compound page */
                c_ulong compound_head;  /* Bit zero is set */

                /* First tail page only */
                //unsigned char
                ubyte compound_dtor;
                ubyte compound_order;
                atomic_t compound_mapcount;
            }
            struct {  /* Second tail page of compound page */
                c_ulong _compound_pad_1; /* compound_head */
                c_ulong _compound_pad_2;
                list_head deferred_list;
            }
            struct {  /* Page table pages */
                c_ulong _pt_pad_1;	/* compound_head */
                pgtable_t pmd_huge_pte; /* protected by page->ptl */
                c_ulong _pt_pad_2;	/* mapping */

                union {
                    mm_struct *pt_mm; /* x86 pgds only */
                    atomic_t pt_frag_refcount; /* powerpc */
                }

                static if (is(typeof(ALLOC_SPLIT_PTLOCKS)))
                {
                    spinlock_t *ptl;
                }
                else
                {
                    spinlock_t ptl;
                }

            }
            struct {   /* ZONE_DEVICE pages */
                /** @pgmap: Points to the hosting device page map. */
                dev_pagemap *pgmap;
                c_ulong hmm_data;
                c_ulong _zd_pad_1;  /* uses mapping */
            }

            /** @rcu_head: You can use this to free a page by RCU. */
            rcu_head d_alias_rcu_head;
        }

        union {   /* This union is 4 bytes in size. */
            /*
             * If the page can be mapped to userspace, encodes the number
             * of times this page is referenced by a page table.
             */
            atomic_t _mapcount;

            /*
             * If the page is neither PageSlab nor mappable to userspace,
             * the value stored here may help determine what this page
             * is used for.  See page-flags.h for a list of page types
             * which are currently stored here.
             */
            uint page_type;

            uint active;		/* SLAB */
            int units;			/* SLOB */
        }

        /* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
        atomic_t _refcount;

        version(CONFIG_MEMCG) {
            mem_cgroup *mem_cgroup;
        }

        /*
         * On machines where all RAM is mapped into kernel address space,
         * we can simply calculate the virtual address. On machines with
         * highmem some memory is mapped into kernel virtual memory
         * dynamically, so we need a place to store that address.
         * Note that this field could be 16 bits on x86 ... ;)
         *
         * Architectures with slow multiplication can define
         * WANT_PAGE_VIRTUAL in asm/page.h
         */
        static if (is(typeof(WANT_PAGE_VIRTUAL))) {
            void *virtual;     /* Kernel virtual address (NULL if
                               not kmapped, ie. highmem) */
        }

        static if (is(typeof(LAST_CPUPID_NOT_IN_PAGE_FLAGS))) {
            int _last_cpupid;
        }

    }
}

