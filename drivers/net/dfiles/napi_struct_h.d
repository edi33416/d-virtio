import core.stdc.config : c_ulong, c_long;
import list_head_h;

struct net_device;
struct sk_buff;
struct hrtimer_clock_base;

enum  GRO_HASH_BUCKETS = 8;

alias ktime_t = long;

align(c_long.sizeof) struct rb_node {
    c_ulong  __rb_parent_color;
    rb_node *rb_right;
    rb_node *rb_left;
}

struct timerqueue_node {
    rb_node node;
    ktime_t expires;
}

enum hrtimer_restart {
    HRTIMER_NORESTART,	/* Timer is not restarted */
    HRTIMER_RESTART,	/* Timer must be restarted */
};

struct hrtimer {
    timerqueue_node node;
    ktime_t _softexpires;
    hrtimer_restart function(hrtimer *) dlang_function;
    hrtimer_clock_base *base;
    ubyte state;
    ubyte is_rel;
    ubyte is_soft;
}

struct gro_list {
    list_head list;
    int count;
}

struct napi_struct {

    list_head poll_list;
    c_ulong state;
    int weight;
    c_ulong gro_bitmask;
    int function(napi_struct *, int) poll;

    version(CONFIG_NETPOLL) {
        int poll_owner;
    }

    net_device *dev;
    gro_list[GRO_HASH_BUCKETS] gro_hash;
    sk_buff *skb;
    hrtimer timer;
    list_head dev_list;
    hlist_node napi_hash_node;
    uint napi_id;
}
