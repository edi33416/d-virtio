import std.bitmanip : bitfields;
import spinlock_types_h: atomic_t;
import list_head_h : list_head;
import std.bitmanip : bitfields;
import device_h : work_struct;
import napi_struct_h : rb_node;

struct sock_fprog_kern;
struct bpf_prog_ops;
struct bpf_map;
struct user_struct;
struct bpf_prog_offload;

enum BPF_TAG_SIZE = 8;
enum BPF_OBJ_NAME_LEN = 16U;

struct sock_filter {	/* Filter block */
    ushort code;   /* Actual filter code */
    ubyte jt;	/* Jump true */
    ubyte jf;	/* Jump false */
    uint k;      /* Generic multiuse field */
}

struct bpf_insn {
    ubyte code; /* opcode */
    mixin(bitfields!(
        ubyte, "dst_reg", 4, /* dest register */
        ubyte, "src_reg", 4 /* source register */
                ));
    short off; /* signed offset */
    int imm; /* signed immediate constant */
}

enum bpf_prog_type {
    BPF_PROG_TYPE_UNSPEC,
    BPF_PROG_TYPE_SOCKET_FILTER,
    BPF_PROG_TYPE_KPROBE,
    BPF_PROG_TYPE_SCHED_CLS,
    BPF_PROG_TYPE_SCHED_ACT,
    BPF_PROG_TYPE_TRACEPOINT,
    BPF_PROG_TYPE_XDP,
    BPF_PROG_TYPE_PERF_EVENT,
    BPF_PROG_TYPE_CGROUP_SKB,
    BPF_PROG_TYPE_CGROUP_SOCK,
    BPF_PROG_TYPE_LWT_IN,
    BPF_PROG_TYPE_LWT_OUT,
    BPF_PROG_TYPE_LWT_XMIT,
    BPF_PROG_TYPE_SOCK_OPS,
    BPF_PROG_TYPE_SK_SKB,
    BPF_PROG_TYPE_CGROUP_DEVICE,
    BPF_PROG_TYPE_SK_MSG,
    BPF_PROG_TYPE_RAW_TRACEPOINT,
    BPF_PROG_TYPE_CGROUP_SOCK_ADDR,
    BPF_PROG_TYPE_LWT_SEG6LOCAL,
    BPF_PROG_TYPE_LIRC_MODE2,
    BPF_PROG_TYPE_SK_REUSEPORT,
}

enum bpf_attach_type {
    BPF_CGROUP_INET_INGRESS,
    BPF_CGROUP_INET_EGRESS,
    BPF_CGROUP_INET_SOCK_CREATE,
    BPF_CGROUP_SOCK_OPS,
    BPF_SK_SKB_STREAM_PARSER,
    BPF_SK_SKB_STREAM_VERDICT,
    BPF_CGROUP_DEVICE,
    BPF_SK_MSG_VERDICT,
    BPF_CGROUP_INET4_BIND,
    BPF_CGROUP_INET6_BIND,
    BPF_CGROUP_INET4_CONNECT,
    BPF_CGROUP_INET6_CONNECT,
    BPF_CGROUP_INET4_POST_BIND,
    BPF_CGROUP_INET6_POST_BIND,
    BPF_CGROUP_UDP4_SENDMSG,
    BPF_CGROUP_UDP6_SENDMSG,
    BPF_LIRC_MODE2,
    __MAX_BPF_ATTACH_TYPE
}

align((void *).sizeof) struct callback_head {
    callback_head *next;
    void function(callback_head *head) func;
}

alias rcu_head = callback_head;

struct latch_tree_node {
    rb_node[2] node;
}

struct bpf_prog_aux {
    atomic_t refcnt;
    uint used_map_cnt;
    uint max_ctx_offset;
    uint stack_depth;
    uint id;
    uint func_cnt;
    bool offload_requested;
    bpf_prog **func;
    void *jit_data;

    latch_tree_node ksym_tnode;
    list_head ksym_lnode;

    const bpf_prog_ops *ops;
    bpf_map **used_maps;
    bpf_prog *prog;
    user_struct *user;

    ulong load_time; /* ns since boottime */

    bpf_map *cgroup_storage;

    char[BPF_OBJ_NAME_LEN] name;

    version(CONFIG_SECURITY) {
        void *security;
    }

    bpf_prog_offload *offload;

    union {
        work_struct work;
        rcu_head rcu;
    }
}


struct bpf_prog {
    ushort pages;

    mixin(bitfields!(
        ushort, "jited", 1,
        ushort, "jit_requested", 1,
        ushort, "undo_set_mem", 1,
        ushort, "gpl_compatible", 1,
        ushort, "cb_access", 1,
        ushort, "dst_needed", 1,
        ushort, "blinded", 1,
        ushort, "is_func", 1,
        ushort, "kprobe_override", 1,
        ushort, "has_callchain_buf", 1,
        ushort, "", 6
                ));

    bpf_prog_type	type;
    bpf_attach_type	expected_attach_type;
    uint len;
    uint jited_len;

    ubyte[BPF_TAG_SIZE] tag;
    bpf_prog_aux *aux;
    sock_fprog_kern *orig_prog;
    uint function(const void *ctx, const bpf_insn *insn) bpf_func;

    union dummy_anon_union {
        sock_filter[0] insns;
        bpf_insn[0] insnsi;
    }
    dummy_anon_union[0] dummy_anon_union_i;
    pragma(inline, true) sock_filter* insns() { return ((dummy_anon_union_i.ptr).insns).ptr; }
    pragma(inline, true) bpf_insn* insnsi() { return ((dummy_anon_union_i.ptr).insnsi).ptr; }
}
