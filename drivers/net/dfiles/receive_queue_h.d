import napi_struct_h : napi_struct;
import virtio_h : virtqueue;
import bpf_prog_h : bpf_prog;
import page_h : d_alias_page = page;
import send_queue_h : scatterlist, MAX_SKB_FRAGS, u64_stats_sync, PAGE_SIZE;
import net_device_h : net_device;
import cache_h : SMP_CACHE_BYTES, ____cacheline_aligned;
import mutex_h : BITS_PER_LONG;
import core.stdc.config : c_ulong;

struct page_frag {
    d_alias_page *page;
    static if ((BITS_PER_LONG > 32) || (PAGE_SIZE >= 65536)) {
        uint offset;
        uint size;
    }
    else {
        ushort offset;
        ushort size;
    }
}

struct virtnet_rq_stats {
    u64_stats_sync[0] syncp;
    ulong packets;
    ulong bytes;
    ulong drops;
    ulong xdp_packets;
    ulong xdp_tx;
    ulong xdp_redirects;
    ulong xdp_drops;
    ulong kicks;
}

enum xdp_action {
    XDP_ABORTED = 0,
    XDP_DROP,
    XDP_PASS,
    XDP_TX,
    XDP_REDIRECT,
}

struct xdp_buff {
    void *data;
    void *data_end;
    void *data_meta;
    void *data_hard_start;
    c_ulong handle;
    xdp_rxq_info *rxq;
}

struct xdp_frame {
    void *data;
    ushort len;
    ushort headroom;
    ushort metasize;
    /* Lifetime of xdp_rxq_info is limited to NAPI/enqueue time,
     * while mem info is valid on remote CPU.
     */
    xdp_mem_info mem;
    net_device *dev_rx; /* used by cpumap */
}

struct xdp_mem_info {
    uint type; /* enum xdp_mem_type, but known size type */
    uint id;
}

struct xdp_rxq_info {
    net_device *dev;
    uint queue_index;
    uint reg_state;
    xdp_mem_info mem;
} /* perf critical, avoid false-sharing */

struct ewma_pkt_len {
    c_ulong internal;
}

struct receive_queue {
    /* Virtqueue associated with this receive_queue */
    virtqueue *vq;

    napi_struct napi;

    bpf_prog  *xdp_prog;

    virtnet_rq_stats stats;

    /* Chain pages by the private ptr. */
    d_alias_page *pages;

    /* Average packet length for mergeable receive buffers. */
    ewma_pkt_len mrg_avg_pkt_len;

    /* Page frag for packet buffer allocation. */
    page_frag alloc_frag;

    /* RX: fragments + linear part + virtio header */
    scatterlist[MAX_SKB_FRAGS + 2] sg;

    /* Min single buffer size for mergeable buffers case. */
    uint min_buf_len;

    /* Name of this receive queue: input.$index */
    char[40] name;

    //xdp_rxq_info xdp_rxq;
    mixin(____cacheline_aligned ~ "xdp_rxq_info xdp_rxq;");

}
