import core.stdc.config : c_ulong, c_long;
import virtio_h: virtio_net_config, virtio_config_ops,virtio_device,
       virtqueue, virtio_net_ctrl_mac, vq_callback_t;
import mod_devicetable_h;
import napi_struct_h : napi_struct;
import spinlock_types_h : spinlock_t;
import device_h : device, work_struct;
import kobject_h : kobject, delayed_work;
import link_state_h : rtnl_link_stats64;
import net_device_h: net_device, netdev_queue, netdev_bpf, netlink_ext_ack, bpf_netdev_command,
       gogu, netdev_features_t, netdev_priv_flags, ethtool_ops, net_device_ops, attribute_group,
       netdev_hw_addr;
import sk_buff_h : sk_buff, skb_shared_info;
import bpf_prog_h : bpf_prog;
import send_queue_h : send_queue, scatterlist, virtnet_sq_stats, MAX_SKB_FRAGS, PAGE_SIZE,
       u64_stats_sync;
import page_h : dstruct_page = page;
import receive_queue_h : receive_queue, virtnet_rq_stats, xdp_frame, xdp_buff, xdp_action,
       ewma_pkt_len, page_frag, xdp_rxq_info;
import control_buf_h : control_buf;
import virtnet_info_h : virtnet_info, dstruct_failover, dlang_virtnet_info;
import cache_h : L1_CACHE_BYTES, NR_CPUS, SMP_CACHE_BYTES;
import std.algorithm.comparison : max, min;
import core.stdc.string : memcpy, memset;
import gfp_h : GFP_ATOMIC, GFP_KERNEL;
import sock_h : sockaddr;
import list_head_h : hlist_node;
import cpu_state_h : cpuhp_state;
import uapi_h : ethtool_ringparam, ethtool_drvinfo, ethtool_channels, ethtool_stats,
       ethtool_link_ksettings, ethtool_stringset, __ETHTOOL_LINK_MODE_MASK_NBITS;

//pragma(msg, "Sizeof napi_struct: ", napi_struct.sizeof);
//pragma(msg, "Sizeof virtqueue: ", virtqueue.sizeof);
//pragma(msg, "Sizeof virtio_device: ", virtio_device.sizeof);
//pragma(msg, "Sizeof bool: ", bool.sizeof);
//pragma(msg, "Sizeof spinlock_t:", spinlock_t.sizeof);
//pragma(msg, "Sizeof device:", device.sizeof);
//pragma(msg, "Sizeof virtio-device_id:", virtio_device_id.sizeof);
//pragma(msg, "Sizeof mutex:", mutex.sizeof);
//pragma(msg, "Sizeof kobject:", kobject.sizeof);
//pragma(msg, "Sizeof dev_links_info :", dev_links_info.sizeof);
//pragma(msg, "Sizeof dev_pm_info:", dev_pm_info.sizeof);
//pragma(msg, "Sizeof dev_archdata:", dev_archdata.sizeof);
//pragma(msg, "Sizeof klist_node:", klist_node.sizeof);
//pragma(msg, "Sizeof net_device:", net_device.sizeof);
//pragma(msg, "Sizeof netdev_tc_txq:", netdev_tc_txq.sizeof);
//pragma(msg, "Sizeof possible_net_t:", possible_net_t.sizeof);
//pragma(msg, "Sizeof netdev_hw_addr_list:", netdev_hw_addr_list.sizeof);
//pragma(msg, "Sizeof atomic_t:", atomic_t.sizeof);
//pragma(msg, "Sizeof atomic_long_t:", atomic_long_t.sizeof);
//pragma(msg, "Sizeof timer_list:", timer_list.sizeof);
//pragma(msg, "Sizeof net_device_stats:", net_device_stats.sizeof);
//pragma(msg, "Sizeof sk_buff:", sk_buff.sizeof);
//pragma(msg, "Offsetof sk_buff.csum:", sk_buff.csum.offsetof);
//pragma(msg, "Offsetof sk_buff.queue_mapping:", sk_buff.queue_mapping.offsetof);
//pragma(msg, "Offsetof sk_buff.headers_start:", sk_buff.headers_start.offsetof);
//pragma(msg, "Offsetof sk_buff.cb:", sk_buff.cb.offsetof);
//pragma(msg, "Offsetof sk_buff.tcp_tsorted_anchor:", sk_buff.tcp_tsorted_anchor.offsetof);
//pragma(msg, "Offsetof sk_buff.len:", sk_buff.len.offsetof);
//pragma(msg, "Offsetof sk_buff.data_len:", sk_buff.data_len.offsetof);
//pragma(msg, "Offsetof sk_buff.mac_len:", sk_buff.mac_len.offsetof);
//pragma(msg, "Offsetof sk_buff.hdr_len:", sk_buff.hdr_len.offsetof);
//pragma(msg, "Offsetof sk_buff.priority:", sk_buff.priority.offsetof);
//pragma(msg, "Offsetof sk_buff.mac_header:", sk_buff.mac_header.offsetof);
//pragma(msg, "Offsetof sk_buff.headers_end:", sk_buff.headers_end.offsetof);
//pragma(msg, "Sizeof bpf_prog:", bpf_prog.sizeof);
//pragma(msg, "Offsetof bpf_prog.tag:", bpf_prog.tag.offsetof);
//pragma(msg, "Offsetof bpf_prog.bpf_func:", bpf_prog.bpf_func.offsetof);
//pragma(msg, "Offsetof bpf_prog.insns:", bpf_prog.dummy_anon_union_i.offsetof);
//pragma(msg, "Offsetof bpf_prog.insnsi:", bpf_prog.dummy_anon_union_i.offsetof);
//pragma(msg, "Sizeof send_queue:", send_queue.sizeof);
//pragma(msg, "Offsetof send_queue.name:", send_queue.name.offsetof);
//pragma(msg, "Offsetof send_queue.napi:", send_queue.napi.offsetof);
//pragma(msg, "Sizeof page_struct:", dstruct_page.sizeof);
//pragma(msg, "Offsetof page_struct.private:", page.d_alias_private.offsetof);
//pragma(msg, "Offsetof page_struct.pmd_huge_pte:", page.pmd_huge_pte.offsetof);
//pragma(msg, "Sizeof receive_queue:", receive_queue.sizeof);
//pragma(msg, "Offsetof receive_queue.vq:", receive_queue.vq.offsetof);
//pragma(msg, "Offsetof receive_queue.napi:", receive_queue.napi.offsetof);
//pragma(msg, "Offsetof receive_queue.xdp_prog:", receive_queue.xdp_prog.offsetof);
//pragma(msg, "Offsetof receive_queue.stats:", receive_queue.stats.offsetof);
//pragma(msg, "Offsetof receive_queue.pages:", receive_queue.pages.offsetof);
//pragma(msg, "Offsetof receive_queue.mrg_avg_pkt_len:", receive_queue.mrg_avg_pkt_len.offsetof);
//pragma(msg, "Offsetof receive_queue.alloc_frag:", receive_queue.alloc_frag.offsetof);
//pragma(msg, "Offsetof receive_queue.sq:", receive_queue.sg.offsetof);
//pragma(msg, "Offsetof receive_queue.xdp_rxq:", receive_queue.xdp_rxq.offsetof);
//pragma(msg, "Sizeof scatterlist:", scatterlist.sizeof);
//pragma(msg, "Sizeof control_buf:", control_buf.sizeof);
//pragma(msg, "Sizeof virtnet_info:", virtnet_info.sizeof);
//pragma(msg, "Sizeof virtnet_sq_stats:", virtnet_sq_stats.sizeof);
//pragma(msg, "Offsetof virtnet_sq_stats.syncp:", virtnet_sq_stats.syncp.offsetof);
//pragma(msg, "Sizeof virtnet_rq_stats:", virtnet_rq_stats.sizeof);
//pragma(msg, "Offsetof virtnet_rq_stats.syncp:", virtnet_rq_stats.syncp.offsetof);
//pragma(msg, "Offsetof virtnet_info.rq:", virtnet_info.rq.offsetof);
//pragma(msg, "Offsetof virtnet_info.refill:", virtnet_info.refill.offsetof);
//pragma(msg, "Offsetof virtnet_info.failover:", virtnet_info.failover.offsetof);

alias gfp_t = uint;

pragma(inline, true) int bit_macro(int x) {
    return (1 << (x));
}

pragma(inline, true) auto container_of(string type, string member)(void *ptr) {
    void *t = (ptr - mixin(type ~ "." ~ member ~ ".offsetof"));
    return mixin("cast(" ~ type ~ "*) t");
}

auto ARRAY_SIZE(T)(T[] x) {
    return x.length;
}

enum NAPI_POLL_WEIGHT = 64;

enum bool csum = true, gso = true;
immutable enum bool napi_tx = false;
immutable enum napi_weight = NAPI_POLL_WEIGHT;

enum ETH_HLEN = 14;    /* Total octets in header. */
enum VLAN_HLEN = 4; /* The additional bytes required by VLAN */
enum ETH_DATA_LEN = 1500;  /* Max. octets in payload */

enum VIRTIO_NET_HDR_F_DATA_VALID = 2; /* Csum is valid */
enum GOOD_PACKET_LEN = (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN);
enum GOOD_COPY_LEN = 128;
enum NET_IP_ALIGN = 0;
enum NET_SKB_PAD = max(32, L1_CACHE_BYTES);
enum CHECKSUM_UNNECESSARY = 1;
enum VIRTNET_RX_PAD = (NET_IP_ALIGN + NET_SKB_PAD);
enum HZ = 250;

/* Amount of XDP headroom to prepend to packets for use by xdp_adjust_head */
enum VIRTIO_XDP_HEADROOM = 256;

/* Separating two types of XDP xmit */
enum VIRTIO_XDP_TX = bit_macro(0);
enum VIRTIO_XDP_REDIR = bit_macro(1);


enum VIRTNET_DRIVER_VERSION = "1.0.0";
enum ETH_GSTRING_LEN = 32;

enum VIRTIO_NET_F_GUEST_TSO4 = 7;  /* Guest can handle TSOv4 in. */
enum VIRTIO_NET_F_GUEST_TSO6 = 8; /* Guest can handle TSOv6 in. */
enum VIRTIO_NET_F_GUEST_ECN = 9;    /* Guest can handle TSO[6] w/ ECN in. */
enum VIRTIO_NET_F_GUEST_UFO = 10;     /* Guest can handle UFO in. */

enum week { Mon, Tue, Wed }
week d;

__gshared immutable enum c_ulong[] guest_offloads = [
    VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_ECN,
    VIRTIO_NET_F_GUEST_UFO
];

struct virtnet_stat_desc {
    char[ETH_GSTRING_LEN] desc;
    size_t offset;
}


pragma(inline, true) auto __ALIGN_KERNEL_MASK(T, E)(T x, E mask) {
    return ((x) + (mask)) & ~(mask);
}

pragma(inline, true) auto __ALIGN_KERNEL(T, E)(T x, E a) {
    return __ALIGN_KERNEL_MASK(x, cast(T)(a) - 1);
}

pragma(inline, true) auto ALIGN(T, E)(T x, E a) {
    return __ALIGN_KERNEL(x, a);
}

enum NETDEV_ALIGN = 32;

pragma(inline, true) T netdev_priv(T)(const net_device *dev)
{
    return cast(T)(cast(char *)dev + ALIGN(net_device.sizeof, NETDEV_ALIGN));
}

alias netdev_priv_vinfo = netdev_priv!(virtnet_info*);

//pragma(msg, "stat_desc sizeof:", virtnet_stat_desc.sizeof);

__gshared immutable enum virtnet_stat_desc[] virtnet_sq_stats_desc = [
    { "packets", virtnet_sq_stats.packets.offsetof },
    { "bytes", virtnet_sq_stats.bytes.offsetof },
    { "xdp_tx", virtnet_sq_stats.xdp_tx.offsetof },
    { "xdp_tx_drops", virtnet_sq_stats.xdp_tx_drops.offsetof },
    { "kicks",  virtnet_sq_stats.kicks.offsetof},
];

__gshared immutable enum virtnet_stat_desc[] virtnet_rq_stats_desc = [
    { "packets", virtnet_rq_stats.packets.offsetof },
    { "bytes", virtnet_rq_stats.bytes.offsetof },
    { "drops", virtnet_rq_stats.drops.offsetof  },
    { "xdp_packets", virtnet_rq_stats.xdp_packets.offsetof  },
    { "xdp_tx", virtnet_rq_stats.xdp_tx.offsetof },
    { "xdp_redirects", virtnet_rq_stats.xdp_redirects.offsetof },
    { "xdp_drops", virtnet_rq_stats.xdp_drops.offsetof },
    { "kicks",  virtnet_sq_stats.kicks.offsetof}
];


enum VIRTNET_SQ_STATS_LEN = virtnet_sq_stats_desc.length;
enum VIRTNET_RQ_STATS_LEN = virtnet_rq_stats_desc.length;


static if (!is(typeof(VIRTIO_NET_NO_LEGACY))) {

    /* This header comes first in the scatter-gather list.
     * For legacy virtio, if VIRTIO_F_ANY_LAYOUT is not negotiated, it must
     * be the first element of the scatter-gather list.  If you don't
     * specify GSO or CSUM features, you can simply ignore the header. */
    struct virtio_net_hdr {
        /* See VIRTIO_NET_HDR_F_* */
        ubyte flags;
        /* See VIRTIO_NET_HDR_GSO_* */
        ubyte gso_type;
        ushort hdr_len;		/* Ethernet + IP + tcp/udp hdrs */
        ushort gso_size;		/* Bytes to append to hdr_len per frame */
        ushort csum_start;	/* Position to start checksumming from */
        ushort csum_offset;	/* Offset after that to place checksum */
    }

    /* This is the version of the header to use when the MRG_RXBUF
     * feature has been negotiated. */
    struct virtio_net_hdr_mrg_rxbuf {
        virtio_net_hdr hdr;
        ushort num_buffers; /* Number of merged rx buffers */
    }
}

struct padded_vnet_hdr {
    virtio_net_hdr_mrg_rxbuf hdr;
    /*
     * hdr is in a separate sg buffer, and data sg buffer shares same page
     * with this header sg. This padding makes next sg 16 byte aligned
     * after the header.
     */
    char[4] padding;
}

@trusted {
    extern(C) bool napi_schedule_prep(napi_struct *);
    extern(C) void virtqueue_disable_cb(virtqueue *);
    extern(C) void __napi_schedule(napi_struct *);
    extern(C) uint virtqueue_enable_cb_prepare(virtqueue *);
    extern(C) bool napi_complete_done(napi_struct *, int);
    extern(C) bool virtqueue_poll(virtqueue *, uint);
}


@safe
extern(C) int txq2vq(int txq) {
    return txq * 2 + 1;
}

@safe
extern(C) public int rxq2vq(int rxq)
{
    return rxq * 2;
}

enum int MRG_CTX_HEADER_SHIFT = 22;

@trusted
extern(C) void *mergeable_len_to_ctx(uint truesize, uint headroom)
{
    return cast(void *)(cast(c_ulong)((headroom << MRG_CTX_HEADER_SHIFT) | truesize));

}

@safe
extern(C) uint mergeable_ctx_to_headroom(void *mrg_ctx)
{
    return cast(uint)(cast(c_ulong)(mrg_ctx) >> MRG_CTX_HEADER_SHIFT);
}

@safe
extern(C) uint mergeable_ctx_to_truesize(void *mrg_ctx)
{
    return cast(c_ulong)(mrg_ctx) & ((1 << MRG_CTX_HEADER_SHIFT) - 1);
}

@safe
extern(C) int vq2rxq(const virtqueue *vq)
{
    return vq.index / 2;
}

@safe
extern(C) int vq2txq(const virtqueue *vq)
{
    return (vq.index - 1) / 2;
}

@safe
extern(C) void virtqueue_napi_schedule(napi_struct *napi, virtqueue *vq)
{
    if (napi_schedule_prep(napi)) {
        virtqueue_disable_cb(vq);
        __napi_schedule(napi);
    }
}

@safe
extern(C) void virtqueue_napi_complete(napi_struct *napi, virtqueue *vq, int processed)
{
    int opaque;

    opaque = virtqueue_enable_cb_prepare(vq);
    if (napi_complete_done(napi, processed)) {
        //if (unlikely(virtqueue_poll(vq, opaque)))
        // am eliminat unlikely, pierderi de performanta!!
        if (virtqueue_poll(vq, opaque))
            virtqueue_napi_schedule(napi, vq);
    } else {
        virtqueue_disable_cb(vq);
    }
}

@trusted
extern(C) bool __dbind__virtio_has_feature(const virtio_device *vdev, uint fbit);

@safe
extern(C) bool virtnet_fail_on_feature(virtio_device *vdev, uint fbit,
        const char *fname, const char *dname)
{
    if (!__dbind__virtio_has_feature(vdev, fbit))
        return false;

    //dev_err(&vdev->dev, "device advertises feature %s but not %s", fname, dname);

    return true;
}

@safe
extern(C) virtio_net_hdr_mrg_rxbuf *skb_vnet_hdr(sk_buff *skb)
{
    pragma(inline, true) @trusted virtio_net_hdr_mrg_rxbuf* helper() {
        return cast(virtio_net_hdr_mrg_rxbuf*)skb.cb.ptr;
    }
    return helper();
}


@safe
extern(C) void give_pages(receive_queue *rq, dstruct_page *page)
{
    dstruct_page *end;

    /* Find end of list, sew whole thing into vi->rq.pages. */
    pragma(inline, true) @trusted void helper() {
        for (end = page; end.d_alias_private; end = cast(dstruct_page *) end.d_alias_private)
        {

        }
    }
    end.d_alias_private = cast(c_ulong) rq.pages;
    rq.pages = page;
}

@trusted
extern(C) dstruct_page * __dbind__alloc_page(gfp_t);

@safe
extern(C) dstruct_page *get_a_page(receive_queue *rq, gfp_t gfp_mask)
{
    dstruct_page *p = rq.pages;

    if (p !is null) {
        pragma(inline, true) @trusted dstruct_page* helper() {
              return cast(dstruct_page *) p.d_alias_private;
        }
        rq.pages = helper();
        /* clear private here, it is used to chain pages <] */
        p.d_alias_private = 0;
    } else
        p = __dbind__alloc_page(gfp_mask);
    return p;
}

@safe
extern(C) void __dbind__netif_wake_subqueue(net_device *, ushort);

@safe
extern(C) void skb_xmit_done(virtqueue *vq)
{
    virtnet_info *vi;
    napi_struct *napi;

    vi = vq.vdev.priv;

    pragma(inline, true) @trusted napi_struct* helper() {
        dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
        assert(dvi.vi == vi);
        return &dvi.sq[vq2txq(vq)].napi;
    }
    napi = helper();
    /* Suppress further interrupts. */
    virtqueue_disable_cb(vq);

    if (napi.weight)
        virtqueue_napi_schedule(napi, vq);
    else
        /* We were probably waiting for more output buffers. */

        //!!!! ciudat, cast la ushort; nu-l facem mai bine?
        __dbind__netif_wake_subqueue(vi.dev, cast(ushort)vq2txq(vq));
}

extern(C) void * __dbind__page_address(const dstruct_page *);
extern(C) sk_buff* __dbind__napi_alloc_skb(napi_struct *, uint);
extern(C) int __dbind__skb_tailroom(const sk_buff *);
extern(C) void * __dbind__skb_put_data(sk_buff *, const void *, uint);
extern(C) void skb_add_rx_frag(sk_buff *, int, dstruct_page *, int, int, uint);
extern(C) void __dbind__put_page(dstruct_page *);
extern(C) void __dbind__dev_kfree_skb(void*);
extern(C) skb_shared_info *  __dbind__skb_shinfo(const sk_buff *);

extern(C) sk_buff *page_to_skb(virtnet_info *vi, receive_queue *rq,
        dstruct_page *page, uint offset, uint len, uint truesize)
{
    sk_buff *skb;
    virtio_net_hdr_mrg_rxbuf *hdr;
    uint copy, hdr_len, hdr_padded_len;
    char *p;

    //posibile probleme
    p = cast(char *)(__dbind__page_address(page) + offset);

    /* copy small packet so we can reuse these pages for small data */
    skb = __dbind__napi_alloc_skb(&rq.napi, GOOD_COPY_LEN);

    //!!!!!!!!!
    //if (unlikely(!skb))
    if (skb is null)
        return null;

    hdr = skb_vnet_hdr(skb);

    hdr_len = vi.hdr_len;
    if (vi.mergeable_rx_bufs)
        hdr_padded_len = (*hdr).sizeof;
    else
        hdr_padded_len = padded_vnet_hdr.sizeof;

    memcpy(hdr, p, hdr_len);

    len -= hdr_len;
    offset += hdr_padded_len;
    p += hdr_padded_len;

    copy = len;
    if (copy > __dbind__skb_tailroom(skb))
        copy = __dbind__skb_tailroom(skb);
    __dbind__skb_put_data(skb, p, copy);

    len -= copy;
    offset += copy;

    if (vi.mergeable_rx_bufs) {
        if (len)
            skb_add_rx_frag(skb, 0, page, offset, len, truesize);
        else
            __dbind__put_page(page);
        return skb;
    }

    /*
     * Verify that we can indeed put this data into a skb.
     * This is here to handle cases when the device erroneously
     * tries to receive more than is possible. This is usually
     * the case of a broken device.
     */


    //if (unlikely(len > MAX_SKB_FRAGS * PAGE_SIZE)) {
    if (len > MAX_SKB_FRAGS * PAGE_SIZE) {
        //chestie de debug, cel mai probabil se apeleaza ramura cu no_printk
        //net_dbg_ratelimited("%s: too much data\n", skb.dev.name);
        __dbind__dev_kfree_skb(skb);
        return null;
    }


    //BUG_ON(offset >= PAGE_SIZE);


    while (len) {
        uint frag_size = min(cast(uint)PAGE_SIZE - offset, len);
        skb_add_rx_frag(skb, __dbind__skb_shinfo(skb).nr_frags, page, offset, frag_size, truesize);
        len -= frag_size;
        page = cast(dstruct_page *)page.d_alias_private;
        offset = 0;
    }

    if (page)
        give_pages(rq, page);

    return skb;
}



extern(C) int virtqueue_add_outbuf(virtqueue *vq,
             scatterlist *sg, uint num,
             void *data,
             gfp_t gfp);

enum EOPNOTSUPP = 95;  /* Operation not supported on transport endpoint */
enum EOVERFLOW = 75;  /* Value too large for defined data type */
enum ENOSPC = 28;    /* No space left on device */
enum EINVAL = 22;   /* Invalid argument */
enum ENXIO = 6;   /* No such device or address */

extern(C) void sg_init_one(scatterlist *, const void *, uint);

extern(C) int __virtnet_xdp_xmit_one(virtnet_info *vi, send_queue *sq, xdp_frame *xdpf)
{
    virtio_net_hdr_mrg_rxbuf *hdr;
    int err;

    /* virtqueue want to use data area in-front of packet */
    //if (unlikely(xdpf.metasize > 0))
    if (xdpf.metasize > 0)
        return -EOPNOTSUPP;

    //if (unlikely(xdpf.headroom < vi.hdr_len))
    if (xdpf.headroom < vi.hdr_len)
        return -EOVERFLOW;

    /* Make room for virtqueue hdr (also change xdpf->headroom?) */
    xdpf.data -= vi.hdr_len;
    /* Zero header and leave csum up to XDP layers */
    hdr = cast(virtio_net_hdr_mrg_rxbuf *)xdpf.data;
    memset(hdr, 0, vi.hdr_len);
    xdpf.len += vi.hdr_len;

    //sg_init_one(sq.sg, xdpf.data, xdpf.len);
    sg_init_one(sq.sg.ptr, xdpf.data, xdpf.len);

    //err = virtqueue_add_outbuf(sq.vq, sq.sg, 1, xdpf, GFP_ATOMIC);
    err = virtqueue_add_outbuf(sq.vq, sq.sg.ptr, 1, xdpf, GFP_ATOMIC);
    //if (unlikely(err))
    if (err)
        return -ENOSPC; /* Caller handle free/refcnt */

    return 0;
}


@trusted
extern(C) uint __dbind__smp_processor_id();

@safe
extern(C) send_queue * virtnet_xdp_sq(virtnet_info *vi)
{
    uint qp;
    qp = vi.curr_queue_pairs - vi.xdp_queue_pairs + __dbind__smp_processor_id();

    pragma(inline, true) @trusted send_queue* helper() {
        dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
        assert(dvi.vi == vi);
        return &dvi.sq[qp];
    }

    return helper();
}

@trusted {
    extern(C) void xdp_return_frame(xdp_frame *);
    extern(C) void *virtqueue_get_buf(virtqueue *, uint *);
    extern(C) void xdp_return_frame_rx_napi(xdp_frame *);
    extern(C) bool virtqueue_kick_prepare(virtqueue *);
    extern(C) bool virtqueue_notify(virtqueue *_vq);
    extern(C) void __dbind__u64_stats_update_begin(u64_stats_sync *syncp);
    extern(C) void __dbind__u64_stats_update_end(u64_stats_sync *syncp);
}

enum XDP_XMIT_FLUSH = (1U << 0); /* doorbell signal consumer */
enum XDP_XMIT_FLAGS_MASK = XDP_XMIT_FLUSH;


extern(C) int rcu_read_lock_held();
extern(C) void __dbind__read_once_size(const void *, void *, int);
extern(C) uint *kmalloc(size_t size, gfp_t flags);

//@safe
extern(C) int virtnet_xdp_xmit(net_device *dev,
        int n,  xdp_frame **frames, uint flags)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    receive_queue *rq = vi.rq;
    xdp_frame *xdpf_sent;
    bpf_prog *xdp_prog;
    send_queue *sq;
    //uint *len;
    uint len;
    int drops = 0;
    int kicks = 0;
    int ret, err;
    int i;

    sq = virtnet_xdp_sq(vi);

    ////if (unlikely(flags & ~XDP_XMIT_FLAGS_MASK))
    if (flags & ~XDP_XMIT_FLAGS_MASK) {
        ret = -EINVAL;
        drops = n;
        goto out_label;
    }

     //Only allow ndo_xdp_xmit if XDP is loaded on dev, as this
     //indicate XDP resources have been successfully allocated.
    //xdp_prog = rcu_dereference(rq.xdp_prog);
    xdp_prog = rq.xdp_prog;
    if (xdp_prog is null) {
        ret = -ENXIO;
        drops = n;
        goto out_label;
    }

    // Free up any pending old buffers before queueing new ones.
    while ((xdpf_sent = cast(xdp_frame *)virtqueue_get_buf(sq.vq, &len)) !is null)
        xdp_return_frame(xdpf_sent);

    for (i = 0; i < n; i++) {
        xdp_frame *xdpf = frames[i];

        err = __virtnet_xdp_xmit_one(vi, sq, xdpf);
        if (err) {
            xdp_return_frame_rx_napi(xdpf);
            drops++;
        }
    }
    ret = n - drops;

    if (flags & XDP_XMIT_FLUSH) {
        if (virtqueue_kick_prepare(sq.vq) && virtqueue_notify(sq.vq))
            kicks = 1;
    }

out_label:
    __dbind__u64_stats_update_begin(sq.stats.syncp.ptr);
    sq.stats.xdp_tx += n;
    sq.stats.xdp_tx_drops += drops;
    sq.stats.kicks += kicks;
    __dbind__u64_stats_update_end(sq.stats.syncp.ptr);

    return ret;
}


extern(C) uint virtnet_get_headroom(virtnet_info *vi)
{
    return vi.xdp_queue_pairs ? VIRTIO_XDP_HEADROOM : 0;
}

extern(C) dstruct_page * __dbind__virt_to_head_page(const void *);
extern(C) void __free_pages(dstruct_page *, uint order);

extern(C) dstruct_page *xdp_linearize_page(receive_queue *rq,
                       ushort *num_buf,
                       dstruct_page *p,
                       int offset,
                       int page_off,
                       uint *len)
{
    dstruct_page *page = __dbind__alloc_page(GFP_ATOMIC);

    if (page is null)
        return null;

    memcpy(__dbind__page_address(page) + page_off, __dbind__page_address(p) + offset, *len);
    page_off += *len;

    while (--*num_buf) {
        int tailroom = SKB_DATA_ALIGN(skb_shared_info.sizeof);
        uint buflen;
        void *buf;
        int off;

        buf = virtqueue_get_buf(rq.vq, &buflen);
        //if (unlikely(!buf))
        if (buf is null)
            goto err_buf;

        p = __dbind__virt_to_head_page(buf);
        off = cast(int)(buf - __dbind__page_address(p));

        /* guard against a misconfigured or uncooperative backend that
         * is sending packet larger than the MTU.
         */
        if ((page_off + buflen + tailroom) > PAGE_SIZE) {
            __dbind__put_page(p);
            goto err_buf;
        }

        memcpy(__dbind__page_address(page) + page_off,
               __dbind__page_address(p) + off, buflen);
        page_off += buflen;
        __dbind__put_page(p);
    }

    /* Headroom does not contribute to packet length */
    *len = page_off - VIRTIO_XDP_HEADROOM;
    return page;
err_buf:
    __free_pages(page, 0);
    return null;
}

extern(C) void __dbind__rcu_read_lock();
extern(C) void __dbind__rcu_read_unlock();
extern(C) void __dbind__skb_reserve(sk_buff *, int);
extern(C) void *skb_put(sk_buff *skb, uint len);
extern(C) sk_buff *build_skb(void *, uint);
extern(C) void bpf_warn_invalid_xdp_action(uint);
extern(C) void __dbind__xdp_set_data_meta_invalid(xdp_buff *);
extern(C) int xdp_do_redirect(net_device *, xdp_buff *, bpf_prog *);
extern(C) xdp_frame *__dbind__convert_to_xdp_frame(xdp_buff *);
extern(C) uint __dbind__bpf_prog_run_xdp(const bpf_prog *, xdp_buff *xdp);
//extern(C) void trace_xdp_exception(net_device *, bpf_prog *, uint);

extern(C)  sk_buff *receive_small(net_device *dev,
                    virtnet_info *vi,
                    receive_queue *rq,
                    void *buf, void *ctx,
                    uint len,
                    uint *xdp_xmit,
                    virtnet_rq_stats *stats)
{
    sk_buff *skb;
    bpf_prog *xdp_prog;
    uint xdp_headroom = cast(uint)(cast(c_ulong)ctx);
    uint header_offset = VIRTNET_RX_PAD + xdp_headroom;
    uint headroom = vi.hdr_len + header_offset;
    uint buflen = SKB_DATA_ALIGN(GOOD_PACKET_LEN + headroom) +
                  SKB_DATA_ALIGN(skb_shared_info.sizeof);
    dstruct_page *page = __dbind__virt_to_head_page(buf);
    uint delta = 0;
    dstruct_page *xdp_page;
    int err;

    len -= vi.hdr_len;
    stats.bytes += len;

    __dbind__rcu_read_lock();
    //xdp_prog = rcu_dereference(rq.xdp_prog);
    xdp_prog = rq.xdp_prog;
    if (xdp_prog) {
        virtio_net_hdr_mrg_rxbuf *hdr = cast(virtio_net_hdr_mrg_rxbuf *)(buf + header_offset);
        xdp_frame *xdpf;
        xdp_buff xdp;
        void *orig_data;
        uint act;

        //if (unlikely(hdr.hdr.gso_type))
        if (hdr.hdr.gso_type)
            goto err_xdp;

        //if (unlikely(xdp_headroom < virtnet_get_headroom(vi))) {
        if (xdp_headroom < virtnet_get_headroom(vi)) {
            int offset = cast(int)(buf - __dbind__page_address(page) + header_offset);
            uint tlen = len + vi.hdr_len;
            ushort num_buf = 1;

            xdp_headroom = virtnet_get_headroom(vi);
            header_offset = VIRTNET_RX_PAD + xdp_headroom;
            headroom = vi.hdr_len + header_offset;
            buflen = SKB_DATA_ALIGN(GOOD_PACKET_LEN + headroom) +
                 SKB_DATA_ALIGN(skb_shared_info.sizeof);
            xdp_page = xdp_linearize_page(rq, &num_buf, page,
                              offset, header_offset,
                              &tlen);
            if (xdp_page is null)
                goto err_xdp;

            buf = __dbind__page_address(xdp_page);
            __dbind__put_page(page);
            page = xdp_page;
        }

        xdp.data_hard_start = buf + VIRTNET_RX_PAD + vi.hdr_len;
        xdp.data = xdp.data_hard_start + xdp_headroom;
        __dbind__xdp_set_data_meta_invalid(&xdp);
        xdp.data_end = xdp.data + len;
        xdp.rxq = &rq.xdp_rxq;
        orig_data = xdp.data;
        act = __dbind__bpf_prog_run_xdp(xdp_prog, &xdp);
        stats.xdp_packets++;

        switch (act) {
        case xdp_action.XDP_PASS:
            //[> Recalculate length in case bpf program changed it <]
            delta = cast(uint)(orig_data - xdp.data);
            len = cast(uint)(xdp.data_end - xdp.data);
            break;
        case xdp_action.XDP_TX:
            stats.xdp_tx++;
            xdpf = __dbind__convert_to_xdp_frame(&xdp);

            //if (unlikely(!xdpf))
            if (xdpf is null)
                goto err_xdp;
            err = virtnet_xdp_xmit(dev, 1, &xdpf, 0);
            //if (unlikely(err < 0)) {
            if (err < 0) {
                // AM COMENTAT trace_xdp TODO
                //trace_xdp_exception(vi.dev, xdp_prog, act);
                goto err_xdp;
            }
            *xdp_xmit |= VIRTIO_XDP_TX;
            __dbind__rcu_read_unlock();
            goto xdp_xmit;
        case xdp_action.XDP_REDIRECT:
            stats.xdp_redirects++;
            err = xdp_do_redirect(dev, &xdp, xdp_prog);
            if (err)
                goto err_xdp;
            *xdp_xmit |= VIRTIO_XDP_REDIR;
            __dbind__rcu_read_unlock();
            goto xdp_xmit;
        default:
            bpf_warn_invalid_xdp_action(act);
            goto case;
            //[> fall through <]
        case xdp_action.XDP_ABORTED:
            //trace_xdp_exception(vi.dev, xdp_prog, act);
            goto case;
        case xdp_action.XDP_DROP:
            goto err_xdp;
        }
    }
    __dbind__rcu_read_unlock();

    skb = build_skb(buf, buflen);
    if (skb is null) {
        __dbind__put_page(page);
        goto err;
    }
    __dbind__skb_reserve(skb, headroom - delta);
    skb_put(skb, len);
    if (!delta) {
        buf += header_offset;
        memcpy(skb_vnet_hdr(skb), buf, vi.hdr_len);
    // [> keep zeroed vnet hdr since packet was changed by bpf <]
    }

err:
    return skb;

err_xdp:
    __dbind__rcu_read_unlock();
    stats.xdp_drops++;
    stats.drops++;
    __dbind__put_page(page);
xdp_xmit:
    return null;
}


extern(C) sk_buff *receive_big(net_device *dev,
                   virtnet_info *vi,
                   receive_queue *rq,
                   void *buf,
                   uint len,
                   virtnet_rq_stats *stats)
{
    dstruct_page *page = cast(dstruct_page *)buf;
    sk_buff *skb = page_to_skb(vi, rq, page, 0, len, PAGE_SIZE);

    stats.bytes += len - vi.hdr_len;
    //if (unlikely(!skb))
    if (skb is null)
        goto err;

    return skb;

err:
    stats.drops++;
    give_pages(rq, page);
    return null;
}


extern(C) void *virtqueue_get_buf_ctx(virtqueue *, uint *, void **);
extern(C) ushort __dbind__virtio16_to_cpu(virtio_device *, ushort);
extern(C) sk_buff *__dbind__alloc_skb(uint, gfp_t);
extern(C) bool __dbind__skb_can_coalesce(sk_buff *, int,
        const dstruct_page *, int);
extern(C) void skb_coalesce_rx_frag(sk_buff *, int, int, uint);
extern(C) void __dbind__ewma_pkt_len_add(ewma_pkt_len *e, c_ulong val);
extern(C) c_ulong __dbind__ewma_pkt_len_read(ewma_pkt_len *e);

extern(C) sk_buff *receive_mergeable(net_device *dev,
                    virtnet_info *vi,
                    receive_queue *rq,
                    void *buf,
                    void *ctx,
                    uint len,
                    uint *xdp_xmit,
                    virtnet_rq_stats *stats)
{
    virtio_net_hdr_mrg_rxbuf *hdr = cast(virtio_net_hdr_mrg_rxbuf *)buf;
    ushort num_buf = __dbind__virtio16_to_cpu(vi.vdev, hdr.num_buffers);
    dstruct_page *page = __dbind__virt_to_head_page(buf);
    int offset = cast(int)(buf - __dbind__page_address(page));
    sk_buff *head_skb;
    sk_buff *curr_skb;
    bpf_prog *xdp_prog;
    uint truesize;
    uint headroom = mergeable_ctx_to_headroom(ctx);
    int err;

    head_skb = null;
    stats.bytes += len - vi.hdr_len;

    __dbind__rcu_read_lock();
    xdp_prog = rq.xdp_prog;
    if (xdp_prog) {
        xdp_frame *xdpf;
        dstruct_page *xdp_page;
        xdp_buff xdp;
        void *data;
        uint act;

        /* Transient failure which in theory could occur if
         * in-flight packets from before XDP was enabled reach
         * the receive path after XDP is loaded.
         */
        //if (unlikely(hdr.hdr.gso_type))
        if (hdr.hdr.gso_type)
            goto err_xdp;

        /* This happens when rx buffer size is underestimated
         * or headroom is not enough because of the buffer
         * was refilled before XDP is set. This should only
         * happen for the first several packets, so we don't
         * care much about its performance.
         */

        //if (unlikely(num_buf > 1 || headroom < virtnet_get_headroom(vi))) {
        if (num_buf > 1 || headroom < virtnet_get_headroom(vi)) {
            /* linearize data for XDP */
            xdp_page = xdp_linearize_page(rq, &num_buf,
                              page, offset,
                              VIRTIO_XDP_HEADROOM,
                              &len);
            if (xdp_page is null)
                goto err_xdp;
            offset = VIRTIO_XDP_HEADROOM;
        } else {
            xdp_page = page;
        }

        /* Allow consuming headroom but reserve enough space to push
         * the descriptor on if we get an XDP_TX return code.
         */
        data = __dbind__page_address(xdp_page) + offset;
        xdp.data_hard_start = data - VIRTIO_XDP_HEADROOM + vi.hdr_len;
        xdp.data = data + vi.hdr_len;
        __dbind__xdp_set_data_meta_invalid(&xdp);
        xdp.data_end = xdp.data + (len - vi.hdr_len);
        xdp.rxq = &rq.xdp_rxq;

        act = __dbind__bpf_prog_run_xdp(xdp_prog, &xdp);
        stats.xdp_packets++;

        switch (act) {
        case xdp_action.XDP_PASS:
            /* recalculate offset to account for any header
             * adjustments. Note other cases do not build an
             * skb and avoid using offset
             */
            offset = cast(int)(xdp.data -
                    __dbind__page_address(xdp_page) - vi.hdr_len);

            /* recalculate len if xdp.data or xdp.data_end were
             * adjusted
             */
            len = cast(uint)(xdp.data_end - xdp.data + vi.hdr_len);
            /* We can only create skb based on xdp_page. */
            //if (unlikely(xdp_page != page)) {
            if (xdp_page != page) {
                __dbind__rcu_read_unlock();
                __dbind__put_page(page);
                head_skb = page_to_skb(vi, rq, xdp_page,
                               offset, len, PAGE_SIZE);
                return head_skb;
            }
            break;
        case xdp_action.XDP_TX:
            stats.xdp_tx++;
            xdpf = __dbind__convert_to_xdp_frame(&xdp);
            //if (unlikely(!xdpf))
            if (xdpf is null)
                goto err_xdp;
            err = virtnet_xdp_xmit(dev, 1, &xdpf, 0);
            //if (unlikely(err < 0)) {
            if (err < 0) {
                //trace_xdp_exception(vi.dev, xdp_prog, act);
                //if (unlikely(xdp_page != page))
                if (xdp_page != page)
                    __dbind__put_page(xdp_page);
                goto err_xdp;
            }
            *xdp_xmit |= VIRTIO_XDP_TX;
            //if (unlikely(xdp_page != page))
            if (xdp_page != page)
                __dbind__put_page(page);
            __dbind__rcu_read_unlock();
            goto xdp_xmit;
        case xdp_action.XDP_REDIRECT:
            stats.xdp_redirects++;
            err = xdp_do_redirect(dev, &xdp, xdp_prog);
            if (err) {
                //if (unlikely(xdp_page != page))
                if (xdp_page != page)
                    __dbind__put_page(xdp_page);
                goto err_xdp;
            }
            *xdp_xmit |= VIRTIO_XDP_REDIR;
            //if (unlikely(xdp_page != page))
            if (xdp_page != page)
                __dbind__put_page(page);
            __dbind__rcu_read_unlock();
            goto xdp_xmit;
        default:
            bpf_warn_invalid_xdp_action(act);
            goto case;
            /* fall through */
        case xdp_action.XDP_ABORTED:
            //trace_xdp_exception(vi.dev, xdp_prog, act);
            goto case;
            /* fall through */
        case xdp_action.XDP_DROP:
            //if (unlikely(xdp_page != page))
            if (xdp_page != page)
                __free_pages(xdp_page, 0);
            goto err_xdp;
        }
    }
    __dbind__rcu_read_unlock();

    truesize = mergeable_ctx_to_truesize(ctx);
    //if (unlikely(len > truesize)) {
    if (len > truesize) {
        //pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
             //dev.name, len, (unsigned long)ctx);
        dev.stats.rx_length_errors++;
        goto err_skb;
    }

    head_skb = page_to_skb(vi, rq, page, offset, len, truesize);
    curr_skb = head_skb;

    //if (unlikely(!curr_skb))
    if (curr_skb is null)
        goto err_skb;
    while (--num_buf) {
        int num_skb_frags;

        buf = virtqueue_get_buf_ctx(rq.vq, &len, &ctx);
        //if (unlikely(!buf)) {
        if (buf is null) {
            //pr_debug("%s: rx error: %d buffers out of %d missing\n",
                 //dev.name, num_buf,
                 //virtio16_to_cpu(vi.vdev,
                         //hdr.num_buffers));
            dev.stats.rx_length_errors++;
            goto err_buf;
        }

        stats.bytes += len;
        page = __dbind__virt_to_head_page(buf);

        truesize = mergeable_ctx_to_truesize(ctx);
        //if (unlikely(len > truesize)) {
        if (len > truesize) {
            //pr_debug("%s: rx error: len %u exceeds truesize %lu\n",
                 //dev.name, len, (unsigned long)ctx);
            dev.stats.rx_length_errors++;
            goto err_skb;
        }

        num_skb_frags = __dbind__skb_shinfo(curr_skb).nr_frags;
        //if (unlikely(num_skb_frags == MAX_SKB_FRAGS)) {
        if (num_skb_frags == MAX_SKB_FRAGS) {
             sk_buff *nskb = __dbind__alloc_skb(0, GFP_ATOMIC);

            //if (unlikely(!nskb))
            if (nskb is null)
                goto err_skb;
            if (curr_skb == head_skb)
                __dbind__skb_shinfo(curr_skb).frag_list = nskb;
            else
                curr_skb.next = nskb;
            curr_skb = nskb;
            head_skb.truesize += nskb.truesize;
            num_skb_frags = 0;
        }
        if (curr_skb != head_skb) {
            head_skb.data_len += len;
            head_skb.len += len;
            head_skb.truesize += truesize;
        }
        offset = cast(int)(buf - __dbind__page_address(page));
        if (__dbind__skb_can_coalesce(curr_skb, num_skb_frags, page, offset)) {
            __dbind__put_page(page);
            skb_coalesce_rx_frag(curr_skb, num_skb_frags - 1,
                         len, truesize);
        } else {
            skb_add_rx_frag(curr_skb, num_skb_frags, page,
                    offset, len, truesize);
        }
    }

    __dbind__ewma_pkt_len_add(&rq.mrg_avg_pkt_len, head_skb.len);
    return head_skb;

err_xdp:
    __dbind__rcu_read_unlock();
    stats.xdp_drops++;
err_skb:
    __dbind__put_page(page);
    while (num_buf-- > 1) {
        buf = virtqueue_get_buf(rq.vq, &len);
        //if (unlikely(!buf)) {
        if (buf is null) {
            //pr_debug("%s: rx error: %d buffers missing\n",
                 //dev.name, num_buf);
            dev.stats.rx_length_errors++;
            break;
        }
        stats.bytes += len;
        page = __dbind__virt_to_head_page(buf);
        __dbind__put_page(page);
    }
err_buf:
    stats.drops++;
    __dbind__dev_kfree_skb(head_skb);
xdp_xmit:
    return null;
}


enum gro_result {
    GRO_MERGED,
    GRO_MERGED_FREE,
    GRO_HELD,
    GRO_NORMAL,
    GRO_DROP,
    GRO_CONSUMED,
}

alias gro_result_t = gro_result;

extern(C) int __dbind__virtio_net_hdr_to_skb(sk_buff *,
                    const virtio_net_hdr *,
                    bool);
extern(C) bool __dbind__virtio_is_little_endian(virtio_device *);
extern(C) ushort eth_type_trans(sk_buff *, net_device *);
extern(C) gro_result_t napi_gro_receive(napi_struct *,sk_buff *);
extern(C) void __dbind__set_ip_summed(sk_buff *, int);

extern(C) void receive_buf(virtnet_info *vi, receive_queue *rq,
            void *buf, uint len, void **ctx,
            uint *xdp_xmit,
            virtnet_rq_stats *stats)
{
    net_device *dev = vi.dev;
    sk_buff *skb;
    virtio_net_hdr_mrg_rxbuf *hdr;

    //if (unlikely(len < vi.hdr_len + ETH_HLEN))
    if (len < vi.hdr_len + ETH_HLEN) {
        //pr_debug("%s: short packet %i\n", dev.name, len);
        dev.stats.rx_length_errors++;
        if (vi.mergeable_rx_bufs) {
            __dbind__put_page(__dbind__virt_to_head_page(buf));
        } else if (vi.big_packets) {
            give_pages(rq, cast(dstruct_page *)buf);
        } else {
            __dbind__put_page(__dbind__virt_to_head_page(buf));
        }
        return;
    }

    if (vi.mergeable_rx_bufs)
        skb = receive_mergeable(dev, vi, rq, buf, ctx, len, xdp_xmit,
                    stats);
    else if (vi.big_packets)
        skb = receive_big(dev, vi, rq, buf, len, stats);
    else
        skb = receive_small(dev, vi, rq, buf, ctx, len, xdp_xmit, stats);

    //if (unlikely(!skb))
    if (skb is null)
        return;

    hdr = skb_vnet_hdr(skb);

    if (hdr.hdr.flags & VIRTIO_NET_HDR_F_DATA_VALID)
        skb.ip_summed = CHECKSUM_UNNECESSARY;
        //__dbind__set_ip_summed(skb, CHECKSUM_UNNECESSARY);
        //skb.cloned= 0;
        //dev.wol_enabled= 0;

    if (__dbind__virtio_net_hdr_to_skb(skb, &hdr.hdr,
                  __dbind__virtio_is_little_endian(vi.vdev))) {
        //net_warn_ratelimited("%s: bad gso: type: %u, size: %u\n",
                     //dev.name, hdr.hdr.gso_type,
                     //hdr.hdr.gso_size);
        goto frame_err;
    }

    skb.protocol = eth_type_trans(skb, dev);
    //pr_debug("Receiving skb proto 0x%04x len %i type %i\n",
         //ntohs(skb.protocol), skb.len, skb.pkt_type);

    napi_gro_receive(&rq.napi, skb);
    return;

frame_err:
    dev.stats.rx_frame_errors++;
    __dbind__dev_kfree_skb(skb);
}


uint SKB_DATA_ALIGN(T)(T x) {
    return cast(uint)ALIGN(x, SMP_CACHE_BYTES);
}

extern(C) void __dbind__get_page(dstruct_page *);
extern(C) bool skb_page_frag_refill(uint sz, page_frag *, gfp_t);
extern(C) int virtqueue_add_inbuf_ctx(virtqueue *,
            scatterlist *, uint num,
            void *, void *, gfp_t);
enum ENOMEM = 12; /* Out of memory */

extern(C) int add_recvbuf_small(virtnet_info *vi,receive_queue *rq,
             gfp_t gfp)
{
    page_frag *alloc_frag = &rq.alloc_frag;
    char *buf;
    uint xdp_headroom = virtnet_get_headroom(vi);
    void *ctx = cast(void *)(cast(c_ulong)(xdp_headroom));
    int len = vi.hdr_len + VIRTNET_RX_PAD + GOOD_PACKET_LEN + xdp_headroom;
    int err;

    len = SKB_DATA_ALIGN(len) +
          SKB_DATA_ALIGN(skb_shared_info.sizeof);
    //if (unlikely(!skb_page_frag_refill(len, alloc_frag, gfp)))
    if (!skb_page_frag_refill(len, alloc_frag, gfp))
        return -ENOMEM;

    buf = cast(char *)__dbind__page_address(alloc_frag.page) + alloc_frag.offset;
    __dbind__get_page(alloc_frag.page);
    alloc_frag.offset += len;
    sg_init_one(rq.sg.ptr, buf + VIRTNET_RX_PAD + xdp_headroom,
            vi.hdr_len + GOOD_PACKET_LEN);
    err = virtqueue_add_inbuf_ctx(rq.vq, rq.sg.ptr, 1, buf, ctx, gfp);
    if (err < 0)
        __dbind__put_page(__dbind__virt_to_head_page(buf));
    return err;
}

extern(C) void __dbind__sg_set_buf(scatterlist *, const void *, uint buflen);
extern(C) void sg_init_table(scatterlist *, uint);
extern(C) int virtqueue_add_inbuf(virtqueue *,
            scatterlist *, uint,
            void *,
            gfp_t);

extern(C) int add_recvbuf_big(virtnet_info *vi, receive_queue *rq,
               gfp_t gfp)
{
    dstruct_page *first = null;
    dstruct_page *list = null;
    char *p;
    int i, err, offset;

    sg_init_table(rq.sg.ptr, MAX_SKB_FRAGS + 2);

    for (i = MAX_SKB_FRAGS + 1; i > 1; --i) {
        first = get_a_page(rq, gfp);
        if (first is null) {
            if (list !is null)
                give_pages(rq, list);
            return -ENOMEM;
        }
        __dbind__sg_set_buf(&rq.sg[i], __dbind__page_address(first), PAGE_SIZE);

        first.d_alias_private = cast(c_ulong)list;
        list = first;
    }

    first = get_a_page(rq, gfp);
    if (first is null) {
        give_pages(rq, list);
        return -ENOMEM;
    }
    p = cast(char *)__dbind__page_address(first);

    __dbind__sg_set_buf(&rq.sg[0], p, vi.hdr_len);

    offset = padded_vnet_hdr.sizeof;
    __dbind__sg_set_buf(&rq.sg[1], p + offset, PAGE_SIZE - offset);

    first.d_alias_private = cast(c_ulong)list;
    err = virtqueue_add_inbuf(rq.vq, rq.sg.ptr, MAX_SKB_FRAGS + 2,
                  first, gfp);
    if (err < 0)
        give_pages(rq, first);

    return err;
}


extern(C) uint __dbind__clamp_t(c_ulong, uint, size_t);

extern(C) uint get_mergeable_buf_len(receive_queue *rq,
                      ewma_pkt_len *avg_pkt_len,
                      uint room)
{
    const size_t hdr_len = virtio_net_hdr_mrg_rxbuf.sizeof;
    uint len;

    if (room)
        return PAGE_SIZE - room;

    len = cast(uint)(hdr_len + __dbind__clamp_t(__dbind__ewma_pkt_len_read(avg_pkt_len),
                rq.min_buf_len, PAGE_SIZE - hdr_len));

    return cast(uint)ALIGN(len, L1_CACHE_BYTES);
}



extern(C) int add_recvbuf_mergeable(virtnet_info *vi,
                 receive_queue *rq, gfp_t gfp)
{
    page_frag *alloc_frag = &rq.alloc_frag;
    uint headroom = virtnet_get_headroom(vi);
    uint tailroom = headroom ? (skb_shared_info.sizeof) : 0;
    uint room = SKB_DATA_ALIGN(headroom + tailroom);
    char *buf;
    void *ctx;
    int err;
    uint len, hole;

    /* Extra tailroom is needed to satisfy XDP's assumption. This
     * means rx frags coalescing won't work, but consider we've
     * disabled GSO for XDP, it won't be a big issue.
     */
    len = get_mergeable_buf_len(rq, &rq.mrg_avg_pkt_len, room);
    //if (unlikely(!skb_page_frag_refill(len + room, alloc_frag, gfp)))
    if (!skb_page_frag_refill(len + room, alloc_frag, gfp))
        return -ENOMEM;

    buf = cast(char *)__dbind__page_address(alloc_frag.page) + alloc_frag.offset;
    buf += headroom; /* advance address leaving hole at front of pkt */
    __dbind__get_page(alloc_frag.page);
    alloc_frag.offset += len + room;
    hole = alloc_frag.size - alloc_frag.offset;
    if (hole < len + room) {
        /* To avoid internal fragmentation, if there is very likely not
         * enough space for another buffer, add the remaining space to
         * the current buffer.
         */
        len += hole;
        alloc_frag.offset += hole;
    }

    sg_init_one(rq.sg.ptr, buf, len);
    ctx = mergeable_len_to_ctx(len, headroom);
    err = virtqueue_add_inbuf_ctx(rq.vq, rq.sg.ptr, 1, buf, ctx, gfp);
    if (err < 0)
        __dbind__put_page(__dbind__virt_to_head_page(buf));

    return err;
}


extern(C) bool try_fill_recv(virtnet_info *vi, receive_queue *rq, gfp_t gfp)
{
    int err;
    bool oom;

    do {
        if (vi.mergeable_rx_bufs)
            err = add_recvbuf_mergeable(vi, rq, gfp);
        else if (vi.big_packets)
            err = add_recvbuf_big(vi, rq, gfp);
        else
            err = add_recvbuf_small(vi, rq, gfp);

        oom = err == -ENOMEM;
        if (err)
            break;
    } while (rq.vq.num_free);
    if (virtqueue_kick_prepare(rq.vq) && virtqueue_notify(rq.vq)) {
        __dbind__u64_stats_update_begin(rq.stats.syncp.ptr);
        rq.stats.kicks++;
        __dbind__u64_stats_update_end(rq.stats.syncp.ptr);
    }

    return !oom;
}



extern(C) void skb_recv_done(virtqueue *rvq)
{
    virtnet_info *vi = rvq.vdev.priv;
    receive_queue *rq;

    pragma(inline, true) @trusted receive_queue* helper() {
        dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
        assert(dvi.vi == vi);
        return &dvi.rq[vq2rxq(rvq)];
    }
    rq = helper();

    virtqueue_napi_schedule(&rq.napi, rvq);
}

extern(C) void __dbind__napi_enable(napi_struct *);
extern(C) void __dbind__local_bh_disable();
extern(C) void __dbind__local_bh_enable();

extern(C) void virtnet_napi_enable(virtqueue *vq, napi_struct *napi)
{
    __dbind__napi_enable(napi);

    __dbind__local_bh_disable();
    virtqueue_napi_schedule(napi, vq);
    __dbind__local_bh_enable();
}

extern(C) void virtnet_napi_tx_enable(virtnet_info *vi,
        virtqueue *vq, napi_struct *napi)
{
    if (!napi.weight)
        return;

    if (!vi.affinity_hint_set) {
        napi.weight = 0;
        return;
    }

    return virtnet_napi_enable(vq, napi);
}

extern(C) void napi_disable(napi_struct *);

extern(C) void virtnet_napi_tx_disable(napi_struct *napi)
{
    if (napi.weight)
        napi_disable(napi);
}

extern(C) bool __dbind__schedule_delayed_work(delayed_work *, c_ulong delay);

extern(C) void refill_work(work_struct *work)
{
    //era refill.work, dar work are offset 0 in refill
    virtnet_info *vi = container_of!("virtnet_info", "refill")(work);
    bool still_empty;
    int i;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.curr_queue_pairs <= dvi.rq.length);

    for (i = 0; i < vi.curr_queue_pairs; i++) {
        receive_queue *rq = &vi.rq[i];

        napi_disable(&rq.napi);
        still_empty = !try_fill_recv(vi, rq, GFP_KERNEL);
        virtnet_napi_enable(rq.vq, &rq.napi);

        if (still_empty)
            __dbind__schedule_delayed_work(&vi.refill, HZ/2);
    }
}


extern(C) uint virtqueue_get_vring_size(virtqueue *);
extern(C) void __dbind__print(void *p);
extern(C) int printk(scope const char *format, ...);
extern(C) void dump_stack();

extern(C) int virtnet_receive(receive_queue *rq, int budget,
               uint *xdp_xmit)
{
    virtnet_info *vi = rq.vq.vdev.priv;
    virtnet_rq_stats stats;
    uint len;
    void *buf;
    int i;

    if (!vi.big_packets || vi.mergeable_rx_bufs) {
        void *ctx;

        while ((stats.packets < budget) && ((buf = virtqueue_get_buf_ctx(rq.vq, &len, &ctx)) !is null))   {
            receive_buf(vi, rq, buf, len, cast(void**) ctx, xdp_xmit, &stats);
            stats.packets++;
        }
    } else {
        while (stats.packets < budget && ((buf = virtqueue_get_buf(rq.vq, &len)) !is null)) {
            receive_buf(vi, rq, buf, len, null, xdp_xmit, &stats);
            stats.packets++;
        }
    }

    if (rq.vq.num_free > virtqueue_get_vring_size(rq.vq) / 2) {
        if (!try_fill_recv(vi, rq, GFP_ATOMIC))
            __dbind__schedule_delayed_work(&vi.refill, 0);
    }

    __dbind__u64_stats_update_begin(rq.stats.syncp.ptr);
    for (i = 0; i < VIRTNET_RQ_STATS_LEN; i++) {
        size_t offset = virtnet_rq_stats_desc[i].offset;
        ulong *item;

        item = cast(ulong *)(cast(ubyte *)&rq.stats + offset);
        *item += *(cast(ulong *)(cast(ubyte *)&stats + offset));
    }
    __dbind__u64_stats_update_end(rq.stats.syncp.ptr);

    return cast(int) stats.packets;
}


extern(C) void __dbind__dev_consume_skb_any(sk_buff *);

extern(C) void free_old_xmit_skbs( send_queue *sq)
{
    sk_buff *skb;
    uint len;
    uint packets = 0;
    uint bytes = 0;

    while ((skb = cast(sk_buff *)(virtqueue_get_buf(sq.vq, &len))) !is null) {
        //pr_debug("Sent skb %p\n", skb);

        bytes += skb.len;
        packets++;

        __dbind__dev_consume_skb_any(skb);
    }

    /* Avoid overhead when no packets have been processed
     * happens when called speculatively from start_xmit.
     */
    if (!packets)
        return;

    __dbind__u64_stats_update_begin(sq.stats.syncp.ptr);
    sq.stats.bytes += bytes;
    sq.stats.packets += packets;
    __dbind__u64_stats_update_end(sq.stats.syncp.ptr);
}

extern(C) netdev_queue * __dbind__netdev_get_tx_queue(const net_device *, uint);
extern(C) bool __dbind__netif_tx_trylock(netdev_queue *);
extern(C) void __dbind__netif_tx_unlock(netdev_queue *);
extern(C) void netif_tx_wake_queue(netdev_queue *);

extern(C) void virtnet_poll_cleantx( receive_queue *rq)
{
    virtnet_info *vi = rq.vq.vdev.priv;
    uint index = vq2rxq(rq.vq);
    send_queue *sq;

    pragma(inline, true) @trusted send_queue* helper() {
        dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
        assert(dvi.vi == vi);
        return &dvi.sq[index];
    }
    sq = helper();

    netdev_queue *txq = __dbind__netdev_get_tx_queue(vi.dev, index);


    if (!sq.napi.weight)
        return;

    if (__dbind__netif_tx_trylock(txq)) {
        free_old_xmit_skbs(sq);
        __dbind__netif_tx_unlock(txq);
    }

    if (sq.vq.num_free >= 2 + MAX_SKB_FRAGS)
        netif_tx_wake_queue(txq);
}

extern(C) void xdp_do_flush_map();

extern(C) int virtnet_poll(napi_struct *napi, int budget)
{
    receive_queue *rq = container_of!("receive_queue", "napi")(napi);
    virtnet_info *vi = rq.vq.vdev.priv;
    send_queue *sq;
    uint received;
    uint xdp_xmit = 0;

    virtnet_poll_cleantx(rq);

    received = virtnet_receive(rq, budget, &xdp_xmit);

    /* Out of packets? */
    if (received < budget)
        virtqueue_napi_complete(napi, rq.vq, received);

    if (xdp_xmit & VIRTIO_XDP_REDIR)
        xdp_do_flush_map();

    if (xdp_xmit & VIRTIO_XDP_TX) {
        sq = virtnet_xdp_sq(vi);
        if (virtqueue_kick_prepare(sq.vq) && virtqueue_notify(sq.vq)) {
            __dbind__u64_stats_update_begin(sq.stats.syncp.ptr);
            sq.stats.kicks++;
            __dbind__u64_stats_update_end(sq.stats.syncp.ptr);
        }
    }

    return received;
}

extern(C) int xdp_rxq_info_reg(xdp_rxq_info *xdp_rxq,
             net_device *dev, uint queue_index);
extern(C) int xdp_rxq_info_reg_mem_model(xdp_rxq_info *,
                   xdp_mem_type, void *);

extern(C) void xdp_rxq_info_unreg(xdp_rxq_info *xdp_rxq);

enum xdp_mem_type {
    MEM_TYPE_PAGE_SHARED = 0, /* Split-page refcnt based model */
    MEM_TYPE_PAGE_ORDER0,     /* Orig XDP full page model */
    MEM_TYPE_PAGE_POOL,
    MEM_TYPE_ZERO_COPY,
    MEM_TYPE_MAX,
};

extern(C) int virtnet_open(net_device *dev)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    int i, err;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    //printk("\x05 dvi=%p dvi.vi=%p dvi.sq=%p vi=%p\n\n", dvi, dvi.vi, dvi.sq.ptr, vi);

    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);
    assert(vi.max_queue_pairs <= dvi.sq.length);

    for (i = 0; i < vi.max_queue_pairs; i++) {
        if (i < vi.curr_queue_pairs)
            /* Make sure we have some buffers: if oom use wq. */
            if (!try_fill_recv(vi, &vi.rq[i], GFP_KERNEL))
                __dbind__schedule_delayed_work(&vi.refill, 0);

        err = xdp_rxq_info_reg(&vi.rq[i].xdp_rxq, dev, i);
        if (err < 0)
            return err;

        err = xdp_rxq_info_reg_mem_model(&vi.rq[i].xdp_rxq,
                         xdp_mem_type.MEM_TYPE_PAGE_SHARED, null);
        if (err < 0) {
            xdp_rxq_info_unreg(&vi.rq[i].xdp_rxq);
            return err;
        }

        virtnet_napi_enable(vi.rq[i].vq, &vi.rq[i].napi);
        virtnet_napi_tx_enable(vi, vi.sq[i].vq, &vi.sq[i].napi);
    }

    return 0;
}

extern(C) void __dbind__netif_tx_lock(netdev_queue *, int);
extern(C) int __dbind__raw_smp_processor_id();

extern(C) int virtnet_poll_tx(napi_struct *napi, int budget)
{
     send_queue *sq = container_of!("send_queue", "napi")(napi);
     virtnet_info *vi = sq.vq.vdev.priv;
     netdev_queue *txq = __dbind__netdev_get_tx_queue(vi.dev, vq2txq(sq.vq));

    __dbind__netif_tx_lock(txq, __dbind__raw_smp_processor_id());
    free_old_xmit_skbs(sq);
    __dbind__netif_tx_unlock(txq);

    virtqueue_napi_complete(napi, sq.vq, 0);

    if (sq.vq.num_free >= 2 + MAX_SKB_FRAGS)
        netif_tx_wake_queue(txq);

    return 0;
}

enum ETH_ALEN = 6;

align(1) struct ethhdr {
    ubyte[ETH_ALEN] h_dest;	/* destination eth addr	*/
    ubyte[ETH_ALEN] h_source;	/* source ether addr	*/
    ushort h_proto;		/* packet type ID field	*/
};

extern(C) int __dbind__virtio_net_hdr_from_skb(const sk_buff *skb,
					  virtio_net_hdr *hdr,
					  bool little_endian,
					  bool has_data_valid,
					  int vlan_hlen);

extern(C) void __dbind__print_bug();
extern(C) int __dbind__skb_header_cloned(const sk_buff *);
extern(C) uint __dbind__skb_headroom(const sk_buff *);
extern(C) int skb_to_sgvec(sk_buff *, scatterlist *, int, int);
extern(C) void *__dbind__skb_pull(sk_buff *skb, uint len);
extern(C) void *__dbind__skb_push(sk_buff *, uint len);

extern(C) int xmit_skb(send_queue *sq,  sk_buff *skb)
{
    virtio_net_hdr_mrg_rxbuf *hdr;
    const ubyte * dest = cast(ubyte *)((cast (ethhdr *)skb.data).h_dest);
    virtnet_info *vi = sq.vq.vdev.priv;
    int num_sg;
    uint hdr_len = vi.hdr_len;
    bool can_push;

    //pr_debug("%s: xmit %p %pM\n", vi.dev.name, skb, dest);

    can_push = vi.any_header_sg &&
        //grija la nebunia asta !!!!!!__alignof__(*hdr)
        !(cast(c_ulong)skb.data & (virtio_net_hdr_mrg_rxbuf.alignof - 1)) &&
        !__dbind__skb_header_cloned(skb) && __dbind__skb_headroom(skb) >= hdr_len;
    /* Even if we can, don't push here yet as this would skew
     * csum_start offset below. */
    if (can_push)
        hdr = cast(virtio_net_hdr_mrg_rxbuf *)(skb.data - hdr_len);
    else
        hdr = skb_vnet_hdr(skb);

    if (__dbind__virtio_net_hdr_from_skb(skb, &hdr.hdr,
                    __dbind__virtio_is_little_endian(vi.vdev), false,
                    0))
        __dbind__print_bug();

    if (vi.mergeable_rx_bufs)
        hdr.num_buffers = 0;

    sg_init_table(sq.sg.ptr, __dbind__skb_shinfo(skb).nr_frags + (can_push ? 1 : 2));
    if (can_push) {
        __dbind__skb_push(skb, hdr_len);
        num_sg = skb_to_sgvec(skb, sq.sg.ptr, 0, skb.len);
        //if (unlikely(num_sg < 0))
        if (num_sg < 0)
            return num_sg;
        /* Pull header back to avoid skew in tx bytes calculations. */
        __dbind__skb_pull(skb, hdr_len);
    } else {
        __dbind__sg_set_buf(sq.sg.ptr, hdr, hdr_len);
        //grija aici!!!!!!!!
        num_sg = skb_to_sgvec(skb, sq.sg.ptr + 1, 0, skb.len);
        //if (unlikely(num_sg < 0))
        if (num_sg < 0)
            return num_sg;
        num_sg++;
    }
    return virtqueue_add_outbuf(sq.vq, sq.sg.ptr, num_sg, skb, GFP_ATOMIC);
}

enum INT_MAX = (cast(int)(~0U>>1));
enum INT_MIN = (-INT_MAX - 1);
enum netdev_tx {
    __NETDEV_TX_MIN	 = INT_MIN, /* make sure enum is signed */
    NETDEV_TX_OK	 = 0x00,	/* driver took care of packet */
    NETDEV_TX_BUSY	 = 0x10,	/* driver tx path was busy*/
};

alias netdev_tx_t = netdev_tx;

extern(C) ushort __dbind__skb_get_queue_mapping(const sk_buff *);
extern(C) bool virtqueue_enable_cb_delayed(virtqueue *_vq);
extern(C) void __dbind__skb_tx_timestamp(sk_buff *);
extern(C) int net_ratelimit();
extern(C) bool __dbind__netif_xmit_stopped(const netdev_queue *);
extern(C) void __dbind__netif_start_subqueue(net_device *dev, ushort queue_index);
extern(C) void __dbind__dev_kfree_skb_any(sk_buff *skb);
extern(C) void __dbind__netif_stop_subqueue(net_device *, ushort);
extern(C) void __dbind__skb_orphan(sk_buff *);
extern(C) void __dbind__nf_reset(sk_buff *skb);
extern(C) ubyte __dbind__get_xmit_more_bitfield(sk_buff *);

extern(C) netdev_tx_t start_xmit(sk_buff *skb, net_device *dev)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    int qnum = __dbind__skb_get_queue_mapping(skb);
    send_queue *sq;

    pragma(inline, true) @trusted send_queue* helper() {
        dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
        assert(dvi.vi == vi);
        return &dvi.sq[qnum];
    }
    sq = helper();

    int err;
    netdev_queue *txq = __dbind__netdev_get_tx_queue(dev, qnum);
    bool kick = !__dbind__get_xmit_more_bitfield(skb);
    bool use_napi = cast(bool)sq.napi.weight;

    /* Free up any pending old buffers before queueing new ones. */
    free_old_xmit_skbs(sq);

    if (use_napi && kick)
        virtqueue_enable_cb_delayed(sq.vq);

    /* timestamp packet in software */
    __dbind__skb_tx_timestamp(skb);

    /* Try to transmit */
    err = xmit_skb(sq, skb);

    /* This should not happen! */
    //if (unlikely(err)) {
    if (err) {
        dev.stats.tx_fifo_errors++;
        if (net_ratelimit())
            __dbind__print_bug();
            //dev_warn(&dev.dev,
                 //"Unexpected TXQ (%d) queue failure: %d\n", qnum, err);
        dev.stats.tx_dropped++;
        __dbind__dev_kfree_skb_any(skb);
        return netdev_tx.NETDEV_TX_OK;
    }

    /* Don't wait up for transmitted skbs to be freed. */
    if (!use_napi) {
        __dbind__skb_orphan(skb);
        __dbind__nf_reset(skb);
    }

    /* If running out of space, stop queue to avoid getting packets that we
     * are then unable to transmit.
     * An alternative would be to force queuing layer to requeue the skb by
     * returning NETDEV_TX_BUSY. However, NETDEV_TX_BUSY should not be
     * returned in a normal path of operation: it means that driver is not
     * maintaining the TX queue stop/start state properly, and causes
     * the stack to do a non-trivial amount of useless work.
     * Since most packets only take 1 or 2 ring slots, stopping the queue
     * early means 16 slots are typically wasted.
     */
    if (sq.vq.num_free < 2+MAX_SKB_FRAGS) {
        __dbind__netif_stop_subqueue(dev, cast(ushort)qnum);
        if (!use_napi &&
            !virtqueue_enable_cb_delayed(sq.vq)) {
            //unlikely(!virtqueue_enable_cb_delayed(sq.vq))) {
            /* More just got used, free them then recheck. */
            free_old_xmit_skbs(sq);
            if (sq.vq.num_free >= 2+MAX_SKB_FRAGS) {
                __dbind__netif_start_subqueue(dev, cast(ushort)qnum);
                virtqueue_disable_cb(sq.vq);
            }
        }
    }

    if (kick || __dbind__netif_xmit_stopped(txq)) {
        if (virtqueue_kick_prepare(sq.vq) && virtqueue_notify(sq.vq)) {
            __dbind__u64_stats_update_begin(sq.stats.syncp.ptr);
            sq.stats.kicks++;
            __dbind__u64_stats_update_end(sq.stats.syncp.ptr);
        }
    }

    return netdev_tx.NETDEV_TX_OK;
}



enum VIRTIO_NET_F_CTRL_VQ = 17; /* Control channel available */
enum VIRTIO_NET_OK = 0;

extern(C) bool virtqueue_kick(virtqueue *vq);
extern(C) int virtqueue_add_sgs(virtqueue *_vq,
              scatterlist** sgs,
              uint out_sgs,
              uint in_sgs,
              void *data,
              gfp_t gfp);

extern(C) bool virtqueue_is_broken(virtqueue *_vq);
extern(C) void __dbind__cpu_relax();

extern(C) bool virtnet_send_command(virtnet_info *vi, ubyte dlang_class_alias, ubyte cmd,
                  scatterlist *dlang_out_alias)
{
    scatterlist*[4] sgs;
    scatterlist hdr, stat;
    uint out_num = 0;
    uint tmp;

    //BUG_ON(!__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_CTRL_VQ));
    assert(__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_CTRL_VQ) == true);

    vi.ctrl.status = cast(ubyte)(~0);
    vi.ctrl.hdr.d_alias_class = dlang_class_alias;
    vi.ctrl.hdr.cmd = cmd;

    sg_init_one(&hdr, &vi.ctrl.hdr, vi.ctrl.hdr.sizeof);
    sgs[out_num] = &hdr;
    out_num++;
    if (dlang_out_alias !is null) {
        sgs[out_num] = dlang_out_alias;
        out_num++;
    }

    sg_init_one(&stat, &vi.ctrl.status, vi.ctrl.status.sizeof);
    sgs[out_num] = &stat;

    //BUG_ON(out_num + 1 > ARRAY_SIZE(sgs));
    assert(out_num + 1 <= ARRAY_SIZE(sgs));
    virtqueue_add_sgs(vi.cvq, sgs.ptr, out_num, 1, vi, GFP_ATOMIC);

    //if (unlikely(!virtqueue_kick(vi.cvq)))
    if (!virtqueue_kick(vi.cvq))
        return vi.ctrl.status == VIRTIO_NET_OK;

    while ((virtqueue_get_buf(vi.cvq, &tmp) is null) &&
           !virtqueue_is_broken(vi.cvq))
        __dbind__cpu_relax();

    return vi.ctrl.status == VIRTIO_NET_OK;
}

enum VIRTIO_NET_F_STANDBY = 62;
enum VIRTIO_NET_F_CTRL_MAC_ADDR = 23; /* Set MAC address */
enum VIRTIO_NET_CTRL_MAC = 1;
enum VIRTIO_NET_CTRL_MAC_ADDR_SET = 1;
enum VIRTIO_NET_F_MAC = 5; /* Host has given MAC address. */
enum VIRTIO_F_VERSION_1 = 32;

extern(C) void *__dbind__kmemdup(const void *, size_t, gfp_t);
extern(C) int eth_prepare_mac_addr_change(net_device *, void *);
extern(C) void __dbind__virtio_cwrite8(virtio_device *vdev, uint offset, ubyte val);
extern(C) void eth_commit_mac_addr_change(net_device *, void *);
extern(C) void __dbind__kfree(void *p);

extern(C) int virtnet_set_mac_address(net_device *dev, void *p)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    virtio_device *vdev = vi.vdev;
    int ret;
    sockaddr *addr;
    scatterlist sg;

    if (__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_STANDBY))
        return -EOPNOTSUPP;

    addr = cast(sockaddr *)__dbind__kmemdup(p, (*addr).sizeof, GFP_KERNEL);
    if (!addr)
        return -ENOMEM;

    ret = eth_prepare_mac_addr_change(dev, addr);
    if (ret)
        goto out_label;

    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_MAC_ADDR)) {
        sg_init_one(&sg, addr.sa_data.ptr, dev.addr_len);
        if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MAC,
                      VIRTIO_NET_CTRL_MAC_ADDR_SET, &sg)) {
            //dev_warn(&vdev.dev,
                 //"Failed to set mac address by vq command.\n");
            ret = -EINVAL;
            goto out_label;
        }
    } else if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_MAC) &&
           !__dbind__virtio_has_feature(vdev, VIRTIO_F_VERSION_1)) {
        uint i;

        for (i = 0; i < dev.addr_len; i++)
            __dbind__virtio_cwrite8(vdev, virtio_net_config.mac.offsetof + i, addr.sa_data[i]);
    }

    eth_commit_mac_addr_change(dev, p);
    ret = 0;

out_label:
    __dbind__kfree(addr);
    return ret;
}

extern(C) uint __dbind__u64_stats_fetch_begin_irq(const u64_stats_sync *);
extern(C) bool __dbind__u64_stats_fetch_retry_irq(const u64_stats_sync *, uint start);

extern(C) void virtnet_stats(net_device *dev, rtnl_link_stats64 *tot)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    uint start;
    int i;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    //printk("\x05 dvi=%p dvi.vi=%p dvi.sq=%p vi=%p\n\n", dvi, dvi.vi, dvi.sq.ptr, vi);
    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);
    assert(vi.max_queue_pairs <= dvi.sq.length);

    for (i = 0; i < vi.max_queue_pairs; i++) {
         ulong tpackets, tbytes, rpackets, rbytes, rdrops;
         receive_queue *rq = &vi.rq[i];
         send_queue *sq = &vi.sq[i];

        do {
            start = __dbind__u64_stats_fetch_begin_irq(sq.stats.syncp.ptr);
            tpackets = sq.stats.packets;
            tbytes   = sq.stats.bytes;
        } while (__dbind__u64_stats_fetch_retry_irq(sq.stats.syncp.ptr, start));

        do {
            start = __dbind__u64_stats_fetch_begin_irq(rq.stats.syncp.ptr);
            rpackets = rq.stats.packets;
            rbytes   = rq.stats.bytes;
            rdrops   = rq.stats.drops;
        } while (__dbind__u64_stats_fetch_retry_irq(rq.stats.syncp.ptr, start));

        tot.rx_packets += rpackets;
        tot.tx_packets += tpackets;
        tot.rx_bytes   += rbytes;
        tot.tx_bytes   += tbytes;
        tot.rx_dropped += rdrops;
    }

    tot.tx_dropped = dev.stats.tx_dropped;
    tot.tx_fifo_errors = dev.stats.tx_fifo_errors;
    tot.rx_length_errors = dev.stats.rx_length_errors;
    tot.rx_frame_errors = dev.stats.rx_frame_errors;
}

extern(C) void rtnl_lock();
extern(C) void rtnl_unlock();
enum VIRTIO_NET_CTRL_ANNOUNCE_ACK = 0;
enum VIRTIO_NET_CTRL_ANNOUNCE = 3;

extern(C) void virtnet_ack_link_announce( virtnet_info *vi)
{
    rtnl_lock();
    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_ANNOUNCE,
                VIRTIO_NET_CTRL_ANNOUNCE_ACK, null))
        __dbind__print_bug();
        //dev_warn(&vi.dev.dev, "Failed to ack link announce.\n");
    rtnl_unlock();
}

enum VIRTIO_NET_CTRL_MQ = 4;
enum VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET = 0;
enum VIRTIO_NET_F_MQ = 22;

extern(C) ushort  __dbind__cpu_to_virtio16(virtio_device *vdev, ushort val);
extern(C) int __dbind__getIFF_UP();

extern(C) int _virtnet_set_queues(virtnet_info *vi, ushort queue_pairs)
{
     scatterlist sg;
     net_device *dev = vi.dev;

    if (!vi.has_cvq || !__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_MQ))
        return 0;

    vi.ctrl.mq.virtqueue_pairs = __dbind__cpu_to_virtio16(vi.vdev, queue_pairs);
    sg_init_one(&sg, &vi.ctrl.mq, vi.ctrl.mq.sizeof);

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MQ,
                  VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET, &sg)) {
        //dev_warn(&dev.dev, "Fail to set num of queue pairs to %d\n",
             //queue_pairs);
        __dbind__print_bug();
        return -EINVAL;
    } else {
        vi.curr_queue_pairs = queue_pairs;
        if (dev.flags & __dbind__getIFF_UP)
            __dbind__schedule_delayed_work(&vi.refill, 0);
    }

    return 0;
}

extern(C) int virtnet_set_queues(virtnet_info *vi, ushort queue_pairs)
{
    int err;

    rtnl_lock();
    err = _virtnet_set_queues(vi, queue_pairs);
    rtnl_unlock();
    return err;
}

extern(C) bool cancel_delayed_work_sync(delayed_work *dwork);

extern(C) int virtnet_close( net_device *dev)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    int i;

    cancel_delayed_work_sync(&vi.refill);



    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);
    assert(vi.max_queue_pairs <= dvi.sq.length);

    for (i = 0; i < vi.max_queue_pairs; i++) {
        xdp_rxq_info_unreg(&vi.rq[i].xdp_rxq);
        napi_disable(&vi.rq[i].napi);
        virtnet_napi_tx_disable(&vi.sq[i].napi);
    }

    return 0;
}


enum VIRTIO_NET_F_CTRL_RX = 18; /* Control channel RX mode support */
enum VIRTIO_NET_CTRL_RX = 0;
enum VIRTIO_NET_CTRL_RX_PROMISC = 0;
enum VIRTIO_NET_CTRL_RX_ALLMULTI = 1;
enum VIRTIO_NET_CTRL_MAC_TABLE_SET = 0;

extern(C) int __dbind__getIFF_PROMISC();
extern(C) int __dbind__getIFF_ALLMULTI();
extern(C) int __dbind__netdev_uc_count(net_device*);
extern(C) int __dbind__netdev_mc_count(net_device*);
extern(C) uint __dbind__cpu_to_virtio32(virtio_device *, uint);
extern(C) void *__dbind__kzalloc(size_t, gfp_t);


extern(C) void __dbind__netdev_for_each_uc_addr(netdev_hw_addr *ha, net_device *dev, virtio_net_ctrl_mac *mac_data);

extern(C) void __dbind__netdev_for_each_mc_addr(netdev_hw_addr *ha, net_device *dev, virtio_net_ctrl_mac *mac_data);

extern(C) void virtnet_set_rx_mode(net_device *dev)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    scatterlist[2] sg;
    virtio_net_ctrl_mac *mac_data;
    netdev_hw_addr *ha;
    int uc_count;
    int mc_count;
    void *buf;
    int i;

    //[> We can't dynamically set ndo_set_rx_mode, so return gracefully <]
    if (!__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_CTRL_RX))
        return;

    vi.ctrl.promisc = ((dev.flags & __dbind__getIFF_PROMISC) != 0);
    vi.ctrl.allmulti = ((dev.flags & __dbind__getIFF_ALLMULTI) != 0);

    sg_init_one(&sg[0], &vi.ctrl.promisc, vi.ctrl.promisc.sizeof);

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_RX,
                  VIRTIO_NET_CTRL_RX_PROMISC, &sg[0]))
        //__dbind__print_bug();
        printk("\x05 aici1");
        //dev_warn(&dev.dev, "Failed to %sable promisc mode.\n",
             //vi.ctrl.promisc ? "en" : "dis");

    sg_init_one(&sg[0], &vi.ctrl.allmulti, vi.ctrl.allmulti.sizeof);

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_RX,
                  VIRTIO_NET_CTRL_RX_ALLMULTI, &sg[0]))
        //__dbind__print_bug();
        printk("\x05 aici2");
        //dev_warn(&dev.dev, "Failed to %sable allmulti mode.\n",
             //vi.ctrl.allmulti ? "en" : "dis");

    uc_count = __dbind__netdev_uc_count(dev);
    mc_count = __dbind__netdev_mc_count(dev);
    //[> MAC filter - use one buffer for both lists <]
    buf = __dbind__kzalloc(((uc_count + mc_count) * ETH_ALEN) +
              (2 * mac_data.entries.sizeof), GFP_ATOMIC);
    mac_data = cast(virtio_net_ctrl_mac *)buf;

    if (buf is null)
        return;

    sg_init_table(&sg[0], 2);

    //[> Store the unicast list and count in the front of the buffer <]
    mac_data.entries = __dbind__cpu_to_virtio32(vi.vdev, uc_count);
    i = 0;

    //for (ha = cast(netdev_hw_addr*)container_of!(typeof(*ha).stringof, "list")((&((&(dev.uc)).list)).next);
            //&ha.list != (&((&(dev.uc)).list));
    //for (ha = cast(netdev_hw_addr*)container_of!(typeof(*ha).stringof, "list")(dev.uc.list.next);
            //&ha.list != &(dev.uc.list);
        //ha = cast(netdev_hw_addr*)container_of!(typeof(*ha).stringof, "list")(ha.list.next)) {
            //ubyte *m_ptr = mac_data.macs.ptr;
            //memcpy(m_ptr + i * ETH_ALEN, ha.addr.ptr, ETH_ALEN);
            //i++;
    //}
    __dbind__netdev_for_each_uc_addr(ha, dev, mac_data);

    __dbind__sg_set_buf(&sg[0], mac_data,
          cast(uint)(mac_data.entries.sizeof + (uc_count * ETH_ALEN)));

    //[> multicast list and count fill the end <]
    auto m_ptr = mac_data.macs.ptr;
    mac_data = cast(virtio_net_ctrl_mac*)(m_ptr + uc_count * ETH_ALEN);

    mac_data.entries = __dbind__cpu_to_virtio32(vi.vdev, mc_count);

    i = 0;
    __dbind__netdev_for_each_mc_addr(ha, dev, mac_data);
    //for (ha = cast(netdev_hw_addr*)container_of!(typeof(*ha).stringof, "list")((&((&(dev.mc)).list)).next);
            //&ha.list != (&((&(dev.mc)).list));
    //for (ha = cast(netdev_hw_addr*)container_of!(typeof(*ha).stringof, "list")(dev.mc.list.next);
            //&ha.list != &(dev.mc.list);
        //ha = cast(netdev_hw_addr*)container_of!(typeof(*ha).stringof, "list")(ha.list.next))
    //{
            //memcpy(m_ptr + i * ETH_ALEN, ha.addr.ptr, ETH_ALEN);
            //i++;
    //}

    __dbind__sg_set_buf(&sg[1], mac_data,
          cast(uint)(mac_data.entries.sizeof + (mc_count * ETH_ALEN)));

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MAC,
                  VIRTIO_NET_CTRL_MAC_TABLE_SET, &sg[0]))
        printk("\x05 aici3");
        //dev_warn(&dev.dev, "Failed to set MAC filter table.\n");

    __dbind__kfree(buf);
}


enum VIRTIO_NET_CTRL_VLAN = 2;
enum VIRTIO_NET_CTRL_VLAN_ADD = 0;
enum VIRTIO_NET_CTRL_VLAN_DEL = 1;

extern(C) int virtnet_vlan_rx_add_vid(net_device *dev,
                   ushort proto, ushort vid)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    scatterlist sg;

    vi.ctrl.vid = __dbind__cpu_to_virtio16(vi.vdev, vid);
    sg_init_one(&sg, &vi.ctrl.vid, vi.ctrl.vid.sizeof);

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_VLAN,
                  VIRTIO_NET_CTRL_VLAN_ADD, &sg))
        //dev_warn(&dev.dev, "Failed to add VLAN ID %d.\n", vid);
        __dbind__print_bug();
    return 0;
}

extern(C) int virtnet_vlan_rx_kill_vid( net_device *dev,
                    ushort proto, ushort vid)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    scatterlist sg;

    vi.ctrl.vid = __dbind__cpu_to_virtio16(vi.vdev, vid);
    sg_init_one(&sg, &vi.ctrl.vid, vi.ctrl.vid.sizeof);

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_VLAN,
                  VIRTIO_NET_CTRL_VLAN_DEL, &sg))
        //dev_warn(&dev.dev, "Failed to kill VLAN ID %d.\n", vid);
        __dbind__print_bug();
    return 0;
}


struct cpumask {
    c_ulong[((8 + (c_long.sizeof * 8) - 1) / (c_long.sizeof * 8))] bits;
}

alias cpumask_var_t = cpumask[1];

extern(C) int __dbind__virtqueue_set_affinity(virtqueue *vq,
        const cpumask *);

extern(C) void virtnet_clean_affinity(virtnet_info *vi, long hcpu)
{
    int i;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);

    if (vi.affinity_hint_set) {
        assert(vi.max_queue_pairs <= dvi.rq.length);
        assert(vi.max_queue_pairs <= dvi.sq.length);
        for (i = 0; i < vi.max_queue_pairs; i++) {
            __dbind__virtqueue_set_affinity(vi.rq[i].vq, null);
            __dbind__virtqueue_set_affinity(vi.sq[i].vq, null);
        }

        vi.affinity_hint_set = false;
    }
}

extern(C) bool __dbind__zalloc_cpumask_var(cpumask_var_t *, gfp_t);
extern(C) uint __dbind__num_online_cpus();
extern(C) uint __dbind__cpumask_next(int, const cpumask *);
extern(C) cpumask *__dbind__cpu_online_mask();
extern(C) uint __dbind__cpumask_next_wrap(int, const cpumask *, int, bool );
extern(C) void __dbind__cpumask_set_cpu(uint, cpumask *);
extern(C) void __dbind__free_cpumask_var(cpumask_var_t);
extern(C) int __dbind__netif_set_xps_queue(net_device *dev,
                    const c_ulong *mask,
                    ushort index, bool is_rxqs_map);
extern(C) void __dbind__cpumask_clear(cpumask *dstp);
extern(C) c_ulong * __dbind__cpumask_bits(cpumask * mask);

extern(C) void virtnet_set_affinity(virtnet_info *vi)
{
    cpumask_var_t mask;
    int stragglers;
    int group_size;
    int i, j, cpu;
    int num_cpu;
    int stride;

    if (!__dbind__zalloc_cpumask_var(&mask, GFP_KERNEL)) {
        virtnet_clean_affinity(vi, -1);
        return;
    }

    num_cpu = __dbind__num_online_cpus();
    stride = max(num_cpu / vi.curr_queue_pairs, 1);
    //stride = max_t(int, num_cpu / vi.curr_queue_pairs, 1);
    stragglers = num_cpu >= vi.curr_queue_pairs ?
            num_cpu % vi.curr_queue_pairs :
            0;
    cpu = __dbind__cpumask_next(-1, __dbind__cpu_online_mask());

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.curr_queue_pairs <= dvi.rq.length);
    assert(vi.curr_queue_pairs <= dvi.sq.length);

    for (i = 0; i < vi.curr_queue_pairs; i++) {
        group_size = stride + (i < stragglers ? 1 : 0);

        for (j = 0; j < group_size; j++) {
            __dbind__cpumask_set_cpu(cpu, mask.ptr);
            cpu = __dbind__cpumask_next_wrap(cpu, __dbind__cpu_online_mask,
                        8, false);
        }
        __dbind__virtqueue_set_affinity(vi.rq[i].vq, mask.ptr);
        __dbind__virtqueue_set_affinity(vi.sq[i].vq, mask.ptr);
        __dbind__netif_set_xps_queue(vi.dev, __dbind__cpumask_bits(mask.ptr), cast(ushort)i, false);
        __dbind__cpumask_clear(mask.ptr);
    }

    vi.affinity_hint_set = true;
    __dbind__free_cpumask_var(mask);
}

auto hlist_entry_safe(string type, string member)(hlist_node *node) {
    hlist_node * ____ptr = (node);
    if (____ptr !is null)
        return container_of!(type, member)(____ptr);
    else
        return null;
}

extern(C) int virtnet_cpu_online(uint cpu, hlist_node *node)
{
    virtnet_info *vi = hlist_entry_safe!("virtnet_info", "node")(node);
    virtnet_set_affinity(vi);
    return 0;
}

extern(C) int virtnet_cpu_dead(uint cpu, hlist_node *node)
{
    virtnet_info *vi = hlist_entry_safe!("virtnet_info", "node_dead")(node);
    virtnet_set_affinity(vi);
    return 0;
}

extern(C) int virtnet_cpu_down_prep(uint cpu, hlist_node *node)
{
    virtnet_info *vi = hlist_entry_safe!("virtnet_info", "node")(node);

    virtnet_clean_affinity(vi, cpu);
    return 0;
}

extern(C) cpuhp_state __dbind__get_virtionet_online();
extern(C) int __dbind__cpuhp_state_add_instance_nocalls(cpuhp_state, hlist_node *);
extern(C) int __dbind__cpuhp_state_remove_instance_nocalls(cpuhp_state, hlist_node *);


extern(C) int virtnet_cpu_notif_add( virtnet_info *vi)
{
    int ret;

    ret = __dbind__cpuhp_state_add_instance_nocalls(__dbind__get_virtionet_online, &vi.node);
    if (ret)
        return ret;
    ret = __dbind__cpuhp_state_add_instance_nocalls(cpuhp_state.CPUHP_VIRT_NET_DEAD,
                           &vi.node_dead);
    if (!ret)
        return ret;
    __dbind__cpuhp_state_remove_instance_nocalls(__dbind__get_virtionet_online, &vi.node);
    return ret;
}




extern(C) void virtnet_cpu_notif_remove( virtnet_info *vi)
{
    __dbind__cpuhp_state_remove_instance_nocalls(__dbind__get_virtionet_online, &vi.node);
    __dbind__cpuhp_state_remove_instance_nocalls(cpuhp_state.CPUHP_VIRT_NET_DEAD,
                        &vi.node_dead);
}

extern(C) void virtnet_get_ringparam(net_device *dev,
                 ethtool_ringparam *ring)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);

    ring.rx_max_pending = virtqueue_get_vring_size(dvi.rq[0].vq);
    ring.tx_max_pending = virtqueue_get_vring_size(dvi.sq[0].vq);
    ring.rx_pending = ring.rx_max_pending;
    ring.tx_pending = ring.tx_max_pending;
}

extern(C) size_t strlcpy(char *dest, const char *src, size_t size);
extern(C) const(char) *__dbind__virtio_bus_name(virtio_device *);

extern(C) void virtnet_get_drvinfo(net_device *dev,
                 ethtool_drvinfo *info)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    virtio_device *vdev = vi.vdev;

    strlcpy(info.driver.ptr, "virtio_net_tmp", info.driver.sizeof);
    strlcpy(info.d_alias_version.ptr, VIRTNET_DRIVER_VERSION, info.d_alias_version.sizeof);
    strlcpy(info.bus_info.ptr, __dbind__virtio_bus_name(vdev), info.bus_info.sizeof);

}

extern(C) void __dbind__get_online_cpus();
extern(C) void __dbind__put_online_cpus();

extern(C) int virtnet_set_channels( net_device *dev,
                 ethtool_channels *channels)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    ushort queue_pairs = cast(ushort)channels.combined_count;
    int err;

    if (channels.rx_count || channels.tx_count || channels.other_count)
        return -EINVAL;

    if (queue_pairs > vi.max_queue_pairs || queue_pairs == 0)
        return -EINVAL;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);

    if (dvi.rq[0].xdp_prog)
        return -EINVAL;

    __dbind__get_online_cpus();
    err = _virtnet_set_queues(vi, queue_pairs);
    if (!err) {
        netif_set_real_num_tx_queues(dev, queue_pairs);
        netif_set_real_num_rx_queues(dev, queue_pairs);

        virtnet_set_affinity(vi);
    }
    __dbind__put_online_cpus();

    return err;
}

extern(C) int netif_set_real_num_rx_queues(net_device *dev, uint rxq);
extern(C) int snprintf(char *buf, size_t size, const char *fmt, ...);
extern(C) int netif_set_real_num_tx_queues(net_device *dev, uint txq);

extern(C) void virtnet_get_strings(net_device *dev, uint stringset, ubyte *data)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    char *p = cast(char *)data;
    uint i, j;

    final switch (stringset) {
    case ethtool_stringset.ETH_SS_STATS:
        for (i = 0; i < vi.curr_queue_pairs; i++) {
            for (j = 0; j < VIRTNET_RQ_STATS_LEN; j++) {
                snprintf(p, ETH_GSTRING_LEN, "rx_queue_%u_%s",
                     i, virtnet_rq_stats_desc[j].desc.ptr);
                p += ETH_GSTRING_LEN;
            }
        }

        for (i = 0; i < vi.curr_queue_pairs; i++) {
            for (j = 0; j < VIRTNET_SQ_STATS_LEN; j++) {
                snprintf(p, ETH_GSTRING_LEN, "tx_queue_%u_%s",
                     i, virtnet_sq_stats_desc[j].desc.ptr);
                p += ETH_GSTRING_LEN;
            }
        }
        break;
    }
}

extern(C) int virtnet_get_sset_count(net_device *dev, int sset)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);

    switch (sset) {
    case ethtool_stringset.ETH_SS_STATS:
        return vi.curr_queue_pairs * (VIRTNET_RQ_STATS_LEN +
                           VIRTNET_SQ_STATS_LEN);
    default:
        return -EOPNOTSUPP;
    }
}

extern(C) void virtnet_get_ethtool_stats( net_device *dev,
                       ethtool_stats *stats, ulong *data)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    uint idx = 0, start, i, j;
    const(ubyte) *stats_base;
    size_t offset;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.curr_queue_pairs <= dvi.rq.length);

    for (i = 0; i < vi.curr_queue_pairs; i++) {
        receive_queue *rq = &vi.rq[i];

        stats_base = cast(ubyte *)&rq.stats;
        do {
            start = __dbind__u64_stats_fetch_begin_irq(rq.stats.syncp.ptr);
            for (j = 0; j < VIRTNET_RQ_STATS_LEN; j++) {
                offset = virtnet_rq_stats_desc[j].offset;
                data[idx + j] = *(cast(ulong *)(stats_base + offset));
            }
        } while (__dbind__u64_stats_fetch_retry_irq(rq.stats.syncp.ptr, start));
        idx += VIRTNET_RQ_STATS_LEN;
    }

    assert(vi.curr_queue_pairs <= dvi.sq.length);

    for (i = 0; i < vi.curr_queue_pairs; i++) {
        send_queue *sq = &vi.sq[i];

        stats_base = cast(ubyte *)&sq.stats;
        do {
            start = __dbind__u64_stats_fetch_begin_irq(sq.stats.syncp.ptr);
            for (j = 0; j < VIRTNET_SQ_STATS_LEN; j++) {
                offset = virtnet_sq_stats_desc[j].offset;
                data[idx + j] = *(cast(ulong *)(stats_base + offset));
            }
        } while (__dbind__u64_stats_fetch_retry_irq(sq.stats.syncp.ptr, start));
        idx += VIRTNET_SQ_STATS_LEN;
    }
}

extern(C) void virtnet_get_channels( net_device *dev,
                  ethtool_channels *channels)
{
     virtnet_info *vi = netdev_priv_vinfo(dev);

    channels.combined_count = vi.curr_queue_pairs;
    channels.max_combined = vi.max_queue_pairs;
    channels.max_other = 0;
    channels.rx_count = 0;
    channels.tx_count = 0;
    channels.other_count = 0;
}

enum PORT_OTHER = 0xff;
extern(C) void __dbind__bitmap_zero(c_ulong *, uint);

void ethtool_link_ksettings_zero_link_mode(ethtool_link_ksettings *eth) {
    __dbind__bitmap_zero(eth.link.advertising.ptr, __ETHTOOL_LINK_MODE_MASK_NBITS);
}


extern(C) int memcmp(const void *s1, const void *s2, size_t len);
extern(C) int __dbind__bitmap_empty(const c_ulong *src, uint nbits);
extern(C) bool virtnet_validate_ethtool_cmd(const ethtool_link_ksettings *cmd)
{
    ethtool_link_ksettings diff1 = *cmd;
    ethtool_link_ksettings diff2;

    diff1.base.speed = 0;
    diff2.base.port = PORT_OTHER;
    ethtool_link_ksettings_zero_link_mode(&diff1);
    diff1.base.duplex = 0;
    diff1.base.cmd = 0;
    diff1.base.link_mode_masks_nwords = 0;

    bool res = !memcmp(&diff1.base, &diff2.base, (diff1.base.sizeof)) &&
    __dbind__bitmap_empty(diff1.link.supported.ptr, __ETHTOOL_LINK_MODE_MASK_NBITS) &&
    __dbind__bitmap_empty(diff1.link.advertising.ptr, __ETHTOOL_LINK_MODE_MASK_NBITS) &&
    __dbind__bitmap_empty(diff1.link.lp_advertising.ptr, __ETHTOOL_LINK_MODE_MASK_NBITS);
    return res;
}

extern(C) int __dbind__ethtool_validate_duplex(ubyte duplex);
extern(C) int __dbind__ethtool_validate_speed(uint speed);

extern(C) int virtnet_set_link_ksettings( net_device *dev,
                      const ethtool_link_ksettings *cmd)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    uint speed;

    speed = cmd.base.speed;

    if (!__dbind__ethtool_validate_speed(speed) ||
        !__dbind__ethtool_validate_duplex(cast(ubyte)cmd.base.duplex) ||
        !virtnet_validate_ethtool_cmd(cmd))
        return -EINVAL;
    vi.speed = speed;
    vi.duplex = cast(ubyte)cmd.base.duplex;

    return 0;
}

extern(C) int virtnet_get_link_ksettings( net_device *dev,
                       ethtool_link_ksettings *cmd)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);

    cmd.base.speed = vi.speed;
    cmd.base.duplex = vi.duplex;
    cmd.base.port = PORT_OTHER;

    return 0;
}

enum SPEED_UNKNOWN = -1;
enum DUPLEX_UNKNOWN = 0xff;

extern(C) void virtnet_init_settings( net_device *dev)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);

    vi.speed = SPEED_UNKNOWN;
    vi.duplex = DUPLEX_UNKNOWN;
}

enum VIRTIO_NET_F_SPEED_DUPLEX = 63;

extern(C) uint __dbind__virtio_cread32(virtio_device *vdev, uint offset);
extern(C) uint __dbind__virtio_cread8(virtio_device *vdev, uint offset);

extern(C) void virtnet_update_settings(virtnet_info *vi)
{
    uint speed;
    ubyte duplex;

    if (!__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_SPEED_DUPLEX))
        return;

    speed = __dbind__virtio_cread32(vi.vdev, virtio_net_config.speed.offsetof);
    if (__dbind__ethtool_validate_speed(speed))
        vi.speed = speed;
    duplex = cast(ubyte)__dbind__virtio_cread8(vi.vdev, virtio_net_config.duplex.offsetof);
    if (__dbind__ethtool_validate_duplex(duplex))
        vi.duplex = duplex;
}


extern(C) bool flush_work(work_struct *work);
extern(C) void __dbind__netif_tx_lock_bh(net_device *dev);
extern(C) void netif_device_detach(net_device *dev);
extern(C) void __dbind__netif_tx_unlock_bh(net_device *dev);
extern(C) bool __dbind__netif_running(const net_device *dev);

extern(C) void virtnet_freeze_down( virtio_device *vdev)
{
    virtnet_info *vi = vdev.priv;
    int i;

    /* Make sure no work handler is accessing the device */
    flush_work(&vi.config_work);

    __dbind__netif_tx_lock_bh(vi.dev);
    netif_device_detach(vi.dev);
    __dbind__netif_tx_unlock_bh(vi.dev);
    cancel_delayed_work_sync(&vi.refill);

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);

    if (__dbind__netif_running(vi.dev)) {
        assert(vi.max_queue_pairs <= dvi.rq.length);
        assert(vi.max_queue_pairs <= dvi.sq.length);
        for (i = 0; i < vi.max_queue_pairs; i++) {
            napi_disable(&vi.rq[i].napi);
            virtnet_napi_tx_disable(&vi.sq[i].napi);
        }
    }
}

extern(C) void __dbind__virtio_device_ready(virtio_device *dev);
extern(C) void netif_device_attach(net_device *dev);

extern(C) int virtnet_restore_up(virtio_device *vdev)
{
    virtnet_info *vi = vdev.priv;
    int err, i;

    err = init_vqs(vi);
    if (err)
        return err;

    __dbind__virtio_device_ready(vdev);

    if (__dbind__netif_running(vi.dev)) {

        dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
        assert(dvi.vi == vi);
        assert(vi.curr_queue_pairs <= dvi.rq.length);
        assert(vi.curr_queue_pairs <= dvi.sq.length);

        for (i = 0; i < vi.curr_queue_pairs; i++)
            if (!try_fill_recv(vi, &vi.rq[i], GFP_KERNEL))
                __dbind__schedule_delayed_work(&vi.refill, 0);

        for (i = 0; i < vi.max_queue_pairs; i++) {
            virtnet_napi_enable(vi.rq[i].vq, &vi.rq[i].napi);
            virtnet_napi_tx_enable(vi, vi.sq[i].vq,
                           &vi.sq[i].napi);
        }
    }

    __dbind__netif_tx_lock_bh(vi.dev);
    netif_device_attach(vi.dev);
    __dbind__netif_tx_unlock_bh(vi.dev);
    return err;
}

extern(C) ulong __dbind__cpu_to_virtio64(virtio_device *vdev, ulong val);
enum VIRTIO_NET_CTRL_GUEST_OFFLOADS = 5;
enum VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET = 0;
enum VIRTIO_NET_F_GUEST_CSUM = 1; /* Guest handles pkts w/ partial csum */

extern(C) int virtnet_set_guest_offloads(virtnet_info *vi, ulong offloads)
{
    scatterlist sg;
    vi.ctrl.offloads = __dbind__cpu_to_virtio64(vi.vdev, offloads);

    sg_init_one(&sg, &vi.ctrl.offloads, vi.ctrl.offloads.sizeof);

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_GUEST_OFFLOADS,
                  VIRTIO_NET_CTRL_GUEST_OFFLOADS_SET, &sg)) {
        //dev_warn(&vi.dev.dev, "Fail to set guest offload. \n");
        __dbind__print_bug();
        return -EINVAL;
    }

    return 0;
}

extern(C) int virtnet_clear_guest_offloads( virtnet_info *vi)
{
    ulong offloads = 0;

    if (!vi.guest_offloads)
        return 0;

    if (__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_GUEST_CSUM))
        offloads = 1UL << VIRTIO_NET_F_GUEST_CSUM;

    return virtnet_set_guest_offloads(vi, offloads);
}

extern(C) int virtnet_restore_guest_offloads( virtnet_info *vi)
{
    ulong offloads = vi.guest_offloads;

    if (!vi.guest_offloads)
        return 0;
    if (__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_GUEST_CSUM))
        offloads |= 1UL << VIRTIO_NET_F_GUEST_CSUM;

    return virtnet_set_guest_offloads(vi, offloads);
}

enum VIRTIO_NET_F_CTRL_GUEST_OFFLOADS = 2; /* Dynamic offload configuration. */
enum nr_cpu_ids = 8;
extern(C) void __dbind__bpf_prog_sub(bpf_prog *prog, int i);
extern(C) void __dbind__bpf_prog_put(bpf_prog *prog);
extern(C) long  __dbind__PTR_ERR(const void *ptr);
extern(C) long  __dbind__IS_ERR(const void *ptr);
extern(C) bpf_prog * __dbind__bpf_prog_add(bpf_prog *, int);
extern(C) void __dbind__rcu_assign_pointer(bpf_prog *p, bpf_prog* v);

extern(C) int virtnet_xdp_set(net_device *dev, bpf_prog *prog, netlink_ext_ack *extack)
{
    c_ulong max_sz = PAGE_SIZE - padded_vnet_hdr.sizeof;
    virtnet_info *vi = netdev_priv_vinfo(dev);
    bpf_prog *old_prog;
    ushort xdp_qp = 0, curr_qp;
    int i, err;

    if (!__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)
        && (__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_GUEST_TSO4) ||
            __dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_GUEST_TSO6) ||
            __dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_GUEST_ECN) ||
        __dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_GUEST_UFO))) {
        //NL_SET_ERR_MSG_MOD(extack, "Can't set XDP while host is implementing LRO, disable LRO first");
        __dbind__print_bug();
        return -EOPNOTSUPP;
    }

    if (vi.mergeable_rx_bufs && !vi.any_header_sg) {
        //NL_SET_ERR_MSG_MOD(extack, "XDP expects header/data in single page, any_header_sg required");
        __dbind__print_bug();
        return -EINVAL;
    }

    if (dev.mtu > max_sz) {
        //NL_SET_ERR_MSG_MOD(extack, "MTU too large to enable XDP");
        //netdev_warn(dev, "XDP requires MTU less than %lu\n", max_sz);
        __dbind__print_bug();
        return -EINVAL;
    }

    curr_qp = cast(ushort)(vi.curr_queue_pairs - vi.xdp_queue_pairs);
    if (prog !is null)
        xdp_qp = nr_cpu_ids;

    if (curr_qp + xdp_qp > vi.max_queue_pairs) {
        //NL_SET_ERR_MSG_MOD(extack, "Too few free TX rings available");
        //netdev_warn(dev, "request %i queues but max is %i\n",
                //curr_qp + xdp_qp, vi.max_queue_pairs);
        __dbind__print_bug();
        return -ENOMEM;
    }

    if (prog !is null) {
        prog = __dbind__bpf_prog_add(prog, vi.max_queue_pairs - 1);
        if (__dbind__IS_ERR(prog))
            return cast(int)__dbind__PTR_ERR(prog);
    }

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);
    assert(vi.max_queue_pairs <= dvi.sq.length);

    if (__dbind__netif_running(dev))
        for (i = 0; i < vi.max_queue_pairs; i++)
            napi_disable(&vi.rq[i].napi);

    netif_set_real_num_rx_queues(dev, curr_qp + xdp_qp);
    err = _virtnet_set_queues(vi, cast(ushort)(curr_qp + xdp_qp));
    if (err)
        goto err;
    vi.xdp_queue_pairs = xdp_qp;

    for (i = 0; i < vi.max_queue_pairs; i++) {
        //old_prog = rtnl_dereference(vi.rq[i].xdp_prog);
        old_prog = vi.rq[i].xdp_prog;
        __dbind__rcu_assign_pointer(vi.rq[i].xdp_prog, prog);
        if (i == 0) {
            if (old_prog is null)
                virtnet_clear_guest_offloads(vi);
            if (prog is null)
                virtnet_restore_guest_offloads(vi);
        }
        if (old_prog !is null)
            __dbind__bpf_prog_put(old_prog);
        if (__dbind__netif_running(dev))
            virtnet_napi_enable(vi.rq[i].vq, &vi.rq[i].napi);
    }

    return 0;

err:
    for (i = 0; i < vi.max_queue_pairs; i++)
        virtnet_napi_enable(vi.rq[i].vq, &vi.rq[i].napi);
    if (prog)
        __dbind__bpf_prog_sub(prog, vi.max_queue_pairs - 1);
    return err;
}


extern(C) uint virtnet_xdp_query(net_device *dev)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    const(bpf_prog) *xdp_prog;
    int i;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    //printk("\x05 dvi=%p dvi.vi=%p dvi.sq=%p vi=%p\n\n", dvi, dvi.vi, dvi.sq.ptr, vi);
    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);

    for (i = 0; i < vi.max_queue_pairs; i++) {
        //xdp_prog = rtnl_dereference(vi.rq[i].xdp_prog);
        xdp_prog = vi.rq[i].xdp_prog;
        if (xdp_prog !is null)
            return xdp_prog.aux.id;
    }
    return 0;
}

extern(C) int virtnet_xdp(net_device *dev, netdev_bpf *xdp)
{
    switch (xdp.command) {
    case bpf_netdev_command.XDP_SETUP_PROG:
        return virtnet_xdp_set(dev, xdp.prog, xdp.extack);
    case bpf_netdev_command.XDP_QUERY_PROG:
        xdp.prog_id = virtnet_xdp_query(dev);
        return 0;
    default:
        return -EINVAL;
    }
}

extern(C) int virtnet_get_phys_port_name( net_device *dev, char *buf,
                      size_t len)
{
    virtnet_info *vi = netdev_priv_vinfo(dev);
    int ret;

    if (!__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_STANDBY))
        return -EOPNOTSUPP;

    ret = snprintf(buf, len, "sby");
    if (ret >= len)
        return -EOPNOTSUPP;

    return 0;
}


enum VIRTIO_NET_S_ANNOUNCE = 2;
enum VIRTIO_NET_S_LINK_UP = 1;
enum VIRTIO_NET_F_STATUS = 16;
extern(C) void netdev_notify_peers(net_device *dev);
extern(C) void netif_carrier_on(net_device *dev);
extern(C) void __dbind__netif_tx_wake_all_queues(net_device *dev);
extern(C) void netif_carrier_off(net_device *dev);
extern(C) void netif_tx_stop_all_queues(net_device *dev);
extern(C) int __dbind__virtio_cread_feature_1(virtio_device *vdev, int fbit, ushort *ptr);

extern(C) void virtnet_config_changed_work(work_struct *work)
{
    virtnet_info *vi = container_of!("virtnet_info", "config_work")(work);
    ushort v;

    if (__dbind__virtio_cread_feature_1(vi.vdev, VIRTIO_NET_F_STATUS, &v) < 0)
        return;

    if (v & VIRTIO_NET_S_ANNOUNCE) {
        netdev_notify_peers(vi.dev);
        virtnet_ack_link_announce(vi);
    }

    v &= VIRTIO_NET_S_LINK_UP;

    if (vi.status == v)
        return;

    vi.status = v;

    if (vi.status & VIRTIO_NET_S_LINK_UP) {
        virtnet_update_settings(vi);
        netif_carrier_on(vi.dev);
        __dbind__netif_tx_wake_all_queues(vi.dev);
    } else {
        netif_carrier_off(vi.dev);
        netif_tx_stop_all_queues(vi.dev);
    }
}

extern(C) bool __dbind__schedule_work(work_struct *work);

extern(C) void virtnet_config_changed( virtio_device *vdev)
{
    virtnet_info *vi = vdev.priv;

    __dbind__schedule_work(&vi.config_work);
}

extern(C) bool napi_hash_del(napi_struct *napi);
extern(C) void netif_napi_del(napi_struct *napi);
extern(C) void synchronize_net();

extern(C) void virtnet_free_queues(virtnet_info *vi)
{
    int i;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);
    assert(vi.max_queue_pairs <= dvi.sq.length);

    for (i = 0; i < vi.max_queue_pairs; i++) {
        napi_hash_del(&vi.rq[i].napi);
        netif_napi_del(&vi.rq[i].napi);
        netif_napi_del(&vi.sq[i].napi);
    }

    synchronize_net();

   __dbind__kfree(dvi);
   __dbind__kfree(vi.ctrl);
}

extern(C) void __dbind__RCU_INIT_POINTER_null(bpf_prog *xdp);

extern(C) void _free_receive_bufs(virtnet_info *vi)
{
    bpf_prog *old_prog;
    int i;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);

    for (i = 0; i < vi.max_queue_pairs; i++) {
        while (vi.rq[i].pages)
            __free_pages(get_a_page(&vi.rq[i], GFP_KERNEL), 0);

        //old_prog = rtnl_dereference(vi.rq[i].xdp_prog);
        old_prog = vi.rq[i].xdp_prog;
        __dbind__RCU_INIT_POINTER_null(vi.rq[i].xdp_prog);
        if (old_prog !is null)
            __dbind__bpf_prog_put(old_prog);
    }
}

extern(C) void free_receive_bufs( virtnet_info *vi)
{
    rtnl_lock();
    _free_receive_bufs(vi);
    rtnl_unlock();
}


extern(C) void free_receive_page_frags( virtnet_info *vi)
{
    int i;
    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);

    for (i = 0; i < vi.max_queue_pairs; i++)
        if (vi.rq[i].alloc_frag.page)
            __dbind__put_page(vi.rq[i].alloc_frag.page);
}

extern(C) bool is_xdp_raw_buffer_queue( virtnet_info *vi, int q)
{
    if (q < (vi.curr_queue_pairs - vi.xdp_queue_pairs))
        return false;
    else if (q < vi.curr_queue_pairs)
        return true;
    else
        return false;
}

extern(C) void *virtqueue_detach_unused_buf(virtqueue *_vq);

extern(C) void free_unused_bufs(virtnet_info *vi)
{
    void *buf;
    int i;

    dlang_virtnet_info *dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    assert(vi.max_queue_pairs <= dvi.rq.length);
    assert(vi.max_queue_pairs <= dvi.sq.length);

    for (i = 0; i < vi.max_queue_pairs; i++) {
        virtqueue *vq = vi.sq[i].vq;
        while ((buf = virtqueue_detach_unused_buf(vq)) != null) {
            if (!is_xdp_raw_buffer_queue(vi, i))
                __dbind__dev_kfree_skb(cast(void*)buf);
            else
                __dbind__put_page(__dbind__virt_to_head_page(buf));
        }
    }

    for (i = 0; i < vi.max_queue_pairs; i++) {
         virtqueue *vq = vi.rq[i].vq;

        while ((buf = virtqueue_detach_unused_buf(vq)) != null) {
            if (vi.mergeable_rx_bufs) {
                __dbind__put_page(__dbind__virt_to_head_page(buf));
            } else if (vi.big_packets) {
                give_pages(&vi.rq[i], cast(dstruct_page*)buf);
            } else {
                __dbind__put_page(__dbind__virt_to_head_page(buf));
            }
        }
    }
}

extern(C) void virtnet_del_vqs( virtnet_info *vi)
{
    virtio_device *vdev = vi.vdev;

    virtnet_clean_affinity(vi, -1);

    vdev.config.del_vqs(vdev);

    virtnet_free_queues(vi);
}

 //How large should a single buffer be so a queue full of these can fit at
 //least one full packet?
 //Logic below assumes the mergeable buffer header is used.
enum IP_MAX_MTU = 0xFFFFU;

extern(C) uint mergeable_min_buf_len( virtnet_info *vi,  virtqueue *vq)
{
    const uint hdr_len = virtio_net_hdr_mrg_rxbuf.sizeof;
    uint rq_size = virtqueue_get_vring_size(vq);
    uint packet_len = vi.big_packets ? IP_MAX_MTU : vi.dev.max_mtu;
    uint buf_len = hdr_len + ETH_HLEN + VLAN_HLEN + packet_len;
    //uint min_buf_len = DIV_ROUND_UP(buf_len, rq_size);
    //uint min_buf_len = KERNEL_DIV_ROUND_UP__1(buf_len, rq_size);
    uint min_buf_len = (buf_len + rq_size - 1) / rq_size;

    return max(max(min_buf_len, hdr_len) - hdr_len,
           cast(uint)GOOD_PACKET_LEN);
}

extern(C) void *__dbind__kcalloc(size_t n, size_t size, gfp_t flags);
extern(C) void *__dbind__kmalloc_array(size_t n, size_t size, gfp_t flags);


extern(C) int sprintf(char *buf, const char *fmt, ...);
enum VIRTIO_NET_F_CTRL_VLAN = 19;

netdev_features_t __NETIF_F_BIT(int bit) {
    return cast(netdev_features_t)(1 << bit);
}

netdev_features_t __NETIF_F(string name)() {
    mixin("return __NETIF_F_BIT(gogu.NETIF_F_" ~ name ~ "_BIT);");
}


extern(C) void *addr_skb_recv_done();
extern(C) void *addr_skb_xmit_done();
struct irq_affinity;

extern(C) int virtnet_find_vqs(virtnet_info *vi)
{
    vq_callback_t *callbacks;
    virtqueue **vqs;
    dlang_virtnet_info *dvi;
    int ret = -ENOMEM;
    int i, total_vqs;
    const(char) **names;
    bool *ctx;

     /*[>We expect 1 RX virtqueue followed by 1 TX virtqueue, followed by<]*/
     /*[>possible N-1 RX/TX queue pairs used in multiqueue mode, followed by<]*/
     /*[>possible control vq.<]*/
    total_vqs = vi.max_queue_pairs * 2 +
            __dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_CTRL_VQ);

    /*[>[> Allocate space for find_vqs parameters <]<]*/
    vqs = cast(virtqueue**)__dbind__kcalloc(total_vqs, (*vqs).sizeof, GFP_KERNEL);
    if (!vqs)
        goto err_vq;
    //grija!!!
    callbacks = cast(vq_callback_t*)__dbind__kmalloc_array(total_vqs, (*callbacks).sizeof, GFP_KERNEL);
    if (!callbacks)
        goto err_callback;
    //grija!!!
    names = cast(const(char)**)__dbind__kmalloc_array(total_vqs, (*names).sizeof, GFP_KERNEL);
    if (!names)
        goto err_names;
    if (!vi.big_packets || vi.mergeable_rx_bufs) {
        ctx = cast(bool*)__dbind__kcalloc(total_vqs, (*ctx).sizeof, GFP_KERNEL);
        if (!ctx)
            goto err_ctx;
    } else {
        ctx = null;
    }

    /*[>[> Parameters for control virtqueue, if any <]<]*/
    if (vi.has_cvq) {
        callbacks[total_vqs - 1] = null;
        names[total_vqs - 1] = "control";
    }

    /*[>[> Allocate/initialize parameters for send/receive virtqueues <]<]*/




    dvi = container_of!("dlang_virtnet_info", "tmp")(vi.sq);
    assert(dvi.vi == vi);
    //printk("\x05 e ok salut \n\n");
    //printk("\x05 dvi=%p dvi.vi=%p dvi.sq=%p vi=%p\n\n", dvi, dvi.vi, dvi.sq.ptr, vi);
    //printk("\x05 dvi.rq.length=%zu, dvi.sq.length=%zu, vi.max=%hu\n\n", dvi.rq.length,
            //dvi.sq.length, vi.max_queue_pairs);

    assert(vi.max_queue_pairs <= dvi.rq.length);
    assert(vi.max_queue_pairs <= dvi.sq.length);

    for (i = 0; i < vi.max_queue_pairs; i++) {
        callbacks[rxq2vq(i)] = cast(vq_callback_t)addr_skb_recv_done;
        callbacks[txq2vq(i)] = cast(vq_callback_t)addr_skb_xmit_done;
        sprintf(vi.rq[i].name.ptr, "input.%d", i);
        sprintf(vi.sq[i].name.ptr, "output.%d", i);
        names[rxq2vq(i)] = vi.rq[i].name.ptr;
        names[txq2vq(i)] = vi.sq[i].name.ptr;
        if (ctx)
            ctx[rxq2vq(i)] = true;
    }

    ret = vi.vdev.config.find_vqs(vi.vdev, total_vqs, vqs, callbacks,
                     names, ctx, null);
    if (ret)
        goto err_find;

    if (vi.has_cvq) {
        vi.cvq = vqs[total_vqs - 1];
        if (__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_CTRL_VLAN))
            //vi.dev.features |= NETIF_F_HW_VLAN_CTAG_FILTER;
            vi.dev.features |= __NETIF_F!("HW_VLAN_CTAG_FILTER");
    }

    for (i = 0; i < vi.max_queue_pairs; i++) {
        vi.rq[i].vq = vqs[rxq2vq(i)];
        vi.rq[i].min_buf_len = mergeable_min_buf_len(vi, vi.rq[i].vq);
        vi.sq[i].vq = vqs[txq2vq(i)];
    }

    /*[>[> run here: ret == 0. <]<]*/


err_find:
    __dbind__kfree(ctx);
err_ctx:
    __dbind__kfree(names);
err_names:
    __dbind__kfree(callbacks);
err_callback:
    __dbind__kfree(vqs);
err_vq:
    return ret;
}

extern(C) void __dbind__u64_stats_init(u64_stats_sync *syncp);
extern(C) void __dbind__netif_napi_add(net_device *dev, napi_struct *napi,
             int weight);
extern(C) void __dbind__netif_tx_napi_add(net_device *dev,
                     napi_struct *napi,
                     int weight);

extern(C) void __dbind__INIT_DELAYED_WORK(delayed_work* dw);
extern(C) void __dbind__ewma_pkt_len_init(ewma_pkt_len *e);

extern(C) int virtnet_alloc_queues(virtnet_info *vi)
{
    int i;
    size_t sq_size;
    size_t rq_size;
    size_t dvi_total_size;
    dlang_virtnet_info* dvi;

    vi.ctrl = cast(control_buf*)__dbind__kzalloc((*vi.ctrl).sizeof, GFP_KERNEL);
    if (vi.ctrl is null)
        goto err_ctrl;

    sq_size = (*vi.sq).sizeof * vi.max_queue_pairs;
    rq_size = (*vi.rq).sizeof * vi.max_queue_pairs;
    dvi_total_size = dlang_virtnet_info.sizeof + sq_size + rq_size;
    dvi = cast(dlang_virtnet_info*) __dbind__kzalloc(dvi_total_size, GFP_KERNEL);
    dvi.sq = (cast(send_queue*)(dvi.tmp.ptr))[0 .. vi.max_queue_pairs];

    if (dvi.sq is null)
        goto err_sq;

    vi.sq = dvi.sq.ptr;
    dvi.vi = vi;

    dvi.rq = (cast(receive_queue*)(dvi.tmp.ptr + sq_size))[0 .. vi.max_queue_pairs];

    if (dvi.rq is null)
        goto err_rq;
    vi.rq = dvi.rq.ptr;


    __dbind__INIT_DELAYED_WORK(&vi.refill);
    for (i = 0; i < vi.max_queue_pairs; i++) {
        vi.rq[i].pages = null;
        __dbind__netif_napi_add(vi.dev, &vi.rq[i].napi, napi_weight);
        __dbind__netif_tx_napi_add(vi.dev, &vi.sq[i].napi, napi_tx ? napi_weight : 0);

        sg_init_table(vi.rq[i].sg.ptr, cast(uint)ARRAY_SIZE(vi.rq[i].sg));
        __dbind__ewma_pkt_len_init(&vi.rq[i].mrg_avg_pkt_len);
        sg_init_table(vi.sq[i].sg.ptr, cast(uint)ARRAY_SIZE(vi.sq[i].sg));

        __dbind__u64_stats_init(vi.rq[i].stats.syncp.ptr);
        __dbind__u64_stats_init(vi.sq[i].stats.syncp.ptr);
    }

    return 0;

err_rq:
    __dbind__kfree(vi.sq);
err_sq:
    __dbind__kfree(vi.ctrl);
err_ctrl:
    return -ENOMEM;
}

extern(C) int init_vqs( virtnet_info *vi)
{
    int ret;

    //[> Allocate send & receive queues <]
    ret = virtnet_alloc_queues(vi);
    if (ret)
        goto err;

    ret = virtnet_find_vqs(vi);
    if (ret)
        goto err_free;

    __dbind__get_online_cpus();
    virtnet_set_affinity(vi);
    __dbind__put_online_cpus();

    return 0;

err_free:
    virtnet_free_queues(vi);
err:
    return ret;
}


//extern(C) uint __dbind__get_netdev_rx_queue_index(netdev_rx_queue *);

//version(CONFIG_SYSFS) {
    //extern(C) ssize_t mergeable_rx_buffer_size_show(netdev_rx_queue *queue,
            //char *buf)
    //{
        //virtnet_info *vi = netdev_priv_vinfo(queue.dev);
        //uint queue_index = __dbind__get_netdev_rx_queue_index(queue);
        //uint headroom = virtnet_get_headroom(vi);
        //uint tailroom = headroom ? skb_shared_info.sizeof : 0;
        //ewma_pkt_len *avg;

        ////BUG_ON(queue_index >= vi.max_queue_pairs);
        //assert(queue_index < vi.max_queue_pairs);
        //avg = &vi.rq[queue_index].mrg_avg_pkt_len;
        //return sprintf(buf, "%u\n",
                   //get_mergeable_buf_len(&vi.rq[queue_index], avg,
                           //SKB_DATA_ALIGN(headroom + tailroom)));
    //}

    //static rx_queue_attribute mergeable_rx_buffer_size_attribute =
        //.attr = {.name = "mergeable_rx_buffer_size", .mode = std.conv.octal!444 },
        //.show = mergeable_rx_buffer_size_show;
    

    //static attribute *virtio_net_mrg_rx_attrs[] = {
        //&mergeable_rx_buffer_size_attribute.attr,
        //NULL
    //};

    //const attribute_group virtio_net_mrg_rx_group = {
        //.name = "virtio_net",
        //.attrs = virtio_net_mrg_rx_attrs,
    //};
//}


enum VIRTIO_NET_F_GUEST_ANNOUNCE = 21;

extern(C) bool virtnet_validate_features(virtio_device *vdev)
{
    if (!__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ) &&
        (virtnet_fail_on_feature(vdev, VIRTIO_NET_F_CTRL_RX,
               "VIRTIO_NET_F_CTRL_RX", "VIRTIO_NET_F_CTRL_VQ") ||
         virtnet_fail_on_feature(vdev, VIRTIO_NET_F_CTRL_VLAN,
             "VIRTIO_NET_F_CTRL_VLAN", "VIRTIO_NET_F_CTRL_VQ") ||
         virtnet_fail_on_feature(vdev, VIRTIO_NET_F_GUEST_ANNOUNCE,
               "VIRTIO_NET_F_GUEST_ANNOUNCE", "VIRTIO_NET_F_CTRL_VQ") ||
         virtnet_fail_on_feature(vdev, VIRTIO_NET_F_MQ, "VIRTIO_NET_F_MQ",
             "VIRTIO_NET_F_CTRL_VQ") ||
         virtnet_fail_on_feature(vdev, VIRTIO_NET_F_CTRL_MAC_ADDR,
             "VIRTIO_NET_F_CTRL_MAC_ADDR", "VIRTIO_NET_F_CTRL_VQ"))) {
        return false;
    }

    return true;
}

enum ETH_MIN_MTU = 68;
enum ETH_MAX_MTU = 0xFFFFU;
enum MIN_MTU = ETH_MIN_MTU;
enum MAX_MTU = ETH_MAX_MTU;
enum VIRTIO_NET_F_MTU = 3;
extern(C) ushort __dbind__virtio_cread16(virtio_device *, uint);
extern(C) void __dbind__virtio_clear_bit(virtio_device *, uint);

extern(C) int virtnet_validate(virtio_device *vdev)
{
    if (vdev.config.get is null) {
        //dev_err(&vdev.dev, "%s failure: config access disabled\n",
            //__func__);
        printk("%s failure: config access disabled\n");
        return -EINVAL;
    }

    if (!virtnet_validate_features(vdev))
        return -EINVAL;

    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_MTU)) {
        int mtu = __dbind__virtio_cread16(vdev, virtio_net_config.mtu.offsetof);
        if (mtu < MIN_MTU)
            __dbind__virtio_clear_bit(vdev, VIRTIO_NET_F_MTU);
    }

    return 0;
}

extern(C) int __dbind__virtio_cread_feature_2(virtio_device *, int, ushort *);
extern(C) void __dbind__virtio_cread_bytes(virtio_device *, uint offset,
        void *buf, size_t len);
enum VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN = 1;
enum VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX = 0x8000;
enum VIRTIO_NET_F_CSUM = 0;
enum VIRTIO_NET_F_GSO = 6;
enum VIRTIO_NET_F_HOST_TSO4 = 11;
enum VIRTIO_NET_F_HOST_TSO6 = 12;
enum VIRTIO_NET_F_HOST_ECN = 13;
enum VIRTIO_NET_F_MRG_RXBUF = 15;
enum VIRTIO_F_ANY_LAYOUT = 27;
extern(C) void* __dbind__get_virtnet_netdev_addr();
extern(C) void* __dbind__get_ethtool_ops_addr();
extern(C) void __dbind__eth_hw_addr_random(net_device *);
extern(C) dstruct_failover *__dbind__net_failover_create(net_device *standby_dev);
extern(C) int register_netdev(net_device *dev);
extern(C) void __dbind__set_bit(int nr, void *addr);
extern(C) void unregister_netdev(net_device *dev);
extern(C) void net_failover_destroy(dstruct_failover *);
extern(C) void free_netdev(net_device *dev);
extern(C) void __dbind__INIT_WORK(work_struct *ws);
extern(C) net_device* __dbind__alloc_etherdev_mq(size_t, uint);
extern(C) attribute_group * __dbind__get_mrg_rx_group();

netdev_features_t __NETIF_F_ALL_TSO() {
    return (__NETIF_F!("TSO") | __NETIF_F!("TSO6") |
     __NETIF_F!("TSO_ECN") | __NETIF_F!("TSO_MANGLEID"));
}


extern(C) int virtnet_probe(virtio_device *vdev)
{
    int i, err = -ENOMEM;
    net_device *dev;
    virtnet_info *vi;
    ushort max_queue_pairs;
    int mtu;

    //[> Find if host supports multiqueue virtio_net device <]
    err = __dbind__virtio_cread_feature_2(vdev, VIRTIO_NET_F_MQ, &max_queue_pairs);

    //[> We need at least 2 queue's <]
    if (err || max_queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
        max_queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
        !__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
        max_queue_pairs = 1;

    //[> Allocate ourselves a network device with room for our info <]
    dev = __dbind__alloc_etherdev_mq(virtnet_info.sizeof, max_queue_pairs);
    if (dev is null)
        return -ENOMEM;

    //[> Set up network device as normal. <]
    dev.priv_flags |= netdev_priv_flags.IFF_UNICAST_FLT | netdev_priv_flags.IFF_LIVE_ADDR_CHANGE;
    //dev.netdev_ops = &virtnet_netdev;
    dev.netdev_ops = cast(net_device_ops*)__dbind__get_virtnet_netdev_addr();
    dev.features = __NETIF_F!("HIGHDMA");

    dev.ethtool_ops = cast(ethtool_ops*)__dbind__get_ethtool_ops_addr();
    //#define SET_NETDEV_DEV(net, pdev)	((net)->dev.parent = (pdev))
    //SET_NETDEV_DEV(dev, &vdev.dev);
    dev.dev.parent = &vdev.dev;

    //[> Do we support "hardware" checksums? <]
    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_CSUM)) {
        //[> This opens up the world of extra features. <]
        dev.hw_features |= __NETIF_F!("HW_CSUM") | __NETIF_F!("SG");
        if (csum)
            dev.features |= __NETIF_F!("HW_CSUM") | __NETIF_F!("SG");

        if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_GSO)) {
            dev.hw_features |= __NETIF_F!("TSO")
                | __NETIF_F!("TSO_ECN") | __NETIF_F!("TSO6");
        }
        //[> Individual feature bits: what can host handle? <]
        if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO4))
            dev.hw_features |= __NETIF_F!("TSO");
        if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO6))
            dev.hw_features |= __NETIF_F!("TSO6");
        if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_HOST_ECN))
            dev.hw_features |= __NETIF_F!("TSO_ECN");

        dev.features |= __NETIF_F!("GSO_ROBUST");

        if (gso)
            dev.features |= dev.hw_features & __NETIF_F_ALL_TSO;
        //[> (!csum && gso) case will be fixed by register_netdev() <]
    }
    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_CSUM))
        dev.features |= __NETIF_F!("RXCSUM");

    dev.vlan_features = dev.features;

    //[> MTU range: 68 - 65535 <]
    dev.min_mtu = MIN_MTU;
    dev.max_mtu = MAX_MTU;

    //[> Configuration may specify what MAC to use.  Otherwise random. <]
    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_MAC))
        __dbind__virtio_cread_bytes(vdev,
                virtio_net_config.mac.offsetof,
                dev.dev_addr, dev.addr_len);
    else
        __dbind__eth_hw_addr_random(dev);

    //[> Set up our device-specific information <]
    vi = netdev_priv_vinfo(dev);
    vi.dev = dev;
    vi.vdev = vdev;
    vdev.priv = vi;

    __dbind__INIT_WORK(&vi.config_work);

    //[> If we can receive ANY GSO packets, we must allocate large ones. <]
    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
        __dbind__virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6) ||
        __dbind__virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_ECN) ||
        __dbind__virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_UFO))
        vi.big_packets = true;

    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF))
        vi.mergeable_rx_bufs = true;

    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF) ||
        __dbind__virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
        vi.hdr_len = virtio_net_hdr_mrg_rxbuf.sizeof;
    else
        vi.hdr_len = virtio_net_hdr.sizeof;

    if (__dbind__virtio_has_feature(vdev, VIRTIO_F_ANY_LAYOUT) ||
        __dbind__virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
        vi.any_header_sg = true;

    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
        vi.has_cvq = true;

    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_MTU)) {
        mtu = __dbind__virtio_cread16(vdev, virtio_net_config.mtu.offsetof);
        if (mtu < dev.min_mtu) {
            //Should never trigger: MTU was previously validated
             //in virtnet_validate.
            //dev_err(&vdev.dev, "device MTU appears to have changed "
                //"it is now %d < %d", mtu, dev.min_mtu);
            printk("device MTU appears to have changed\n");
            goto free;
        }

        dev.mtu = mtu;
        dev.max_mtu = mtu;

        //[> TODO: size buffers correctly in this case. <]
        if (dev.mtu > ETH_DATA_LEN)
            vi.big_packets = true;
    }

    if (vi.any_header_sg)
        dev.needed_headroom = vi.hdr_len;

    //[> Enable multiqueue by default <]
    if (__dbind__num_online_cpus() >= max_queue_pairs)
        vi.curr_queue_pairs = cast(ushort)max_queue_pairs;
    else
        vi.curr_queue_pairs = cast(ushort)__dbind__num_online_cpus();
    vi.max_queue_pairs = cast(ushort)max_queue_pairs;

    //[> Allocate/initialize the rx/tx queues, and invoke find_vqs <]
    err = init_vqs(vi);
    if (err)
        goto free;

    version(CONFIG_SYSFS) {
        if (vi.mergeable_rx_bufs)
            dev.sysfs_rx_queue_group = __dbind__get_mrg_rx_group();
    }
    netif_set_real_num_tx_queues(dev, vi.curr_queue_pairs);
    netif_set_real_num_rx_queues(dev, vi.curr_queue_pairs);

    virtnet_init_settings(dev);

    if (__dbind__virtio_has_feature(vdev, VIRTIO_NET_F_STANDBY)) {
        vi.failover = __dbind__net_failover_create(vi.dev);
        if (__dbind__IS_ERR(vi.failover)) {
            err = cast(int)__dbind__PTR_ERR(vi.failover);
            goto free_vqs;
        }
    }

    err = register_netdev(dev);
    if (err) {
        //pr_debug("virtio_net: registering device failed\n");
        printk("virtio_net: registering device failed\n");
        goto free_failover;
    }

    __dbind__virtio_device_ready(vdev);

    err = virtnet_cpu_notif_add(vi);
    if (err) {
        //pr_debug("virtio_net: registering cpu notifier failed\n");
        printk("virtio_net: registering cpu notifier failed\n");
        goto free_unregister_netdev;
    }

    virtnet_set_queues(vi, vi.curr_queue_pairs);

    //[> Assume link up if device can't report link status,
       //otherwise get link status from config. */
    netif_carrier_off(dev);
    if (__dbind__virtio_has_feature(vi.vdev, VIRTIO_NET_F_STATUS)) {
        __dbind__schedule_work(&vi.config_work);
    } else {
        vi.status = VIRTIO_NET_S_LINK_UP;
        virtnet_update_settings(vi);
        netif_carrier_on(dev);
    }

    //for (i = 0; i < ARRAY_SIZE(guest_offloads); i++)
    for (i = 0; i < 4; i++)
        if (__dbind__virtio_has_feature(vi.vdev, cast(uint)guest_offloads[i]))
            __dbind__set_bit(cast(int)guest_offloads[i], &vi.guest_offloads);

    printk("virtnet: registered device %s with %d RX and TX vq's\n",
         dev.name.ptr, max_queue_pairs);
    //printk("virtnet: registered device %s with %d RX and TX vq's\n");

    return 0;

free_unregister_netdev:
    vi.vdev.config.reset(vdev);

    unregister_netdev(dev);
free_failover:
    net_failover_destroy(vi.failover);
free_vqs:
    cancel_delayed_work_sync(&vi.refill);
    free_receive_page_frags(vi);
    virtnet_del_vqs(vi);
free:
    free_netdev(dev);
    return err;
}


extern(C) void remove_vq_common( virtnet_info *vi)
{
    vi.vdev.config.reset(vi.vdev);

    /* Free unused buffers in both send and recv, if any. */
    free_unused_bufs(vi);

    free_receive_bufs(vi);

    free_receive_page_frags(vi);

    virtnet_del_vqs(vi);
}

extern(C) void virtnet_remove( virtio_device *vdev)
{
    virtnet_info *vi = vdev.priv;

    virtnet_cpu_notif_remove(vi);

    /* Make sure no work handler is accessing the device. */
    flush_work(&vi.config_work);

    unregister_netdev(vi.dev);

    net_failover_destroy(vi.failover);

    remove_vq_common(vi);

    free_netdev(vi.dev);
}

extern(C) int virtnet_freeze( virtio_device *vdev)
{
    virtnet_info *vi = vdev.priv;

    virtnet_cpu_notif_remove(vi);
    virtnet_freeze_down(vdev);
    remove_vq_common(vi);

    return 0;
}

extern(C) int virtnet_restore( virtio_device *vdev)
{
    virtnet_info *vi = vdev.priv;
    int err;

    err = virtnet_restore_up(vdev);
    if (err)
        return err;
    virtnet_set_queues(vi, vi.curr_queue_pairs);

    err = virtnet_cpu_notif_add(vi);
    if (err)
        return err;

    return 0;
}
