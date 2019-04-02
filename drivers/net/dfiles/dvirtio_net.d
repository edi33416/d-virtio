import core.stdc.config;
import virtio_h: virtio_net_config, virtio_config_ops,virtio_device,
       virtqueue;
import mod_devicetable_h;
import napi_struct_h : napi_struct;
import spinlock_types_h;
import device_h;
import mutex_h;
import kobject_h : kobject, delayed_work;
import link_state_h : rtnl_link_stats64;
import net_device_h;
import sk_buff_h : sk_buff, skb_shared_info;
import bpf_prog_h : bpf_prog;
import send_queue_h : send_queue, scatterlist, virtnet_sq_stats, MAX_SKB_FRAGS, PAGE_SIZE,
       u64_stats_sync;
import page_h : dstruct_page = page;
import receive_queue_h : receive_queue, virtnet_rq_stats, xdp_frame, xdp_buff, xdp_action,
       ewma_pkt_len, page_frag, xdp_rxq_info;
import control_buf_h : control_buf;
import virtnet_info_h : virtnet_info;
import cache_h : L1_CACHE_BYTES;
import std.algorithm.comparison : max, min;
import core.stdc.string : memcpy, memset;
import gfp_h;
import sock_h;

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

pragma(inline, true) void* container_of(string type, string member)(void *ptr) {
    return (ptr - mixin(type ~ "." ~ member ~ ".offsetof"));
}

auto ARRAY_SIZE(T)(T[] x) {
    return x.length;
}

enum NAPI_POLL_WEIGHT = 64;

int napi_weight = NAPI_POLL_WEIGHT;
bool csum = true, gso = true, napi_tx;

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

immutable enum c_ulong[] guest_offloads = [
    VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_ECN,
    VIRTIO_NET_F_GUEST_UFO
];

struct virtnet_stat_desc {
    char[ETH_GSTRING_LEN] desc;
    size_t offset;
}

pragma(msg, "stat_desc sizeof:", virtnet_stat_desc.sizeof);

immutable enum virtnet_stat_desc[5] virtnet_sq_stats_desc = [
    { "packets", virtnet_sq_stats.packets.offsetof },
    { "bytes", virtnet_sq_stats.bytes.offsetof },
    { "xdp_tx", virtnet_sq_stats.xdp_tx.offsetof },
    { "xdp_tx_drops", virtnet_sq_stats.xdp_tx_drops.offsetof },
    { "kicks",  virtnet_sq_stats.kicks.offsetof},
];

immutable enum virtnet_stat_desc[8] virtnet_rq_stats_desc = [
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

extern(C) bool napi_schedule_prep(napi_struct *);
extern(C) void virtqueue_disable_cb(virtqueue *);
extern(C) void __napi_schedule(napi_struct *);
extern(C) uint virtqueue_enable_cb_prepare(virtqueue *);
extern(C) bool napi_complete_done(napi_struct *, int);
extern(C) bool virtqueue_poll(virtqueue *, uint);

extern(C) int txq2vq(int txq) {
    return txq * 2 + 1;
}

extern(C) int rxq2vq(int rxq)
{
    return rxq * 2;
}

enum int MRG_CTX_HEADER_SHIFT = 22;

extern(C) void *mergeable_len_to_ctx(uint truesize, uint headroom)
{
    return cast(void *)(cast(c_ulong)((headroom << MRG_CTX_HEADER_SHIFT) | truesize));
}

extern(C) uint mergeable_ctx_to_headroom(void *mrg_ctx)
{
    return cast(uint)(cast(c_ulong)(mrg_ctx) >> MRG_CTX_HEADER_SHIFT);
}

extern(C) uint mergeable_ctx_to_truesize(void *mrg_ctx)
{
    return cast(c_ulong)(mrg_ctx) & ((1 << MRG_CTX_HEADER_SHIFT) - 1);
}

extern(C) int vq2rxq(virtqueue *vq)
{
	return vq.index / 2;
}

extern(C) int vq2txq(virtqueue *vq)
{
    return (vq.index - 1) / 2;
}


extern(C) void virtqueue_napi_schedule(napi_struct *napi, virtqueue *vq)
{
    if (napi_schedule_prep(napi)) {
        virtqueue_disable_cb(vq);
        __napi_schedule(napi);
    }
}

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

extern(C) pragma(inline, true) bool __dbind__virtio_has_feature(const virtio_device *vdev, uint fbit);

pragma(inline, true) bool virtio_has_feature(const virtio_device *vdev, uint fbit)
{
    return __dbind__virtio_has_feature(vdev, fbit);
}

extern(C) bool virtnet_fail_on_feature(virtio_device *vdev, uint fbit,
        const char *fname, const char *dname)
{
    if (!virtio_has_feature(vdev, fbit))
        return false;

    //dev_err(&vdev->dev, "device advertises feature %s but not %s", fname, dname);

    return true;
}


extern(C) virtio_net_hdr_mrg_rxbuf *skb_vnet_hdr(sk_buff *skb)
{
	return cast(virtio_net_hdr_mrg_rxbuf *)skb.cb;
}



extern(C) void give_pages(receive_queue *rq, dstruct_page *page)
{
    dstruct_page *end;

    /* Find end of list, sew whole thing into vi->rq.pages. */
    for (end = page; end.d_alias_private; end = cast(dstruct_page *)end.d_alias_private)
    {

    }

    end.d_alias_private = cast(c_ulong)rq.pages;
    rq.pages = page;
}

extern(C) dstruct_page * __dbind__alloc_page(gfp_t);

extern(C) dstruct_page *get_a_page(receive_queue *rq, gfp_t gfp_mask)
{
    dstruct_page *p = rq.pages;

    if (p !is null) {
        rq.pages = cast(dstruct_page *)p.d_alias_private;
        /* clear private here, it is used to chain pages <] */
        p.d_alias_private = 0;
    } else
        p = __dbind__alloc_page(gfp_mask);
    return p;
}


extern(C) void __dbind__netif_wake_subqueue(net_device *, ushort);

extern(C) void skb_xmit_done(virtqueue *vq)
{
    virtnet_info *vi = cast(virtnet_info *)vq.vdev.priv;
    napi_struct *napi = &vi.sq[vq2txq(vq)].napi;

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
extern(C) void __dbind__dev_kfree_skb(sk_buff *);
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


extern(C) uint __dbind__smp_processor_id();

extern(C) send_queue * virtnet_xdp_sq(virtnet_info *vi)
{
    uint qp;

    qp = vi.curr_queue_pairs - vi.xdp_queue_pairs + __dbind__smp_processor_id();
    return &vi.sq[qp];
}

extern(C) void * __dbind__netdev_priv(const net_device *);
extern(C) void xdp_return_frame(xdp_frame *);
extern(C) void *virtqueue_get_buf(virtqueue *, uint *);
extern(C) void xdp_return_frame_rx_napi(xdp_frame *);
extern(C) bool virtqueue_kick_prepare(virtqueue *);
extern(C) bool virtqueue_notify(virtqueue *_vq);
extern(C) void __dbind__u64_stats_update_begin(u64_stats_sync *syncp);
extern(C) void __dbind__u64_stats_update_end(u64_stats_sync *syncp);

enum XDP_XMIT_FLUSH = (1U << 0); /* doorbell signal consumer */
enum XDP_XMIT_FLAGS_MASK = XDP_XMIT_FLUSH;


extern(C) int rcu_read_lock_held();
extern(C) void __dbind__read_once_size(const void *, void *, int);

//T __d__READ_ONCE(T)(T x, int check) {
    //union __u {
        //T __val;
        //char[1] __c;
    //}
    //__u u;
    //if (check)
        //__dbind__read_once_size(&x, u.__c.ptr, x.sizeof);
    //return u.__val;
//}

//T __rcu_dereference_check(T)(T p, int condition) {
    //T p1 = __d__READ_ONCE(p, 1);
    //return p1;
//}

//T rcu_dereference_check(T)(T p, int condition) {
    //return __rcu_dereference_check(p, condition || rcu_read_lock_held());
//}

//T rcu_dereference(T)(T p)
//if (is(T == U*, U))
//{
    //return (rcu_dereference_check(p, 0));
//}

extern(C) int virtnet_xdp_xmit(net_device *dev,
        int n,  xdp_frame **frames, uint flags)
{
    virtnet_info *vi = cast(virtnet_info *)__dbind__netdev_priv(dev);
    receive_queue *rq = vi.rq;
    xdp_frame *xdpf_sent;
    bpf_prog *xdp_prog;
    send_queue *sq;
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

extern(C) int __dbind__SKB_DATA_ALIGN(size_t);
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
        int tailroom = __dbind__SKB_DATA_ALIGN(skb_shared_info.sizeof);
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
    uint buflen = __dbind__SKB_DATA_ALIGN(GOOD_PACKET_LEN + headroom) +
                  __dbind__SKB_DATA_ALIGN(skb_shared_info.sizeof);
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
            buflen = __dbind__SKB_DATA_ALIGN(GOOD_PACKET_LEN + headroom) +
                 __dbind__SKB_DATA_ALIGN(skb_shared_info.sizeof);
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

extern(C) sk_buff *receive_mergeable( net_device *dev,
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
        //skb.ip_summed = CHECKSUM_UNNECESSARY;
        __dbind__set_ip_summed(skb, CHECKSUM_UNNECESSARY);
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

    len = __dbind__SKB_DATA_ALIGN(len) +
          __dbind__SKB_DATA_ALIGN(skb_shared_info.sizeof);
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
extern(C) uint __dbind__ALIGN(uint len, uint L1);

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

    return __dbind__ALIGN(len, L1_CACHE_BYTES);
}



extern(C) int add_recvbuf_mergeable(virtnet_info *vi,
                 receive_queue *rq, gfp_t gfp)
{
    page_frag *alloc_frag = &rq.alloc_frag;
    uint headroom = virtnet_get_headroom(vi);
    uint tailroom = headroom ? (skb_shared_info.sizeof) : 0;
    uint room = __dbind__SKB_DATA_ALIGN(headroom + tailroom);
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
    virtnet_info *vi = cast(virtnet_info *)rvq.vdev.priv;
    receive_queue *rq = &vi.rq[vq2rxq(rvq)];

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
    virtnet_info *vi = cast(virtnet_info *)container_of!("virtnet_info", "refill")(work);
    bool still_empty;
    int i;

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

extern(C) int virtnet_receive(receive_queue *rq, int budget,
               uint *xdp_xmit)
{
    virtnet_info *vi = cast(virtnet_info*)rq.vq.vdev.priv;
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
    virtnet_info *vi = cast(virtnet_info *)(rq.vq.vdev.priv);
    uint index = vq2rxq(rq.vq);
    send_queue *sq = &vi.sq[index];
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
    receive_queue *rq = cast(receive_queue *)container_of!("receive_queue", "napi")(napi);
    virtnet_info *vi = cast(virtnet_info *)(rq.vq.vdev.priv);
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
    virtnet_info *vi = cast(virtnet_info *)__dbind__netdev_priv(dev);
    int i, err;

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
     send_queue *sq = cast(send_queue *)container_of!("send_queue", "napi")(napi);
     virtnet_info *vi = cast(virtnet_info*)sq.vq.vdev.priv;
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

extern(C) int xmit_skb( send_queue *sq,  sk_buff *skb)
{
    virtio_net_hdr_mrg_rxbuf *hdr;
    const ubyte * dest = cast(ubyte *)((cast (ethhdr *)skb.data).h_dest);
    virtnet_info *vi = cast(virtnet_info *)sq.vq.vdev.priv;
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
    virtnet_info *vi = cast(virtnet_info *)__dbind__netdev_priv(dev);
    int qnum = __dbind__skb_get_queue_mapping(skb);
    send_queue *sq = &vi.sq[qnum];
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

extern(C) void __dbind__scatter_print(scatterlist** scat);

extern(C) bool virtnet_send_command(virtnet_info *vi, ubyte dlang_class_alias, ubyte cmd,
                  scatterlist *dlang_out_alias)
{
    scatterlist*[4] sgs;
    scatterlist hdr, stat;
    uint out_num = 0;
    uint tmp;

    //BUG_ON(!virtio_has_feature(vi.vdev, VIRTIO_NET_F_CTRL_VQ));
    assert(virtio_has_feature(vi.vdev, VIRTIO_NET_F_CTRL_VQ) == true);

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
    virtnet_info *vi = cast(virtnet_info *)__dbind__netdev_priv(dev);
    virtio_device *vdev = vi.vdev;
    int ret;
    sockaddr *addr;
    scatterlist sg;

    if (virtio_has_feature(vi.vdev, VIRTIO_NET_F_STANDBY))
        return -EOPNOTSUPP;

    addr = cast(sockaddr *)__dbind__kmemdup(p, (*addr).sizeof, GFP_KERNEL);
    if (!addr)
        return -ENOMEM;

    ret = eth_prepare_mac_addr_change(dev, addr);
    if (ret)
        goto out_label;

    if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_MAC_ADDR)) {
        sg_init_one(&sg, addr.sa_data.ptr, dev.addr_len);
        if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MAC,
                      VIRTIO_NET_CTRL_MAC_ADDR_SET, &sg)) {
            //dev_warn(&vdev.dev,
                 //"Failed to set mac address by vq command.\n");
            ret = -EINVAL;
            goto out_label;
        }
    } else if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC) &&
           !virtio_has_feature(vdev, VIRTIO_F_VERSION_1)) {
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
    virtnet_info *vi = cast(virtnet_info *)__dbind__netdev_priv(dev);
    uint start;
    int i;

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

    if (!vi.has_cvq || !virtio_has_feature(vi.vdev, VIRTIO_NET_F_MQ))
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
    virtnet_info *vi = cast(virtnet_info *)__dbind__netdev_priv(dev);
    int i;

    cancel_delayed_work_sync(&vi.refill);

    for (i = 0; i < vi.max_queue_pairs; i++) {
        xdp_rxq_info_unreg(&vi.rq[i].xdp_rxq);
        napi_disable(&vi.rq[i].napi);
        virtnet_napi_tx_disable(&vi.sq[i].napi);
    }

    return 0;
}
