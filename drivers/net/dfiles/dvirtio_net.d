import core.stdc.config;
import virtio_h;
import mod_devicetable_h;
import napi_struct_h : napi_struct;
import spinlock_types_h;
import device_h;
import mutex_h;
import kobject_h : kobject;
import net_device_h;
import sk_buff_h : sk_buff, skb_shared_info;
import bpf_prog_h : bpf_prog;
import send_queue_h : send_queue, scatterlist, virtnet_sq_stats, MAX_SKB_FRAGS, PAGE_SIZE,
       u64_stats_sync;
import page_h : dstruct_page = page;
import receive_queue_h : receive_queue, virtnet_rq_stats, xdp_frame, xdp_buff, xdp_action,
       ewma_pkt_len;
import control_buf_h : control_buf;
import virtnet_info_h : virtnet_info;
import cache_h : L1_CACHE_BYTES;
import std.algorithm.comparison : max, min;
import core.stdc.string : memcpy, memset;
import gfp_h;

pragma(msg, "Sizeof napi_struct: ", napi_struct.sizeof);
pragma(msg, "Sizeof virtqueue: ", virtqueue.sizeof);
pragma(msg, "Sizeof virtio_device: ", virtio_device.sizeof);
pragma(msg, "Sizeof bool: ", bool.sizeof);
pragma(msg, "Sizeof spinlock_t:", spinlock_t.sizeof);
pragma(msg, "Sizeof device:", device.sizeof);
pragma(msg, "Sizeof virtio-device_id:", virtio_device_id.sizeof);
pragma(msg, "Sizeof mutex:", mutex.sizeof);
pragma(msg, "Sizeof kobject:", kobject.sizeof);
pragma(msg, "Sizeof dev_links_info :", dev_links_info.sizeof);
pragma(msg, "Sizeof dev_pm_info:", dev_pm_info.sizeof);
pragma(msg, "Sizeof dev_archdata:", dev_archdata.sizeof);
pragma(msg, "Sizeof klist_node:", klist_node.sizeof);
pragma(msg, "Sizeof net_device:", net_device.sizeof);
pragma(msg, "Sizeof netdev_tc_txq:", netdev_tc_txq.sizeof);
pragma(msg, "Sizeof possible_net_t:", possible_net_t.sizeof);
pragma(msg, "Sizeof netdev_hw_addr_list:", netdev_hw_addr_list.sizeof);
pragma(msg, "Sizeof atomic_t:", atomic_t.sizeof);
pragma(msg, "Sizeof atomic_long_t:", atomic_long_t.sizeof);
pragma(msg, "Sizeof timer_list:", timer_list.sizeof);
pragma(msg, "Sizeof net_device_stats:", net_device_stats.sizeof);
pragma(msg, "Sizeof sk_buff:", sk_buff.sizeof);
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
pragma(msg, "Sizeof bpf_prog:", bpf_prog.sizeof);
//pragma(msg, "Offsetof bpf_prog.tag:", bpf_prog.tag.offsetof);
//pragma(msg, "Offsetof bpf_prog.bpf_func:", bpf_prog.bpf_func.offsetof);
//pragma(msg, "Offsetof bpf_prog.insns:", bpf_prog.dummy_anon_union_i.offsetof);
//pragma(msg, "Offsetof bpf_prog.insnsi:", bpf_prog.dummy_anon_union_i.offsetof);
pragma(msg, "Sizeof send_queue:", send_queue.sizeof);
//pragma(msg, "Offsetof send_queue.name:", send_queue.name.offsetof);
//pragma(msg, "Offsetof send_queue.napi:", send_queue.napi.offsetof);
pragma(msg, "Sizeof page_struct:", dstruct_page.sizeof);
//pragma(msg, "Offsetof page_struct.private:", page.d_alias_private.offsetof);
//pragma(msg, "Offsetof page_struct.pmd_huge_pte:", page.pmd_huge_pte.offsetof);
pragma(msg, "Sizeof receive_queue:", receive_queue.sizeof);
//pragma(msg, "Offsetof receive_queue.vq:", receive_queue.vq.offsetof);
//pragma(msg, "Offsetof receive_queue.napi:", receive_queue.napi.offsetof);
//pragma(msg, "Offsetof receive_queue.xdp_prog:", receive_queue.xdp_prog.offsetof);
//pragma(msg, "Offsetof receive_queue.stats:", receive_queue.stats.offsetof);
//pragma(msg, "Offsetof receive_queue.pages:", receive_queue.pages.offsetof);
//pragma(msg, "Offsetof receive_queue.mrg_avg_pkt_len:", receive_queue.mrg_avg_pkt_len.offsetof);
//pragma(msg, "Offsetof receive_queue.alloc_frag:", receive_queue.alloc_frag.offsetof);
//pragma(msg, "Offsetof receive_queue.sq:", receive_queue.sg.offsetof);
//pragma(msg, "Offsetof receive_queue.xdp_rxq:", receive_queue.xdp_rxq.offsetof);
pragma(msg, "Sizeof scatterlist:", scatterlist.sizeof);
pragma(msg, "Sizeof control_buf:", control_buf.sizeof);
pragma(msg, "Sizeof virtnet_info:", virtnet_info.sizeof);
pragma(msg, "Sizeof virtnet_sq_stats:", virtnet_sq_stats.sizeof);
pragma(msg, "Offsetof virtnet_sq_stats.syncp:", virtnet_sq_stats.syncp.offsetof);
pragma(msg, "Sizeof virtnet_rq_stats:", virtnet_rq_stats.sizeof);
pragma(msg, "Offsetof virtnet_rq_stats.syncp:", virtnet_rq_stats.syncp.offsetof);
//pragma(msg, "Offsetof virtnet_info.rq:", virtnet_info.rq.offsetof);
//pragma(msg, "Offsetof virtnet_info.refill:", virtnet_info.refill.offsetof);
//pragma(msg, "Offsetof virtnet_info.failover:", virtnet_info.failover.offsetof);


alias gfp_t = uint;

pragma(inline, true) int bit_macro(int x) {
    return (1 << (x));
}

pragma(inline, true) size_t VIRTNET_SQ_STAT(string m)() {
    return mixin("virtnet_sq_stats." ~ m ~ ".offsetof");
}

pragma(inline, true) size_t VIRTNET_RQ_STAT(string m)() {
    return mixin("virtnet_rq_stats." ~ m ~ ".offsetof");
}

enum NAPI_POLL_WEIGHT = 64;

int napi_weight = NAPI_POLL_WEIGHT;
bool csum = true, gso = true, napi_tx;

enum ETH_HLEN = 14;    /* Total octets in header. */
enum VLAN_HLEN = 4; /* The additional bytes required by VLAN */
enum ETH_DATA_LEN = 1500;  /* Max. octets in payload */

enum GOOD_PACKET_LEN = (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN);
enum GOOD_COPY_LEN = 128;
enum NET_IP_ALIGN = 0;
enum NET_SKB_PAD = max(32, L1_CACHE_BYTES);

enum VIRTNET_RX_PAD = (NET_IP_ALIGN + NET_SKB_PAD);

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

const c_ulong[] guest_offloads = [
    VIRTIO_NET_F_GUEST_TSO4,
    VIRTIO_NET_F_GUEST_TSO6,
    VIRTIO_NET_F_GUEST_ECN,
    VIRTIO_NET_F_GUEST_UFO
];

struct virtnet_stat_desc {
    char[ETH_GSTRING_LEN] desc;
    size_t offset;
}

const virtnet_stat_desc[] virtnet_sq_stats_desc = [
    { desc:"packets", offset:VIRTNET_SQ_STAT!("packets") },
    { desc:"bytes", offset:VIRTNET_SQ_STAT!("bytes") },
    { desc:"xdp_tx", offset:VIRTNET_SQ_STAT!("xdp_tx") },
    { desc:"xdp_tx_drops", offset:VIRTNET_SQ_STAT!("xdp_tx_drops") },
    { desc:"kicks", offset:VIRTNET_SQ_STAT!("kicks") },
];

const virtnet_stat_desc[] virtnet_rq_stats_desc = [
    { desc:"packets", offset:VIRTNET_RQ_STAT!"packets" },
    { desc:"bytes", offset:VIRTNET_RQ_STAT!"bytes" },
    { desc:"drops", offset:VIRTNET_RQ_STAT!"drops" },
    { desc:"xdp_packets", offset:VIRTNET_RQ_STAT!"xdp_packets" },
    { desc:"xdp_tx", offset:VIRTNET_RQ_STAT!"xdp_tx" },
    { desc:"xdp_redirects", offset:VIRTNET_RQ_STAT!"xdp_redirects" },
    { desc:"xdp_drops", offset:VIRTNET_RQ_STAT!"xdp_drops" },
    { desc:"kicks", offset:VIRTNET_RQ_STAT!"kicks" },
];

pragma(inline, true) uint ARRAY_SIZE(string x)() {
    return mixin((x).sizeof / (*(x.ptr)).sizeof);
}

enum VIRTNET_SQ_STATS_LEN = ARRAY_SIZE!("virtnet_sq_stats_desc");
enum VIRTNET_RQ_STATS_LEN = ARRAY_SIZE!("virtnet_rq_stats_desc");

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

    if (p) {
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
