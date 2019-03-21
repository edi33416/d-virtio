import core.stdc.config;
import virtio_h;
import mod_devicetable_h;
import napi_struct_h : napi_struct;
import spinlock_types_h;
import device_h;
import mutex_h;
import kobject_h : kobject;
import net_device_h;
import sk_buff_h : sk_buff;
import bpf_prog_h : bpf_prog;
import send_queue_h : send_queue, scatterlist, virtnet_sq_stats;
import page_h : dstruct_page = page;
import receive_queue_h : receive_queue, virtnet_rq_stats;
import control_buf_h : control_buf;
import virtnet_info_h : virtnet_info;
import cache_h : L1_CACHE_BYTES;
import std.algorithm.comparison : max;

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

//extern(C) dstruct_page *get_a_page(receive_queue *rq, gfp_t gfp_mask)
//{
    //dstruct_page *p = rq.pages;

    //if (p) {
        //rq.pages = cast(dstruct_page *)p.d_alias_private;
        //[> clear private here, it is used to chain pages <]
        //p.d_alias_private = 0;
    //} else
        //p = alloc_page(gfp_mask);
    //return p;
//}


extern(C) void netif_wake_subqueue(net_device *, ushort);

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
        netif_wake_subqueue(vi.dev, cast(ushort)vq2txq(vq));
}
