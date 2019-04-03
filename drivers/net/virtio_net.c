/* A network driver using virtio.
 *
 * Copyright 2007 Rusty Russell <rusty@rustcorp.com.au> IBM Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
//#define DEBUG
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/module.h>
#include <linux/virtio.h>
#include <linux/virtio_net.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <linux/scatterlist.h>
#include <linux/if_vlan.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/average.h>
#include <linux/filter.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <net/route.h>
#include <net/xdp.h>
#include <net/net_failover.h>


void abort(void);

// D Bindings



// Macros

inline void __dbind__cpu_relax(void) {
    cpu_relax();
}

inline void __dbind__print(void *p) {
    pr_info("my val: %u\n", *(unsigned int *)p);
}

inline unsigned int __dbind__ALIGN(unsigned int len, unsigned int L1) {
    return ALIGN(len, L1);
}

inline unsigned int __dbind__clamp_t(unsigned long len_read, uint buf_len, size_t diff) {
    return clamp_t(unsigned int, len_read, buf_len, diff);
}

inline struct page * __dbind__alloc_page(gfp_t gfp_mask, unsigned int order) {
    return alloc_pages(gfp_mask, 0);
}

inline void * __dbind__page_address(const struct page *page) {
    return page_address(page);
}

inline void __dbind__dev_kfree_skb(struct sk_buff *skb) {
    return consume_skb(skb);
}

inline unsigned int __dbind__smp_processor_id(void) {
    return smp_processor_id();
}

inline struct skb_shared_info * __dbind__skb_shinfo(const struct sk_buff *skb) {
    return (struct skb_shared_info *) skb_end_pointer(skb);
}

inline int __dbind__SKB_DATA_ALIGN(size_t x) {
    return SKB_DATA_ALIGN(x);
}


inline int __dbind__raw_smp_processor_id(void) {
    return raw_smp_processor_id();
}

inline void __dbind__print_bug(void) {
    pr_info("%s\n", "BUG, nasol, plm");
}

inline int __dbind__getIFF_UP(void) {
    return IFF_UP;
}

inline int __dbind__getIFF_PROMISC(void) {
    return IFF_PROMISC;
}

inline int __dbind__getIFF_ALLMULTI(void) {
    return IFF_ALLMULTI;
}

inline int __dbind__netdev_uc_count(struct net_device *dev) {
    return netdev_uc_count(dev);
}

inline int __dbind__netdev_mc_count(struct net_device *dev) {
    return netdev_mc_count(dev);
}

inline struct cpumask *__dbind__cpu_online_mask(void) {
    return &__cpu_online_mask;
}

// End Macros
// inceput

inline struct bpf_prog * __dbind__bpf_prog_add(struct bpf_prog *prog, int i) {
    return bpf_prog_add(prog, i);
}

inline long __must_check __dbind__PTR_ERR(const void *ptr)
{
	return PTR_ERR(ptr);
}

inline bool __must_check __dbind__IS_ERR(const void *ptr) {
    return IS_ERR(ptr);
}

inline void __dbind__bpf_prog_sub(struct bpf_prog *prog, int i)
{
    bpf_prog_sub(prog, i);
}

inline void __dbind__bpf_prog_put(struct bpf_prog *prog)
{
    bpf_prog_put(prog);
}

inline __virtio64 __dbind__cpu_to_virtio64(struct virtio_device *vdev, u64 val) {
    return cpu_to_virtio64(vdev, val);
}

inline void __dbind__virtio_device_ready(struct virtio_device *dev) {
    return virtio_device_ready(dev);
}

inline bool __dbind__netif_running(const struct net_device *dev) {
    return netif_running(dev);
}

inline void __dbind__netif_tx_unlock_bh(struct net_device *dev) {
    return netif_tx_unlock_bh(dev);
}

inline void __dbind__netif_tx_lock_bh(struct net_device *dev) {
    return netif_tx_lock_bh(dev);
}


inline u32 __dbind__virtio_cread32(struct virtio_device *vdev, unsigned int offset)
{
    return virtio_cread32(vdev, offset);
}

inline u8 __dbind__virtio_cread8(struct virtio_device *vdev, unsigned int offset) {
    return virtio_cread8(vdev, offset);
}

inline int __dbind__ethtool_validate_duplex(__u8 duplex) {
    return ethtool_validate_speed(duplex);
}

inline int __dbind__ethtool_validate_speed(__u32 speed) {
    return ethtool_validate_speed(speed);
}

inline int __dbind__bitmap_empty(const unsigned long *src, unsigned nbits) {
    return bitmap_empty(src, nbits);
}

inline void __dbind__bitmap_zero(unsigned long *dst, unsigned int nbits) {
    return bitmap_zero(dst, nbits);
}


inline void __dbind__get_online_cpus(void) {
    get_online_cpus();
}

inline void __dbind__put_online_cpus(void) { 
    put_online_cpus();
}

inline unsigned long * __dbind__cpumask_bits(struct cpumask *mask) {
    return cpumask_bits(mask);
}


inline const char *__dbind__virtio_bus_name(struct virtio_device *vdev) {
    return virtio_bus_name(vdev);
}

inline void __dbind__cpumask_clear(struct cpumask *dstp) {
    return cpumask_clear(dstp);
}

inline int __dbind__netif_set_xps_queue(struct net_device *dev,
					const unsigned long *mask,
					u16 index, bool is_rxqs_map) {
    return __netif_set_xps_queue(dev, mask, index, is_rxqs_map);
}


inline void __dbind__free_cpumask_var(cpumask_var_t mask) {
    free_cpumask_var(mask);
}

inline void __dbind__cpumask_set_cpu(unsigned int cpu, struct cpumask *dstp) {
    return cpumask_set_cpu(cpu, dstp);
}

inline unsigned int __dbind__cpumask_next_wrap(int n, const struct cpumask *mask,
					     int start, bool wrap) {
    return cpumask_next_wrap(n, mask, start, wrap);
}

inline unsigned int __dbind__cpumask_next(int n, const struct cpumask *srcp) {
    return cpumask_next(n, srcp);
}

inline int __dbind__num_online_cpus(void) {
    return num_online_cpus();
}

inline bool __dbind__zalloc_cpumask_var(cpumask_var_t *mask, gfp_t flags) {
    return zalloc_cpumask_var(mask, flags);
}

inline int __dbind__cpuhp_state_add_instance_nocalls(enum cpuhp_state state, struct hlist_node *node) {
    return cpuhp_state_add_instance_nocalls(state, node);
}

inline int __dbind__cpuhp_state_remove_instance_nocalls(enum cpuhp_state state,
						      struct hlist_node *node) {
    return cpuhp_state_remove_instance_nocalls(state, node);
}

inline int __dbind__virtqueue_set_affinity(struct virtqueue *vq,
        const struct cpumask *cpu_mask) {
    return virtqueue_set_affinity(vq, cpu_mask);
}


inline void *__dbind__kzalloc(size_t size, gfp_t flags) {
    return kzalloc(size, flags);
}


inline __virtio32 __dbind__cpu_to_virtio32(struct virtio_device *vdev, u32 val) {
    return cpu_to_virtio32(vdev, val);
}


inline __virtio16 __dbind__cpu_to_virtio16(struct virtio_device *vdev, u16 val) {
    return cpu_to_virtio16(vdev, val);
}

inline bool __dbind__u64_stats_fetch_retry_irq(const struct u64_stats_sync *syncp,
					     unsigned int start) {
    return u64_stats_fetch_retry_irq(syncp, start);
}

inline unsigned int __dbind__u64_stats_fetch_begin_irq(const struct u64_stats_sync *syncp) {
    return u64_stats_fetch_begin_irq(syncp);
}

inline void __dbind__kfree(void *p) {
    kfree(p);
}

inline void __dbind__virtio_cwrite8(struct virtio_device *vdev,
				  unsigned int offset, u8 val) {
    return virtio_cwrite8(vdev, offset, val);
}

inline void *__dbind__kmemdup(const void *src, size_t len, gfp_t gfp) {
    return kmemdup(src, len, gfp);
}

inline void __dbind__netif_start_subqueue(struct net_device *dev, u16 queue_index) {
    return netif_start_subqueue(dev, queue_index);
}

inline void __dbind__nf_reset(struct sk_buff *skb) {
    return nf_reset(skb);
}

inline void __dbind__skb_orphan(struct sk_buff *skb) {
    return skb_orphan(skb);
}

inline void __dbind__netif_stop_subqueue(struct net_device *dev, u16 queue_index) {
    return netif_stop_subqueue(dev, queue_index);
}

inline void __dbind__dev_kfree_skb_any(struct sk_buff *skb) {
    return dev_kfree_skb_any(skb);
}

inline bool __dbind__netif_xmit_stopped(const struct netdev_queue *nq) {
    return netif_xmit_stopped(nq);
}

inline void __dbind__skb_tx_timestamp(struct sk_buff *skb) {
    return skb_tx_timestamp(skb);
}

inline u16 __dbind__skb_get_queue_mapping(const struct sk_buff *skb) {
    return skb_get_queue_mapping(skb);
}

inline void *__dbind__skb_pull(struct sk_buff *skb, unsigned int len) {
    return __skb_pull(skb, len);
}

inline void *__dbind__skb_push(struct sk_buff *skb, unsigned int len) {
    return __skb_push(skb, len);
}

inline unsigned int __dbind__skb_headroom(const struct sk_buff *skb) {
    return skb_headroom(skb);
}

inline int __dbind__skb_header_cloned(const struct sk_buff *skb) {
    return skb_header_cloned(skb);
}

inline int __dbind__virtio_net_hdr_from_skb(const struct sk_buff *skb,
					  struct virtio_net_hdr *hdr,
					  bool little_endian,
					  bool has_data_valid,
					  int vlan_hlen) {
    return virtio_net_hdr_from_skb(skb, hdr, little_endian, has_data_valid, vlan_hlen);
}

inline void __dbind__netif_tx_lock(struct netdev_queue *nq, int smth) {
    return __netif_tx_lock(nq, smth);
}

inline void *__dbind__netdev_priv(const struct net_device *dev) {
    return netdev_priv(dev);
}

inline void __dbind__netif_tx_unlock(struct netdev_queue *txq) {
    return __netif_tx_unlock(txq);
}

inline bool __dbind__netif_tx_trylock(struct netdev_queue *txq) {
    return __netif_tx_trylock(txq);
}

inline void __dbind__dev_consume_skb_any(struct sk_buff *skb) {
    return dev_consume_skb_any(skb);
}

inline bool __dbind__schedule_delayed_work(struct delayed_work *dwork,
					 unsigned long delay)
{
	return schedule_delayed_work(dwork, delay);
}

inline void __dbind__local_bh_disable(void) {
    return local_bh_disable();
}

inline void __dbind__local_bh_enable(void) {
    return local_bh_enable();
}

inline void __dbind__napi_enable(struct napi_struct *n)
{
    return napi_enable(n);
}


void __assert (const char *__assertion, const char *__file, int __line)
{
    pr_info("%s %s:%d\n", "Out of bounds, lele", __file, __line);
    /*abort();*/
}

inline void __dbind__sg_set_buf(struct scatterlist *sg, const void *buf,
        unsigned int buflen) {
    return sg_set_buf(sg, buf, buflen);
}

inline void __dbind__set_ip_summed(struct sk_buff *skb, int value) {
    skb->ip_summed = value;
}

inline bool __dbind__virtio_is_little_endian(struct virtio_device *vdev)
{
    return virtio_is_little_endian(vdev);
}

inline u8 __dbind__get_xmit_more_bitfield(struct sk_buff *skb) {
    return skb->xmit_more;
}


inline int __dbind__virtio_net_hdr_to_skb(struct sk_buff *skb,
                    const struct virtio_net_hdr *hdr,
                    bool little_endian) {
    return virtio_net_hdr_to_skb(skb, hdr, little_endian);
}

inline bool __dbind__skb_can_coalesce(struct sk_buff *skb, int i,
        const struct page *page, int off) {
    return skb_can_coalesce(skb, i, page, off);
}


inline struct sk_buff *__dbind__alloc_skb(unsigned int size, gfp_t priority) {
    return alloc_skb(size, priority);
}

inline u16 __dbind__virtio16_to_cpu(struct virtio_device *vdev, __virtio16 val) {
    return virtio16_to_cpu(vdev, val);
}


__always_inline
void __dbind__read_once_size(const volatile void *p, void *res, int size) {
    return __read_once_size(p, res, size);
}


__always_inline u32 __dbind__bpf_prog_run_xdp(const struct bpf_prog *prog,
        struct xdp_buff *xdp) {
    return bpf_prog_run_xdp(prog, xdp);
}

inline struct xdp_frame *__dbind__convert_to_xdp_frame(struct xdp_buff *xdp) {
    return convert_to_xdp_frame(xdp);
}


__always_inline void __dbind__xdp_set_data_meta_invalid(struct xdp_buff *xdp) {
    return xdp_set_data_meta_invalid(xdp);
}

inline void __dbind__rcu_read_unlock(void) {
    return rcu_read_unlock();
}

inline void __dbind__skb_reserve(struct sk_buff *skb, int len) {
    return skb_reserve(skb, len);
}

inline void __dbind__rcu_read_lock(void) {
    return rcu_read_lock();
}

inline struct page *__dbind__virt_to_head_page(const void *x) {
    return virt_to_head_page(x);
}

inline void __dbind__u64_stats_update_end(struct u64_stats_sync *syncp) {
    return u64_stats_update_end(syncp);
}

inline void __dbind__u64_stats_update_begin(struct u64_stats_sync *syncp) {
    return u64_stats_update_begin(syncp);
}

inline void __dbind__put_page(struct page *page) {
    return put_page(page);
}

inline void * __dbind__skb_put_data(struct sk_buff *skb, const void *data,
        unsigned int len)
{
    return skb_put_data(skb, data, len);
}

inline struct sk_buff *__dbind__napi_alloc_skb(struct napi_struct *napi,
        unsigned int length) {
    return napi_alloc_skb(napi, length);
}

inline int __dbind__skb_tailroom(const struct sk_buff *skb)
{
    return skb_tailroom(skb);
}

inline void __dbind__netif_wake_subqueue(struct net_device *dev, u16 queue_index) {
    return netif_wake_subqueue(dev, queue_index);
}

inline bool __dbind__virtio_has_feature(const struct virtio_device *vdev,
        unsigned int fbit)
{
    return virtio_has_feature(vdev, fbit);
}

inline void __dbind__get_page(struct page *page) {
    return get_page(page);
}

inline struct netdev_queue * __dbind__netdev_get_tx_queue(const struct net_device *dev,
					 unsigned int index) {
    return netdev_get_tx_queue(dev, index);
}

// End of D Bindings

static int napi_weight = NAPI_POLL_WEIGHT;
module_param(napi_weight, int, 0444);

static bool csum = true, gso = true, napi_tx;
module_param(csum, bool, 0444);
module_param(gso, bool, 0444);
module_param(napi_tx, bool, 0644);

/* FIXME: MTU in config. */
#define GOOD_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define GOOD_COPY_LEN	128

#define VIRTNET_RX_PAD (NET_IP_ALIGN + NET_SKB_PAD)

/* Amount of XDP headroom to prepend to packets for use by xdp_adjust_head */
#define VIRTIO_XDP_HEADROOM 256

/* Separating two types of XDP xmit */
#define VIRTIO_XDP_TX		BIT(0)
#define VIRTIO_XDP_REDIR	BIT(1)

/* RX packet size EWMA. The average packet size is used to determine the packet
 * buffer size when refilling RX rings. As the entire RX ring may be refilled
 * at once, the weight is chosen so that the EWMA will be insensitive to short-
 * term, transient changes in packet size.
 */
DECLARE_EWMA(pkt_len, 0, 64)

inline void __dbind__ewma_pkt_len_add(struct ewma_pkt_len *e, unsigned long val) {
    ewma_pkt_len_add(e, val);
}

inline void __dbind__ewma_pkt_len_read(struct ewma_pkt_len *e) {
    ewma_pkt_len_read(e);
}

#define VIRTNET_DRIVER_VERSION "1.0.0"

static const unsigned long guest_offloads[] = {
	VIRTIO_NET_F_GUEST_TSO4,
	VIRTIO_NET_F_GUEST_TSO6,
	VIRTIO_NET_F_GUEST_ECN,
	VIRTIO_NET_F_GUEST_UFO
};

struct virtnet_stat_desc {
	char desc[ETH_GSTRING_LEN];
	size_t offset;
};

struct virtnet_sq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 xdp_tx;
	u64 xdp_tx_drops;
	u64 kicks;
};

struct virtnet_rq_stats {
	struct u64_stats_sync syncp;
	u64 packets;
	u64 bytes;
	u64 drops;
	u64 xdp_packets;
	u64 xdp_tx;
	u64 xdp_redirects;
	u64 xdp_drops;
	u64 kicks;
};

#define VIRTNET_SQ_STAT(m)	offsetof(struct virtnet_sq_stats, m)
#define VIRTNET_RQ_STAT(m)	offsetof(struct virtnet_rq_stats, m)

static const struct virtnet_stat_desc virtnet_sq_stats_desc[] = {
	{ "packets",		VIRTNET_SQ_STAT(packets) },
	{ "bytes",		VIRTNET_SQ_STAT(bytes) },
	{ "xdp_tx",		VIRTNET_SQ_STAT(xdp_tx) },
	{ "xdp_tx_drops",	VIRTNET_SQ_STAT(xdp_tx_drops) },
	{ "kicks",		VIRTNET_SQ_STAT(kicks) },
};

static const struct virtnet_stat_desc virtnet_rq_stats_desc[] = {
	{ "packets",		VIRTNET_RQ_STAT(packets) },
	{ "bytes",		VIRTNET_RQ_STAT(bytes) },
	{ "drops",		VIRTNET_RQ_STAT(drops) },
	{ "xdp_packets",	VIRTNET_RQ_STAT(xdp_packets) },
	{ "xdp_tx",		VIRTNET_RQ_STAT(xdp_tx) },
	{ "xdp_redirects",	VIRTNET_RQ_STAT(xdp_redirects) },
	{ "xdp_drops",		VIRTNET_RQ_STAT(xdp_drops) },
	{ "kicks",		VIRTNET_RQ_STAT(kicks) },
};

#define VIRTNET_SQ_STATS_LEN	ARRAY_SIZE(virtnet_sq_stats_desc)
#define VIRTNET_RQ_STATS_LEN	ARRAY_SIZE(virtnet_rq_stats_desc)

/* Internal representation of a send virtqueue */
struct send_queue {
	/* Virtqueue associated with this send _queue */
	struct virtqueue *vq;

	/* TX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Name of the send queue: output.$index */
	char name[40];

	struct virtnet_sq_stats stats;

	struct napi_struct napi;
};

/* Internal representation of a receive virtqueue */
struct receive_queue {
	/* Virtqueue associated with this receive_queue */
	struct virtqueue *vq;

	struct napi_struct napi;

	struct bpf_prog __rcu *xdp_prog;

	struct virtnet_rq_stats stats;

	/* Chain pages by the private ptr. */
	struct page *pages;

	/* Average packet length for mergeable receive buffers. */
	struct ewma_pkt_len mrg_avg_pkt_len;

	/* Page frag for packet buffer allocation. */
	struct page_frag alloc_frag;

	/* RX: fragments + linear part + virtio header */
	struct scatterlist sg[MAX_SKB_FRAGS + 2];

	/* Min single buffer size for mergeable buffers case. */
	unsigned int min_buf_len;

	/* Name of this receive queue: input.$index */
	char name[40];

	struct xdp_rxq_info xdp_rxq;
};

/* Control VQ buffers: protected by the rtnl lock */
struct control_buf {
	struct virtio_net_ctrl_hdr hdr;
	virtio_net_ctrl_ack status;
	struct virtio_net_ctrl_mq mq;
	u8 promisc;
	u8 allmulti;
	__virtio16 vid;
	__virtio64 offloads;
};

struct virtnet_info {
	struct virtio_device *vdev;
	struct virtqueue *cvq;
	struct net_device *dev;
	struct send_queue *sq;
	struct receive_queue *rq;
	unsigned int status;

	/* Max # of queue pairs supported by the device */
	u16 max_queue_pairs;

	/* # of queue pairs currently used by the driver */
	u16 curr_queue_pairs;

	/* # of XDP queue pairs currently used by the driver */
	u16 xdp_queue_pairs;

	/* I like... big packets and I cannot lie! */
	bool big_packets;

	/* Host will merge rx buffers for big packets (shake it! shake it!) */
	bool mergeable_rx_bufs;

	/* Has control virtqueue */
	bool has_cvq;

	/* Host can handle any s/g split between our header and packet data */
	bool any_header_sg;

	/* Packet virtio header size */
	u8 hdr_len;

	/* Work struct for refilling if we run low on memory. */
	struct delayed_work refill;

	/* Work struct for config space updates */
	struct work_struct config_work;

	/* Does the affinity hint is set for virtqueues? */
	bool affinity_hint_set;

	/* CPU hotplug instances for online & dead */
	struct hlist_node node;
	struct hlist_node node_dead;

	struct control_buf *ctrl;

	/* Ethtool settings */
	u8 duplex;
	u32 speed;

	unsigned long guest_offloads;

	/* failover when STANDBY feature enabled */
	struct failover *failover;
};

struct padded_vnet_hdr {
	struct virtio_net_hdr_mrg_rxbuf hdr;
	/*
	 * hdr is in a separate sg buffer, and data sg buffer shares same page
	 * with this header sg. This padding makes next sg 16 byte aligned
	 * after the header.
	 */
	char padding[4];
};

/* Converting between virtqueue no. and kernel tx/rx queue no.
 * 0:rx0 1:tx0 2:rx1 3:tx1 ... 2N:rxN 2N+1:txN 2N+2:cvq
 */
int vq2txq(struct virtqueue *vq);

int txq2vq(int txq);

int vq2rxq(struct virtqueue *vq);

int rxq2vq(int rxq);


struct virtio_net_hdr_mrg_rxbuf *skb_vnet_hdr(struct sk_buff *skb);


/*
 * private is used to chain pages for big packets, put the whole
 * most recent used list in the beginning for reuse
 */
void give_pages(struct receive_queue *rq, struct page *page);


struct page *get_a_page(struct receive_queue *rq, gfp_t gfp_mask);


void virtqueue_napi_schedule(struct napi_struct *napi, struct virtqueue *vq);


void virtqueue_napi_complete(struct napi_struct *napi, struct virtqueue *vq, int processed);


void skb_xmit_done(struct virtqueue *vq);


void *mergeable_len_to_ctx(unsigned int truesize, unsigned int headroom);


unsigned int mergeable_ctx_to_headroom(void *mrg_ctx);


unsigned int mergeable_ctx_to_truesize(void *mrg_ctx);


/* Called from bottom half context */
struct sk_buff *page_to_skb(struct virtnet_info *vi,
				   struct receive_queue *rq,
				   struct page *page, unsigned int offset,
				   unsigned int len, unsigned int truesize);


int __virtnet_xdp_xmit_one(struct virtnet_info *vi,
				   struct send_queue *sq,
				   struct xdp_frame *xdpf);


struct send_queue *virtnet_xdp_sq(struct virtnet_info *vi);


int virtnet_xdp_xmit(struct net_device *dev,
            int n, struct xdp_frame **frames, u32 flags);


unsigned int virtnet_get_headroom(struct virtnet_info *vi);

/* We copy the packet for XDP in the following cases:
 *
 * 1) Packet is scattered across multiple rx buffers.
 * 2) Headroom space is insufficient.
 *
 * This is inefficient but it's a temporary condition that
 * we hit right after XDP is enabled and until queue is refilled
 * with large buffers with sufficient headroom - so it should affect
 * at most queue size packets.
 * Afterwards, the conditions to enable
 * XDP should preclude the underlying device from sending packets
 * across multiple buffers (num_buf > 1), and we make sure buffers
 * have enough headroom.
 */
struct page *xdp_linearize_page(struct receive_queue *rq,
                    u16 *num_buf,
                    struct page *p,
                    int offset,
                    int page_off,
                    unsigned int *len);


struct sk_buff *receive_small(struct net_device *dev,
                     struct virtnet_info *vi,
                     struct receive_queue *rq,
                     void *buf, void *ctx,
                     unsigned int len,
                     unsigned int *xdp_xmit,
                     struct virtnet_rq_stats *stats);


struct sk_buff *receive_big(struct net_device *dev,
                   struct virtnet_info *vi,
                   struct receive_queue *rq,
                   void *buf,
                   unsigned int len,
                   struct virtnet_rq_stats *stats);


struct sk_buff *receive_mergeable(struct net_device *dev,
                     struct virtnet_info *vi,
                     struct receive_queue *rq,
                     void *buf,
                     void *ctx,
                     unsigned int len,
                     unsigned int *xdp_xmit,
                     struct virtnet_rq_stats *stats);


void receive_buf(struct virtnet_info *vi, struct receive_queue *rq,
            void *buf, unsigned int len, void **ctx,
            unsigned int *xdp_xmit,
            struct virtnet_rq_stats *stats);


/* Unlike mergeable buffers, all buffers are allocated to the
 * same size, except for the headroom. For this reason we do
 * not need to use  mergeable_len_to_ctx here - it is enough
 * to store the headroom as the context ignoring the truesize.
 */
int add_recvbuf_small(struct virtnet_info *vi, struct receive_queue *rq,
        gfp_t gfp);


int add_recvbuf_big(struct virtnet_info *vi, struct receive_queue *rq,
        gfp_t gfp);


unsigned int get_mergeable_buf_len(struct receive_queue *rq,
                      struct ewma_pkt_len *avg_pkt_len,
                      unsigned int room);


int add_recvbuf_mergeable(struct virtnet_info *vi,
        struct receive_queue *rq, gfp_t gfp);

/*
 * Returns false if we couldn't fill entirely (OOM).
 *
 * Normally run in the receive path, but can also be run from ndo_open
 * before we're receiving packets, or from refill_work which is
 * careful to disable receiving (using napi_disable).
 */

bool try_fill_recv(struct virtnet_info *vi, struct receive_queue *rq, gfp_t gfp);


void skb_recv_done(struct virtqueue *rvq);


void virtnet_napi_enable(struct virtqueue *vq, struct napi_struct *napi);


void virtnet_napi_tx_enable(struct virtnet_info *vi, struct virtqueue *vq,
           struct napi_struct *napi);


void virtnet_napi_tx_disable(struct napi_struct *napi);


void refill_work(struct work_struct *work);


int virtnet_receive(struct receive_queue *rq, int budget,
               unsigned int *xdp_xmit);


void free_old_xmit_skbs(struct send_queue *sq);


void virtnet_poll_cleantx(struct receive_queue *rq);


int virtnet_poll(struct napi_struct *napi, int budget);


int virtnet_open(struct net_device *dev);


int virtnet_poll_tx(struct napi_struct *napi, int budget);


int xmit_skb(struct send_queue *sq, struct sk_buff *skb);


netdev_tx_t start_xmit(struct sk_buff *skb, struct net_device *dev);

/*
 * Send command via the control virtqueue and check status.  Commands
 * supported by the hypervisor, as indicated by feature bits, should
 * never fail unless improperly formatted.
 */
bool virtnet_send_command(struct virtnet_info *vi, u8 class, u8 cmd,
        struct scatterlist *out);


int virtnet_set_mac_address(struct net_device *dev, void *p);


void virtnet_stats(struct net_device *dev, struct rtnl_link_stats64 *tot);


void virtnet_ack_link_announce(struct virtnet_info *vi);


int _virtnet_set_queues(struct virtnet_info *vi, u16 queue_pairs);


int virtnet_set_queues(struct virtnet_info *vi, u16 queue_pairs);


int virtnet_close(struct net_device *dev);


void virtnet_set_rx_mode(struct net_device *dev)
{
    struct virtnet_info *vi = netdev_priv(dev);
    struct scatterlist sg[2];
    struct virtio_net_ctrl_mac *mac_data;
    struct netdev_hw_addr *ha;
    int uc_count;
    int mc_count;
    void *buf;
    int i;

    if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_RX))
        return;

    vi->ctrl->promisc = ((dev->flags & IFF_PROMISC) != 0);
    vi->ctrl->allmulti = ((dev->flags & IFF_ALLMULTI) != 0);

    sg_init_one(sg, &vi->ctrl->promisc, sizeof(vi->ctrl->promisc));

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_RX,
                  VIRTIO_NET_CTRL_RX_PROMISC, sg))
        dev_warn(&dev->dev, "Failed to %sable promisc mode.\n",
             vi->ctrl->promisc ? "en" : "dis");

    sg_init_one(sg, &vi->ctrl->allmulti, sizeof(vi->ctrl->allmulti));

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_RX,
                  VIRTIO_NET_CTRL_RX_ALLMULTI, sg))
        dev_warn(&dev->dev, "Failed to %sable allmulti mode.\n",
             vi->ctrl->allmulti ? "en" : "dis");

    uc_count = netdev_uc_count(dev);
    mc_count = netdev_mc_count(dev);
    buf = kzalloc(((uc_count + mc_count) * ETH_ALEN) +
              (2 * sizeof(mac_data->entries)), GFP_ATOMIC);
    mac_data = buf;
    if (!buf)
        return;

    sg_init_table(sg, 2);

    mac_data->entries = cpu_to_virtio32(vi->vdev, uc_count);
    i = 0;
    netdev_for_each_uc_addr(ha, dev)
        memcpy(&mac_data->macs[i++][0], ha->addr, ETH_ALEN);

    sg_set_buf(&sg[0], mac_data,
           sizeof(mac_data->entries) + (uc_count * ETH_ALEN));

    mac_data = (void *)&mac_data->macs[uc_count][0];

    mac_data->entries = cpu_to_virtio32(vi->vdev, mc_count);
    i = 0;
    netdev_for_each_mc_addr(ha, dev)
        memcpy(&mac_data->macs[i++][0], ha->addr, ETH_ALEN);

    sg_set_buf(&sg[1], mac_data,
           sizeof(mac_data->entries) + (mc_count * ETH_ALEN));

    if (!virtnet_send_command(vi, VIRTIO_NET_CTRL_MAC,
                  VIRTIO_NET_CTRL_MAC_TABLE_SET, sg))
        dev_warn(&dev->dev, "Failed to set MAC filter table.\n");

    kfree(buf);
}

int virtnet_vlan_rx_add_vid(struct net_device *dev,
				   __be16 proto, u16 vid);


int virtnet_vlan_rx_kill_vid(struct net_device *dev,
				    __be16 proto, u16 vid);


void virtnet_clean_affinity(struct virtnet_info *vi, long hcpu);


void virtnet_set_affinity(struct virtnet_info *vi);


int virtnet_cpu_online(unsigned int cpu, struct hlist_node *node);


int virtnet_cpu_dead(unsigned int cpu, struct hlist_node *node);


int virtnet_cpu_down_prep(unsigned int cpu, struct hlist_node *node);


static enum cpuhp_state virtionet_online;

inline enum cpuhp_state __dbind__get_virtionet_online(void) {
    return virtionet_online;
}


int virtnet_cpu_notif_add(struct virtnet_info *vi);


void virtnet_cpu_notif_remove(struct virtnet_info *vi);


void virtnet_get_ringparam(struct net_device *dev, struct ethtool_ringparam *ring);


void virtnet_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info);


/* TODO: Eliminate OOO packets during switching */
int virtnet_set_channels(struct net_device *dev, struct ethtool_channels *channels);


void virtnet_get_strings(struct net_device *dev, u32 stringset, u8 *data);


int virtnet_get_sset_count(struct net_device *dev, int sset);


void virtnet_get_ethtool_stats(struct net_device *dev, struct ethtool_stats *stats, u64 *data);


void virtnet_get_channels(struct net_device *dev, struct ethtool_channels *channels);


/* Check if the user is trying to change anything besides speed/duplex */
bool virtnet_validate_ethtool_cmd(const struct ethtool_link_ksettings *cmd);


int virtnet_set_link_ksettings(struct net_device *dev, const struct ethtool_link_ksettings *cmd);


int virtnet_get_link_ksettings(struct net_device *dev, struct ethtool_link_ksettings *cmd);


void virtnet_init_settings(struct net_device *dev);


void virtnet_update_settings(struct virtnet_info *vi);


static const struct ethtool_ops virtnet_ethtool_ops = {
	.get_drvinfo = virtnet_get_drvinfo,
	.get_link = ethtool_op_get_link,
	.get_ringparam = virtnet_get_ringparam,
	.get_strings = virtnet_get_strings,
	.get_sset_count = virtnet_get_sset_count,
	.get_ethtool_stats = virtnet_get_ethtool_stats,
	.set_channels = virtnet_set_channels,
	.get_channels = virtnet_get_channels,
	.get_ts_info = ethtool_op_get_ts_info,
	.get_link_ksettings = virtnet_get_link_ksettings,
	.set_link_ksettings = virtnet_set_link_ksettings,
};

void virtnet_freeze_down(struct virtio_device *vdev);


int init_vqs(struct virtnet_info *vi);


int virtnet_restore_up(struct virtio_device *vdev);


int virtnet_set_guest_offloads(struct virtnet_info *vi, u64 offloads);


int virtnet_clear_guest_offloads(struct virtnet_info *vi);


int virtnet_restore_guest_offloads(struct virtnet_info *vi);


static int virtnet_xdp_set(struct net_device *dev, struct bpf_prog *prog,
			   struct netlink_ext_ack *extack)
{
	unsigned long int max_sz = PAGE_SIZE - sizeof(struct padded_vnet_hdr);
	struct virtnet_info *vi = netdev_priv(dev);
	struct bpf_prog *old_prog;
	u16 xdp_qp = 0, curr_qp;
	int i, err;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS)
	    && (virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_TSO4) ||
	        virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_TSO6) ||
	        virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_ECN) ||
		virtio_has_feature(vi->vdev, VIRTIO_NET_F_GUEST_UFO))) {
		NL_SET_ERR_MSG_MOD(extack, "Can't set XDP while host is implementing LRO, disable LRO first");
		return -EOPNOTSUPP;
	}

	if (vi->mergeable_rx_bufs && !vi->any_header_sg) {
		NL_SET_ERR_MSG_MOD(extack, "XDP expects header/data in single page, any_header_sg required");
		return -EINVAL;
	}

	if (dev->mtu > max_sz) {
		NL_SET_ERR_MSG_MOD(extack, "MTU too large to enable XDP");
		netdev_warn(dev, "XDP requires MTU less than %lu\n", max_sz);
		return -EINVAL;
	}

	curr_qp = vi->curr_queue_pairs - vi->xdp_queue_pairs;
	if (prog)
		xdp_qp = nr_cpu_ids;

	/* XDP requires extra queues for XDP_TX */
	if (curr_qp + xdp_qp > vi->max_queue_pairs) {
		NL_SET_ERR_MSG_MOD(extack, "Too few free TX rings available");
		netdev_warn(dev, "request %i queues but max is %i\n",
			    curr_qp + xdp_qp, vi->max_queue_pairs);
		return -ENOMEM;
	}

	if (prog) {
		prog = bpf_prog_add(prog, vi->max_queue_pairs - 1);
		if (IS_ERR(prog))
			return PTR_ERR(prog);
	}

	/* Make sure NAPI is not using any XDP TX queues for RX. */
	if (netif_running(dev))
		for (i = 0; i < vi->max_queue_pairs; i++)
			napi_disable(&vi->rq[i].napi);

	netif_set_real_num_rx_queues(dev, curr_qp + xdp_qp);
	err = _virtnet_set_queues(vi, curr_qp + xdp_qp);
	if (err)
		goto err;
	vi->xdp_queue_pairs = xdp_qp;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		old_prog = rtnl_dereference(vi->rq[i].xdp_prog);
		rcu_assign_pointer(vi->rq[i].xdp_prog, prog);
		if (i == 0) {
			if (!old_prog)
				virtnet_clear_guest_offloads(vi);
			if (!prog)
				virtnet_restore_guest_offloads(vi);
		}
		if (old_prog)
			bpf_prog_put(old_prog);
		if (netif_running(dev))
			virtnet_napi_enable(vi->rq[i].vq, &vi->rq[i].napi);
	}

	return 0;

err:
	for (i = 0; i < vi->max_queue_pairs; i++)
		virtnet_napi_enable(vi->rq[i].vq, &vi->rq[i].napi);
	if (prog)
		bpf_prog_sub(prog, vi->max_queue_pairs - 1);
	return err;
}

static u32 virtnet_xdp_query(struct net_device *dev)
{
	struct virtnet_info *vi = netdev_priv(dev);
	const struct bpf_prog *xdp_prog;
	int i;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		xdp_prog = rtnl_dereference(vi->rq[i].xdp_prog);
		if (xdp_prog)
			return xdp_prog->aux->id;
	}
	return 0;
}

static int virtnet_xdp(struct net_device *dev, struct netdev_bpf *xdp)
{
	switch (xdp->command) {
	case XDP_SETUP_PROG:
		return virtnet_xdp_set(dev, xdp->prog, xdp->extack);
	case XDP_QUERY_PROG:
		xdp->prog_id = virtnet_xdp_query(dev);
		return 0;
	default:
		return -EINVAL;
	}
}

static int virtnet_get_phys_port_name(struct net_device *dev, char *buf,
				      size_t len)
{
	struct virtnet_info *vi = netdev_priv(dev);
	int ret;

	if (!virtio_has_feature(vi->vdev, VIRTIO_NET_F_STANDBY))
		return -EOPNOTSUPP;

	ret = snprintf(buf, len, "sby");
	if (ret >= len)
		return -EOPNOTSUPP;

	return 0;
}

static const struct net_device_ops virtnet_netdev = {
	.ndo_open            = virtnet_open,
	.ndo_stop   	     = virtnet_close,
	.ndo_start_xmit      = start_xmit,
	.ndo_validate_addr   = eth_validate_addr,
	.ndo_set_mac_address = virtnet_set_mac_address,
	.ndo_set_rx_mode     = virtnet_set_rx_mode,
	.ndo_get_stats64     = virtnet_stats,
	.ndo_vlan_rx_add_vid = virtnet_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid = virtnet_vlan_rx_kill_vid,
	.ndo_bpf		= virtnet_xdp,
	.ndo_xdp_xmit		= virtnet_xdp_xmit,
	.ndo_features_check	= passthru_features_check,
	.ndo_get_phys_port_name	= virtnet_get_phys_port_name,
};

static void virtnet_config_changed_work(struct work_struct *work)
{
	struct virtnet_info *vi =
		container_of(work, struct virtnet_info, config_work);
	u16 v;

	if (virtio_cread_feature(vi->vdev, VIRTIO_NET_F_STATUS,
				 struct virtio_net_config, status, &v) < 0)
		return;

	if (v & VIRTIO_NET_S_ANNOUNCE) {
		netdev_notify_peers(vi->dev);
		virtnet_ack_link_announce(vi);
	}

	/* Ignore unknown (future) status bits */
	v &= VIRTIO_NET_S_LINK_UP;

	if (vi->status == v)
		return;

	vi->status = v;

	if (vi->status & VIRTIO_NET_S_LINK_UP) {
		virtnet_update_settings(vi);
		netif_carrier_on(vi->dev);
		netif_tx_wake_all_queues(vi->dev);
	} else {
		netif_carrier_off(vi->dev);
		netif_tx_stop_all_queues(vi->dev);
	}
}

static void virtnet_config_changed(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	schedule_work(&vi->config_work);
}

static void virtnet_free_queues(struct virtnet_info *vi)
{
	int i;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		napi_hash_del(&vi->rq[i].napi);
		netif_napi_del(&vi->rq[i].napi);
		netif_napi_del(&vi->sq[i].napi);
	}

	/* We called napi_hash_del() before netif_napi_del(),
	 * we need to respect an RCU grace period before freeing vi->rq
	 */
	synchronize_net();

	kfree(vi->rq);
	kfree(vi->sq);
	kfree(vi->ctrl);
}

static void _free_receive_bufs(struct virtnet_info *vi)
{
	struct bpf_prog *old_prog;
	int i;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		while (vi->rq[i].pages)
			__free_pages(get_a_page(&vi->rq[i], GFP_KERNEL), 0);

		old_prog = rtnl_dereference(vi->rq[i].xdp_prog);
		RCU_INIT_POINTER(vi->rq[i].xdp_prog, NULL);
		if (old_prog)
			bpf_prog_put(old_prog);
	}
}

static void free_receive_bufs(struct virtnet_info *vi)
{
	rtnl_lock();
	_free_receive_bufs(vi);
	rtnl_unlock();
}

static void free_receive_page_frags(struct virtnet_info *vi)
{
	int i;
	for (i = 0; i < vi->max_queue_pairs; i++)
		if (vi->rq[i].alloc_frag.page)
			put_page(vi->rq[i].alloc_frag.page);
}

static bool is_xdp_raw_buffer_queue(struct virtnet_info *vi, int q)
{
	if (q < (vi->curr_queue_pairs - vi->xdp_queue_pairs))
		return false;
	else if (q < vi->curr_queue_pairs)
		return true;
	else
		return false;
}

static void free_unused_bufs(struct virtnet_info *vi)
{
	void *buf;
	int i;

	for (i = 0; i < vi->max_queue_pairs; i++) {
		struct virtqueue *vq = vi->sq[i].vq;
		while ((buf = virtqueue_detach_unused_buf(vq)) != NULL) {
			if (!is_xdp_raw_buffer_queue(vi, i))
				dev_kfree_skb(buf);
			else
				put_page(virt_to_head_page(buf));
		}
	}

	for (i = 0; i < vi->max_queue_pairs; i++) {
		struct virtqueue *vq = vi->rq[i].vq;

		while ((buf = virtqueue_detach_unused_buf(vq)) != NULL) {
			if (vi->mergeable_rx_bufs) {
				put_page(virt_to_head_page(buf));
			} else if (vi->big_packets) {
				give_pages(&vi->rq[i], buf);
			} else {
				put_page(virt_to_head_page(buf));
			}
		}
	}
}

static void virtnet_del_vqs(struct virtnet_info *vi)
{
	struct virtio_device *vdev = vi->vdev;

	virtnet_clean_affinity(vi, -1);

	vdev->config->del_vqs(vdev);

	virtnet_free_queues(vi);
}

/* How large should a single buffer be so a queue full of these can fit at
 * least one full packet?
 * Logic below assumes the mergeable buffer header is used.
 */
static unsigned int mergeable_min_buf_len(struct virtnet_info *vi, struct virtqueue *vq)
{
	const unsigned int hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	unsigned int rq_size = virtqueue_get_vring_size(vq);
	unsigned int packet_len = vi->big_packets ? IP_MAX_MTU : vi->dev->max_mtu;
	unsigned int buf_len = hdr_len + ETH_HLEN + VLAN_HLEN + packet_len;
	unsigned int min_buf_len = DIV_ROUND_UP(buf_len, rq_size);

	return max(max(min_buf_len, hdr_len) - hdr_len,
		   (unsigned int)GOOD_PACKET_LEN);
}

static int virtnet_find_vqs(struct virtnet_info *vi)
{
	vq_callback_t **callbacks;
	struct virtqueue **vqs;
	int ret = -ENOMEM;
	int i, total_vqs;
	const char **names;
	bool *ctx;

	/* We expect 1 RX virtqueue followed by 1 TX virtqueue, followed by
	 * possible N-1 RX/TX queue pairs used in multiqueue mode, followed by
	 * possible control vq.
	 */
	total_vqs = vi->max_queue_pairs * 2 +
		    virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VQ);

	/* Allocate space for find_vqs parameters */
	vqs = kcalloc(total_vqs, sizeof(*vqs), GFP_KERNEL);
	if (!vqs)
		goto err_vq;
	callbacks = kmalloc_array(total_vqs, sizeof(*callbacks), GFP_KERNEL);
	if (!callbacks)
		goto err_callback;
	names = kmalloc_array(total_vqs, sizeof(*names), GFP_KERNEL);
	if (!names)
		goto err_names;
	if (!vi->big_packets || vi->mergeable_rx_bufs) {
		ctx = kcalloc(total_vqs, sizeof(*ctx), GFP_KERNEL);
		if (!ctx)
			goto err_ctx;
	} else {
		ctx = NULL;
	}

	/* Parameters for control virtqueue, if any */
	if (vi->has_cvq) {
		callbacks[total_vqs - 1] = NULL;
		names[total_vqs - 1] = "control";
	}

	/* Allocate/initialize parameters for send/receive virtqueues */
	for (i = 0; i < vi->max_queue_pairs; i++) {
		callbacks[rxq2vq(i)] = skb_recv_done;
		callbacks[txq2vq(i)] = skb_xmit_done;
		sprintf(vi->rq[i].name, "input.%d", i);
		sprintf(vi->sq[i].name, "output.%d", i);
		names[rxq2vq(i)] = vi->rq[i].name;
		names[txq2vq(i)] = vi->sq[i].name;
		if (ctx)
			ctx[rxq2vq(i)] = true;
	}

	ret = vi->vdev->config->find_vqs(vi->vdev, total_vqs, vqs, callbacks,
					 names, ctx, NULL);
	if (ret)
		goto err_find;

	if (vi->has_cvq) {
		vi->cvq = vqs[total_vqs - 1];
		if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_CTRL_VLAN))
			vi->dev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
	}

	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->rq[i].vq = vqs[rxq2vq(i)];
		vi->rq[i].min_buf_len = mergeable_min_buf_len(vi, vi->rq[i].vq);
		vi->sq[i].vq = vqs[txq2vq(i)];
	}

	/* run here: ret == 0. */


err_find:
	kfree(ctx);
err_ctx:
	kfree(names);
err_names:
	kfree(callbacks);
err_callback:
	kfree(vqs);
err_vq:
	return ret;
}

static int virtnet_alloc_queues(struct virtnet_info *vi)
{
	int i;

	vi->ctrl = kzalloc(sizeof(*vi->ctrl), GFP_KERNEL);
	if (!vi->ctrl)
		goto err_ctrl;
	vi->sq = kcalloc(vi->max_queue_pairs, sizeof(*vi->sq), GFP_KERNEL);
	if (!vi->sq)
		goto err_sq;
	vi->rq = kcalloc(vi->max_queue_pairs, sizeof(*vi->rq), GFP_KERNEL);
	if (!vi->rq)
		goto err_rq;

	INIT_DELAYED_WORK(&vi->refill, refill_work);
	for (i = 0; i < vi->max_queue_pairs; i++) {
		vi->rq[i].pages = NULL;
		netif_napi_add(vi->dev, &vi->rq[i].napi, virtnet_poll,
			       napi_weight);
		netif_tx_napi_add(vi->dev, &vi->sq[i].napi, virtnet_poll_tx,
				  napi_tx ? napi_weight : 0);

		sg_init_table(vi->rq[i].sg, ARRAY_SIZE(vi->rq[i].sg));
		ewma_pkt_len_init(&vi->rq[i].mrg_avg_pkt_len);
		sg_init_table(vi->sq[i].sg, ARRAY_SIZE(vi->sq[i].sg));

		u64_stats_init(&vi->rq[i].stats.syncp);
		u64_stats_init(&vi->sq[i].stats.syncp);
	}

	return 0;

err_rq:
	kfree(vi->sq);
err_sq:
	kfree(vi->ctrl);
err_ctrl:
	return -ENOMEM;
}

int init_vqs(struct virtnet_info *vi)
{
	int ret;

	/* Allocate send & receive queues */
	ret = virtnet_alloc_queues(vi);
	if (ret)
		goto err;

	ret = virtnet_find_vqs(vi);
	if (ret)
		goto err_free;

	get_online_cpus();
	virtnet_set_affinity(vi);
	put_online_cpus();

	return 0;

err_free:
	virtnet_free_queues(vi);
err:
	return ret;
}

#ifdef CONFIG_SYSFS
static ssize_t mergeable_rx_buffer_size_show(struct netdev_rx_queue *queue,
		char *buf)
{
	struct virtnet_info *vi = netdev_priv(queue->dev);
	unsigned int queue_index = get_netdev_rx_queue_index(queue);
	unsigned int headroom = virtnet_get_headroom(vi);
	unsigned int tailroom = headroom ? sizeof(struct skb_shared_info) : 0;
	struct ewma_pkt_len *avg;

	BUG_ON(queue_index >= vi->max_queue_pairs);
	avg = &vi->rq[queue_index].mrg_avg_pkt_len;
	return sprintf(buf, "%u\n",
		       get_mergeable_buf_len(&vi->rq[queue_index], avg,
				       SKB_DATA_ALIGN(headroom + tailroom)));
}

static struct rx_queue_attribute mergeable_rx_buffer_size_attribute =
	__ATTR_RO(mergeable_rx_buffer_size);

static struct attribute *virtio_net_mrg_rx_attrs[] = {
	&mergeable_rx_buffer_size_attribute.attr,
	NULL
};

static const struct attribute_group virtio_net_mrg_rx_group = {
	.name = "virtio_net",
	.attrs = virtio_net_mrg_rx_attrs
};
#endif

bool virtnet_fail_on_feature(struct virtio_device *vdev,
				    unsigned int fbit,
				    const char *fname, const char *dname);


#define VIRTNET_FAIL_ON(vdev, fbit, dbit)			\
	virtnet_fail_on_feature(vdev, fbit, #fbit, dbit)

static bool virtnet_validate_features(struct virtio_device *vdev)
{
	if (!virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ) &&
	    (VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_CTRL_RX,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_CTRL_VLAN,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_GUEST_ANNOUNCE,
			     "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_MQ, "VIRTIO_NET_F_CTRL_VQ") ||
	     VIRTNET_FAIL_ON(vdev, VIRTIO_NET_F_CTRL_MAC_ADDR,
			     "VIRTIO_NET_F_CTRL_VQ"))) {
		return false;
	}

	return true;
}

#define MIN_MTU ETH_MIN_MTU
#define MAX_MTU ETH_MAX_MTU

static int virtnet_validate(struct virtio_device *vdev)
{
	if (!vdev->config->get) {
		dev_err(&vdev->dev, "%s failure: config access disabled\n",
			__func__);
		return -EINVAL;
	}

	if (!virtnet_validate_features(vdev))
		return -EINVAL;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MTU)) {
		int mtu = virtio_cread16(vdev,
					 offsetof(struct virtio_net_config,
						  mtu));
		if (mtu < MIN_MTU)
			__virtio_clear_bit(vdev, VIRTIO_NET_F_MTU);
	}

	return 0;
}

static int virtnet_probe(struct virtio_device *vdev)
{
	int i, err = -ENOMEM;
	struct net_device *dev;
	struct virtnet_info *vi;
	u16 max_queue_pairs;
	int mtu;

	/* Find if host supports multiqueue virtio_net device */
	err = virtio_cread_feature(vdev, VIRTIO_NET_F_MQ,
				   struct virtio_net_config,
				   max_virtqueue_pairs, &max_queue_pairs);

	/* We need at least 2 queue's */
	if (err || max_queue_pairs < VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MIN ||
	    max_queue_pairs > VIRTIO_NET_CTRL_MQ_VQ_PAIRS_MAX ||
	    !virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
		max_queue_pairs = 1;

	/* Allocate ourselves a network device with room for our info */
	dev = alloc_etherdev_mq(sizeof(struct virtnet_info), max_queue_pairs);
	if (!dev)
		return -ENOMEM;

	/* Set up network device as normal. */
	dev->priv_flags |= IFF_UNICAST_FLT | IFF_LIVE_ADDR_CHANGE;
	dev->netdev_ops = &virtnet_netdev;
	dev->features = NETIF_F_HIGHDMA;

	dev->ethtool_ops = &virtnet_ethtool_ops;
	SET_NETDEV_DEV(dev, &vdev->dev);

	/* Do we support "hardware" checksums? */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_CSUM)) {
		/* This opens up the world of extra features. */
		dev->hw_features |= NETIF_F_HW_CSUM | NETIF_F_SG;
		if (csum)
			dev->features |= NETIF_F_HW_CSUM | NETIF_F_SG;

		if (virtio_has_feature(vdev, VIRTIO_NET_F_GSO)) {
			dev->hw_features |= NETIF_F_TSO
				| NETIF_F_TSO_ECN | NETIF_F_TSO6;
		}
		/* Individual feature bits: what can host handle? */
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO4))
			dev->hw_features |= NETIF_F_TSO;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_TSO6))
			dev->hw_features |= NETIF_F_TSO6;
		if (virtio_has_feature(vdev, VIRTIO_NET_F_HOST_ECN))
			dev->hw_features |= NETIF_F_TSO_ECN;

		dev->features |= NETIF_F_GSO_ROBUST;

		if (gso)
			dev->features |= dev->hw_features & NETIF_F_ALL_TSO;
		/* (!csum && gso) case will be fixed by register_netdev() */
	}
	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_CSUM))
		dev->features |= NETIF_F_RXCSUM;

	dev->vlan_features = dev->features;

	/* MTU range: 68 - 65535 */
	dev->min_mtu = MIN_MTU;
	dev->max_mtu = MAX_MTU;

	/* Configuration may specify what MAC to use.  Otherwise random. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_MAC))
		virtio_cread_bytes(vdev,
				   offsetof(struct virtio_net_config, mac),
				   dev->dev_addr, dev->addr_len);
	else
		eth_hw_addr_random(dev);

	/* Set up our device-specific information */
	vi = netdev_priv(dev);
	vi->dev = dev;
	vi->vdev = vdev;
	vdev->priv = vi;

	INIT_WORK(&vi->config_work, virtnet_config_changed_work);

	/* If we can receive ANY GSO packets, we must allocate large ones. */
	if (virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO4) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_TSO6) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_ECN) ||
	    virtio_has_feature(vdev, VIRTIO_NET_F_GUEST_UFO))
		vi->big_packets = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF))
		vi->mergeable_rx_bufs = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MRG_RXBUF) ||
	    virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		vi->hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		vi->hdr_len = sizeof(struct virtio_net_hdr);

	if (virtio_has_feature(vdev, VIRTIO_F_ANY_LAYOUT) ||
	    virtio_has_feature(vdev, VIRTIO_F_VERSION_1))
		vi->any_header_sg = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_CTRL_VQ))
		vi->has_cvq = true;

	if (virtio_has_feature(vdev, VIRTIO_NET_F_MTU)) {
		mtu = virtio_cread16(vdev,
				     offsetof(struct virtio_net_config,
					      mtu));
		if (mtu < dev->min_mtu) {
			/* Should never trigger: MTU was previously validated
			 * in virtnet_validate.
			 */
			dev_err(&vdev->dev, "device MTU appears to have changed "
				"it is now %d < %d", mtu, dev->min_mtu);
			goto free;
		}

		dev->mtu = mtu;
		dev->max_mtu = mtu;

		/* TODO: size buffers correctly in this case. */
		if (dev->mtu > ETH_DATA_LEN)
			vi->big_packets = true;
	}

	if (vi->any_header_sg)
		dev->needed_headroom = vi->hdr_len;

	/* Enable multiqueue by default */
	if (num_online_cpus() >= max_queue_pairs)
		vi->curr_queue_pairs = max_queue_pairs;
	else
		vi->curr_queue_pairs = num_online_cpus();
	vi->max_queue_pairs = max_queue_pairs;

	/* Allocate/initialize the rx/tx queues, and invoke find_vqs */
	err = init_vqs(vi);
	if (err)
		goto free;

#ifdef CONFIG_SYSFS
	if (vi->mergeable_rx_bufs)
		dev->sysfs_rx_queue_group = &virtio_net_mrg_rx_group;
#endif
	netif_set_real_num_tx_queues(dev, vi->curr_queue_pairs);
	netif_set_real_num_rx_queues(dev, vi->curr_queue_pairs);

	virtnet_init_settings(dev);

	if (virtio_has_feature(vdev, VIRTIO_NET_F_STANDBY)) {
		vi->failover = net_failover_create(vi->dev);
		if (IS_ERR(vi->failover)) {
			err = PTR_ERR(vi->failover);
			goto free_vqs;
		}
	}

	err = register_netdev(dev);
	if (err) {
		pr_debug("virtio_net: registering device failed\n");
		goto free_failover;
	}

	virtio_device_ready(vdev);

	err = virtnet_cpu_notif_add(vi);
	if (err) {
		pr_debug("virtio_net: registering cpu notifier failed\n");
		goto free_unregister_netdev;
	}

	virtnet_set_queues(vi, vi->curr_queue_pairs);

	/* Assume link up if device can't report link status,
	   otherwise get link status from config. */
	netif_carrier_off(dev);
	if (virtio_has_feature(vi->vdev, VIRTIO_NET_F_STATUS)) {
		schedule_work(&vi->config_work);
	} else {
		vi->status = VIRTIO_NET_S_LINK_UP;
		virtnet_update_settings(vi);
		netif_carrier_on(dev);
	}

	for (i = 0; i < ARRAY_SIZE(guest_offloads); i++)
		if (virtio_has_feature(vi->vdev, guest_offloads[i]))
			set_bit(guest_offloads[i], &vi->guest_offloads);

	pr_debug("virtnet: registered device %s with %d RX and TX vq's\n",
		 dev->name, max_queue_pairs);

	return 0;

free_unregister_netdev:
	vi->vdev->config->reset(vdev);

	unregister_netdev(dev);
free_failover:
	net_failover_destroy(vi->failover);
free_vqs:
	cancel_delayed_work_sync(&vi->refill);
	free_receive_page_frags(vi);
	virtnet_del_vqs(vi);
free:
	free_netdev(dev);
	return err;
}

static void remove_vq_common(struct virtnet_info *vi)
{
	vi->vdev->config->reset(vi->vdev);

	/* Free unused buffers in both send and recv, if any. */
	free_unused_bufs(vi);

	free_receive_bufs(vi);

	free_receive_page_frags(vi);

	virtnet_del_vqs(vi);
}

static void virtnet_remove(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	virtnet_cpu_notif_remove(vi);

	/* Make sure no work handler is accessing the device. */
	flush_work(&vi->config_work);

	unregister_netdev(vi->dev);

	net_failover_destroy(vi->failover);

	remove_vq_common(vi);

	free_netdev(vi->dev);
}

static __maybe_unused int virtnet_freeze(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;

	virtnet_cpu_notif_remove(vi);
	virtnet_freeze_down(vdev);
	remove_vq_common(vi);

	return 0;
}

static __maybe_unused int virtnet_restore(struct virtio_device *vdev)
{
	struct virtnet_info *vi = vdev->priv;
	int err;

	err = virtnet_restore_up(vdev);
	if (err)
		return err;
	virtnet_set_queues(vi, vi->curr_queue_pairs);

	err = virtnet_cpu_notif_add(vi);
	if (err)
		return err;

	return 0;
}

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_NET, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

#define VIRTNET_FEATURES \
	VIRTIO_NET_F_CSUM, VIRTIO_NET_F_GUEST_CSUM, \
	VIRTIO_NET_F_MAC, \
	VIRTIO_NET_F_HOST_TSO4, VIRTIO_NET_F_HOST_UFO, VIRTIO_NET_F_HOST_TSO6, \
	VIRTIO_NET_F_HOST_ECN, VIRTIO_NET_F_GUEST_TSO4, VIRTIO_NET_F_GUEST_TSO6, \
	VIRTIO_NET_F_GUEST_ECN, VIRTIO_NET_F_GUEST_UFO, \
	VIRTIO_NET_F_MRG_RXBUF, VIRTIO_NET_F_STATUS, VIRTIO_NET_F_CTRL_VQ, \
	VIRTIO_NET_F_CTRL_RX, VIRTIO_NET_F_CTRL_VLAN, \
	VIRTIO_NET_F_GUEST_ANNOUNCE, VIRTIO_NET_F_MQ, \
	VIRTIO_NET_F_CTRL_MAC_ADDR, \
	VIRTIO_NET_F_MTU, VIRTIO_NET_F_CTRL_GUEST_OFFLOADS, \
	VIRTIO_NET_F_SPEED_DUPLEX, VIRTIO_NET_F_STANDBY

static unsigned int features[] = {
	VIRTNET_FEATURES,
};

static unsigned int features_legacy[] = {
	VIRTNET_FEATURES,
	VIRTIO_NET_F_GSO,
	VIRTIO_F_ANY_LAYOUT,
};

static struct virtio_driver virtio_net_driver = {
	.feature_table = features,
	.feature_table_size = ARRAY_SIZE(features),
	.feature_table_legacy = features_legacy,
	.feature_table_size_legacy = ARRAY_SIZE(features_legacy),
	.driver.name =	KBUILD_MODNAME,
	.driver.owner =	THIS_MODULE,
	.id_table =	id_table,
	.validate =	virtnet_validate,
	.probe =	virtnet_probe,
	.remove =	virtnet_remove,
	.config_changed = virtnet_config_changed,
#ifdef CONFIG_PM_SLEEP
	.freeze =	virtnet_freeze,
	.restore =	virtnet_restore,
#endif
};

static __init int virtio_net_driver_init(void)
{
	int ret;
    /*pr_info("stat_desc sizeof: %d", sizeof(struct virtnet_stat_desc));*/
    /*pr_info("rq vect sizeof: %d", sizeof(virtnet_rq_stats_desc));*/
    /*pr_info("sq vect sizeof: %d", sizeof(virtnet_sq_stats_desc));*/

    pr_info("sizeof ethtool_link_settings: %ld\n", sizeof(struct ethtool_link_settings));
    pr_info("sizeof ethtool_link_ksettings: %ld\n", sizeof(struct ethtool_link_ksettings));
    pr_info("kbuild name: %s\n", KBUILD_MODNAME);
    pr_info("virtio_net_ctrl_hdr: %ld\n", sizeof(struct virtio_net_ctrl_hdr));
    pr_info("HZ: %d\n", HZ);
    pr_info("Sizeof napi_struct: %ld\n", sizeof(struct napi_struct));
    pr_info("Sizeof virtio_device: %ld\n", sizeof(struct virtio_device));
    pr_info("Sizeof bool: %ld\n", sizeof(bool));
    pr_info("Sizeof spinlock_t: %ld\n", sizeof(spinlock_t));
    pr_info("Sizeof device: %ld\n", sizeof(struct device));
    pr_info("Sizeof virtio-device_id: %ld\n", sizeof(struct virtio_device_id));
    pr_info("Sizeof mutex: %ld\n", sizeof(struct mutex));
    pr_info("Sizeof kobject: %ld\n", sizeof(struct kobject));
    pr_info("Sizeof dev_links_info : %ld\n", sizeof(struct dev_links_info));
    pr_info("Sizeof dev_pm_info : %ld\n", sizeof(struct dev_pm_info));
    pr_info("Sizeof dev_archdata : %ld\n", sizeof(struct dev_archdata));
    pr_info("Sizeof klist_node : %ld\n", sizeof(struct klist_node));
    pr_info("Sizeof net_device : %ld\n", sizeof(struct net_device));
    pr_info("Sizeof netdev_tc_txq:%ld\n", sizeof(struct netdev_tc_txq));
    pr_info("Sizeof possible_net_t:%ld\n", sizeof(possible_net_t));
    pr_info("Sizeof netdev_hw_addr_list:%ld\n", sizeof(struct netdev_hw_addr_list));
    pr_info("Sizeof atomic_t:%ld\n", sizeof(atomic_t));
    pr_info("Sizeof atomic_long_t:%ld\n", sizeof(atomic_long_t));
    pr_info("Sizeof timer_list:%ld\n", sizeof(struct timer_list));
    pr_info("Sizeof net_device_stats:%ld\n", sizeof(struct net_device_stats));
    pr_info("Sizeof sock_filter:%ld\n", sizeof(struct sock_filter));
    pr_info("Sizeof bpf_insn:%ld\n", sizeof(struct bpf_insn));
    pr_info("Sizeof sk_buff:%ld\n", sizeof(struct sk_buff));
    /*pr_info("offset sk_buff.csum:%ld\n", offsetof(struct sk_buff, csum));*/
    /*pr_info("offset sk_buff.queue_mapping:%ld\n", offsetof(struct sk_buff, queue_mapping));*/
    /*pr_info("offset sk_buff.headers_start:%ld\n", offsetof(struct sk_buff, headers_start));*/
    /*pr_info("offset sk_buff.cb:%ld\n", offsetof(struct sk_buff, cb));*/
    /*pr_info("offset sk_buff.tcp_tsorted_anchor:%ld\n", offsetof(struct sk_buff, tcp_tsorted_anchor));*/
    /*pr_info("offset sk_buff.len:%ld\n", offsetof(struct sk_buff, len));*/
    /*pr_info("offset sk_buff.data_len:%ld\n", offsetof(struct sk_buff, data_len));*/
    /*pr_info("offset sk_buff.mac_len:%ld\n", offsetof(struct sk_buff, mac_len));*/
    /*pr_info("offset sk_buff.hdr_len:%ld\n", offsetof(struct sk_buff, hdr_len));*/
    /*pr_info("offset sk_buff.priority:%ld\n", offsetof(struct sk_buff, priority));*/
    /*pr_info("offset sk_buff.mac_header:%ld\n", offsetof(struct sk_buff, mac_header));*/
    /*pr_info("offset sk_buff.mac_header:%ld\n", offsetof(struct sk_buff, mac_header));*/
    pr_info("Sizeof bpf_prog:%ld\n", sizeof(struct bpf_prog));
    /*pr_info("offset bpf_prog.tag:%ld\n", offsetof(struct bpf_prog, tag));*/
    /*pr_info("offset bpf_prog.bpf_func:%ld\n", offsetof(struct bpf_prog, bpf_func));*/
    /*pr_info("offset bpf_prog.insns:%ld\n", offsetof(struct bpf_prog, insns));*/
    /*pr_info("offset bpf_prog.insnsi:%ld\n", offsetof(struct bpf_prog, insnsi));*/
    pr_info("Sizeof send_queue:%ld\n", sizeof(struct send_queue));
    /*pr_info("offset send_queue.name:%ld\n", offsetof(struct send_queue, name));*/
    /*pr_info("offset send_queue.napi:%ld\n", offsetof(struct send_queue, napi));*/
    pr_info("Sizeof page_struct:%ld\n", sizeof(struct page));
    /*pr_info("offset page_struct.private:%ld\n", offsetof(struct page, private));*/
    /*pr_info("offset page_struct.pmd_huge_pte:%ld\n", offsetof(struct page, pmd_huge_pte));*/
    pr_info("Sizeof receive_queue:%ld\n", sizeof(struct receive_queue));
    /*pr_info("offset receive_queue.vq:%ld\n", offsetof(struct receive_queue, vq));*/
    /*pr_info("offset receive_queue.napi:%ld\n", offsetof(struct receive_queue, napi));*/
    /*pr_info("offset receive_queue.xdp_prog:%ld\n", offsetof(struct receive_queue, xdp_prog));*/
    /*pr_info("offset receive_queue.stats:%ld\n", offsetof(struct receive_queue, stats));*/
    /*pr_info("offset receive_queue.pages:%ld\n", offsetof(struct receive_queue, pages));*/
    /*pr_info("offset receive_queue.mrg_avg_pkt_len:%ld\n", offsetof(struct receive_queue, mrg_avg_pkt_len));*/
    /*pr_info("offset receive_queue.alloc_frag:%ld\n", offsetof(struct receive_queue, alloc_frag));*/
    /*pr_info("offset receive_queue.sg:%ld\n", offsetof(struct receive_queue, sg));*/
    /*pr_info("offset receive_queue.xdp_rxq:%ld\n", offsetof(struct receive_queue, xdp_rxq));*/
    pr_info("Sizeof scatterlist:%ld\n", sizeof(struct scatterlist));
    pr_info("Sizeof control_buf:%ld\n", sizeof(struct control_buf));
    pr_info("Sizeof virtnet_info:%ld\n", sizeof(struct virtnet_info));
    pr_info("Sizeof virtnet_sq_stats:%ld\n", sizeof(struct virtnet_sq_stats));
    pr_info("Sizeof virtnet_rq_stats:%ld\n", sizeof(struct virtnet_rq_stats));
    pr_info("offset virtnet_sq_stats.syncp:%ld\n", offsetof(struct virtnet_sq_stats, syncp));
    pr_info("offset virtnet_rq_stats.syncp:%ld\n", offsetof(struct virtnet_rq_stats, syncp));
    /*pr_info("offset virnet_info.rq:%ld\n", offsetof(struct virtnet_info, rq));*/
    /*pr_info("offset virnet_info.refill:%ld\n", offsetof(struct virtnet_info, refill));*/
    /*pr_info("offset virnet_info.failover:%ld\n", offsetof(struct virtnet_info, failover));*/

	ret = cpuhp_setup_state_multi(CPUHP_AP_ONLINE_DYN, "virtio/net:online",
				      virtnet_cpu_online,
				      virtnet_cpu_down_prep);
	if (ret < 0)
		goto out;
	virtionet_online = ret;
	ret = cpuhp_setup_state_multi(CPUHP_VIRT_NET_DEAD, "virtio/net:dead",
				      NULL, virtnet_cpu_dead);
	if (ret)
		goto err_dead;

        ret = register_virtio_driver(&virtio_net_driver);
	if (ret)
		goto err_virtio;
	return 0;
err_virtio:
	cpuhp_remove_multi_state(CPUHP_VIRT_NET_DEAD);
err_dead:
	cpuhp_remove_multi_state(virtionet_online);
out:
	return ret;
}
module_init(virtio_net_driver_init);

static __exit void virtio_net_driver_exit(void)
{
	unregister_virtio_driver(&virtio_net_driver);
	cpuhp_remove_multi_state(CPUHP_VIRT_NET_DEAD);
	cpuhp_remove_multi_state(virtionet_online);
}
module_exit(virtio_net_driver_exit);

MODULE_DEVICE_TABLE(virtio, id_table);
MODULE_DESCRIPTION("Virtio network driver");
MODULE_LICENSE("GPL");
