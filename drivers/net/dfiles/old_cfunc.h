
void give_pages(struct receive_queue *rq, struct page *page);

struct page *get_a_page(struct receive_queue *rq, gfp_t gfp_mask);

void virtqueue_napi_schedule(struct napi_struct *napi, struct virtqueue *vq);

void virtqueue_napi_complete(struct napi_struct *napi, struct virtqueue *vq, int processed);

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

void virtnet_napi_enable(struct virtqueue *vq, struct napi_struct *napi);


void virtnet_napi_tx_enable(struct virtnet_info *vi, struct virtqueue *vq,
           struct napi_struct *napi);


void virtnet_napi_tx_disable(struct napi_struct *napi);

int virtnet_receive(struct receive_queue *rq, int budget,
               unsigned int *xdp_xmit);


void free_old_xmit_skbs(struct send_queue *sq);


void virtnet_poll_cleantx(struct receive_queue *rq);

int xmit_skb(struct send_queue *sq, struct sk_buff *skb);

bool virtnet_send_command(struct virtnet_info *vi, u8 class, u8 cmd,
        struct scatterlist *out);

void virtnet_ack_link_announce(struct virtnet_info *vi);


int _virtnet_set_queues(struct virtnet_info *vi, u16 queue_pairs);


int virtnet_set_queues(struct virtnet_info *vi, u16 queue_pairs);

void virtnet_clean_affinity(struct virtnet_info *vi, long hcpu);

void virtnet_set_affinity(struct virtnet_info *vi);

int virtnet_cpu_notif_add(struct virtnet_info *vi);

void virtnet_cpu_notif_remove(struct virtnet_info *vi);

/* Check if the user is trying to change anything besides speed/duplex */
bool virtnet_validate_ethtool_cmd(const struct ethtool_link_ksettings *cmd);

void virtnet_init_settings(struct net_device *dev);

void virtnet_update_settings(struct virtnet_info *vi);

void virtnet_freeze_down(struct virtio_device *vdev);


int virtnet_restore_up(struct virtio_device *vdev);


int virtnet_set_guest_offloads(struct virtnet_info *vi, u64 offloads);


int virtnet_clear_guest_offloads(struct virtnet_info *vi);


int virtnet_restore_guest_offloads(struct virtnet_info *vi);


int virtnet_xdp_set(struct net_device *dev, struct bpf_prog *prog,
			   struct netlink_ext_ack *extack);


u32 virtnet_xdp_query(struct net_device *dev);

void virtnet_free_queues(struct virtnet_info *vi);


void _free_receive_bufs(struct virtnet_info *vi);


void free_receive_bufs(struct virtnet_info *vi);


void free_receive_page_frags(struct virtnet_info *vi);


bool is_xdp_raw_buffer_queue(struct virtnet_info *vi, int q);


void free_unused_bufs(struct virtnet_info *vi);


void virtnet_del_vqs(struct virtnet_info *vi);


/* How large should a single buffer be so a queue full of these can fit at
 * least one full packet?
 * Logic below assumes the mergeable buffer header is used.
 */
unsigned int mergeable_min_buf_len(struct virtnet_info *vi, struct virtqueue *vq);


int virtnet_find_vqs(struct virtnet_info *vi);


int virtnet_alloc_queues(struct virtnet_info *vi);


int init_vqs(struct virtnet_info *vi);

bool virtnet_validate_features(struct virtio_device *vdev);


#define MIN_MTU ETH_MIN_MTU
#define MAX_MTU ETH_MAX_MTU

void remove_vq_common(struct virtnet_info *vi);


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

struct virtnet_stat_desc {
    char desc[ETH_GSTRING_LEN];
    size_t offset;
};


#define VIRTNET_SQ_STAT(m)	offsetof(struct virtnet_sq_stats, m)
#define VIRTNET_RQ_STAT(m)	offsetof(struct virtnet_rq_stats, m)


#define VIRTNET_SQ_STATS_LEN	ARRAY_SIZE(virtnet_sq_stats_desc)
#define VIRTNET_RQ_STATS_LEN	ARRAY_SIZE(virtnet_rq_stats_desc)

/* FIXME: MTU in config. */
#define GOOD_PACKET_LEN (ETH_HLEN + VLAN_HLEN + ETH_DATA_LEN)
#define GOOD_COPY_LEN	128

#define VIRTNET_RX_PAD (NET_IP_ALIGN + NET_SKB_PAD)

/* Amount of XDP headroom to prepend to packets for use by xdp_adjust_head */
#define VIRTIO_XDP_HEADROOM 256

/* Separating two types of XDP xmit */
#define VIRTIO_XDP_TX		BIT(0)
#define VIRTIO_XDP_REDIR	BIT(1)

