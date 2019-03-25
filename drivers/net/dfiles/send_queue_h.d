import napi_struct_h : napi_struct;
import virtio_h : virtqueue;
import mutex_h : BITS_PER_LONG;
import lockdep_map_h : lockdep_map;
import core.stdc.config : c_ulong;

enum PAGE_SHIFT = 12;
//#ifdef __ASSEMBLY__
enum PAGE_SIZE = (1 << PAGE_SHIFT);
//#else
//#define PAGE_SIZE	(1UL << PAGE_SHIFT)
//#endif
static if ((65536/PAGE_SIZE + 1) < 16) {
    enum MAX_SKB_FRAGS = 16UL;
}
else
{
    enum MAX_SKB_FRAGS = (65536/PAGE_SIZE + 1);
}

version(CONFIG_ARCH_DMA_ADDR_T_64BIT) {
    alias dma_addr_t = ulong;
}
else {
    alias dma_addr_t = uint;
}

struct scatterlist {
    c_ulong page_link;
    uint offset;
    uint length;
    dma_addr_t dma_address;
    version(CONFIG_NEED_SG_DMA_LENGTH) {
        uint	dma_length;
    }
}

struct seqcount {
    uint sequence;
    version(CONFIG_DEBUG_LOCK_ALLOC) {
        lockdep_map dep_map;
    }
}

alias seqcount_t = seqcount;

struct u64_stats_sync {
    static if (BITS_PER_LONG == 32) {
        version(CONFIG_SMP) {
            seqcount_t seq;
        }
    }
}

struct virtnet_sq_stats {
    /* TODO on 32bit */
    //static if (BITS_PER_LONG == 32)
    //{
        //u64_stats_sync syncp;
    //}
    //else
    //{
        //u64_stats_sync[0] syncp;
    //}
    u64_stats_sync[0] syncp;
    ulong packets;
    ulong bytes;
    ulong xdp_tx;
    ulong xdp_tx_drops;
    ulong kicks;
}

struct send_queue {
    virtqueue *vq;

    scatterlist[MAX_SKB_FRAGS + 2] sg;

    char[40] name;

    virtnet_sq_stats stats;

    napi_struct napi;
}
