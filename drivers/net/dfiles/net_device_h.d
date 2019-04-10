import core.stdc.config : c_ulong;
import std.bitmanip : bitfields;
import list_head_h;
import mutex_h : atomic_long_t;
import spinlock_types_h : atomic_t, spinlock_t;
import device_h : device, timer_list;
import cache_h;
import link_state_h : reg_state_alias, rtnl_link_state_alias;
import bpf_prog_h : rcu_head, bpf_prog;
import uapi_h : IFNAMSIZ;

enum GSO_MAX_SIZE = 65536;
enum GSO_MAX_SEGS = 65535;
enum MAX_ADDR_LEN = 32;
enum TC_MAX_QUEUE = 16;
enum TC_BITMASK = 15;

alias netdev_features_t = ulong;

struct dev_ifalias;
struct iw_handler_def;
struct iw_public_data;
struct net_device_ops;
struct ethtool_ops;
alias ethtool_ops_alias = ethtool_ops;
struct switchdev_ops;
struct l3mdev_ops;
struct ndisc_ops;
alias ndisc_ops_alias = ndisc_ops;
struct xfrmdev_ops;
struct tlsdev_ops;
struct header_ops;
alias header_ops_alias = header_ops;
struct kset;
struct vlan_info;
struct dsa_port;
struct tipc_bearer;
struct in_device;
struct dn_dev;
struct inet6_dev;
struct wireless_dev;
struct wpan_dev;
struct mpls_dev;
struct netdev_rx_queue;
struct rx_handler_func_t;
struct mini_Qdisc;
struct netdev_queue;
struct cpu_rmap;
struct Qdisc;
struct xps_dev_maps;
struct nf_hook_entries;
struct netpoll_info;
struct garp_port;
struct mrp_port;
struct attribute_group;
struct rtnl_link_ops;
alias rtnl_link_ops_alias = rtnl_link_ops;
struct dcbnl_rtnl_ops;
struct netprio_map;
struct phy_device;
struct sfp_bus;
alias sfp_bus_alias = sfp_bus;
struct lock_class_key;
struct pcpu_lstats;
struct pcpu_sw_netstats;
struct pcpu_dstats;
struct pcpu_vstats;
struct net;
alias net_alias = net;

struct netdev_hw_addr {
    list_head	list;
    ubyte[MAX_ADDR_LEN] addr;
    ubyte type;
//#define NETDEV_HW_ADDR_T_LAN		1
//#define NETDEV_HW_ADDR_T_SAN		2
//#define NETDEV_HW_ADDR_T_SLAVE		3
//#define NETDEV_HW_ADDR_T_UNICAST	4
//#define NETDEV_HW_ADDR_T_MULTICAST	5
	bool			global_use;
	int			sync_cnt;
	int			refcount;
	int			synced;
	rcu_head		d_alias_rcu_head;
}

struct netdev_tc_txq {
    ushort count;
    ushort offset;
}

struct adj_list_alias {
    list_head upper;
    list_head lower;
}

struct possible_net_t {
    version(CONFIG_NET_NS) {
        net_alias *net;
    }
}

struct netdev_hw_addr_list {
    list_head	list;
    int			count;
}

struct net_device_stats {
    c_ulong	rx_packets;
    c_ulong	tx_packets;
    c_ulong	rx_bytes;
    c_ulong	tx_bytes;
    c_ulong	rx_errors;
    c_ulong	tx_errors;
    c_ulong	rx_dropped;
    c_ulong	tx_dropped;
    c_ulong	multicast;
    c_ulong	collisions;
    c_ulong	rx_length_errors;
    c_ulong	rx_over_errors;
    c_ulong	rx_crc_errors;
    c_ulong	rx_frame_errors;
    c_ulong	rx_fifo_errors;
    c_ulong	rx_missed_errors;
    c_ulong	tx_aborted_errors;
    c_ulong	tx_carrier_errors;
    c_ulong	tx_fifo_errors;
    c_ulong	tx_heartbeat_errors;
    c_ulong	tx_window_errors;
    c_ulong	rx_compressed;
    c_ulong	tx_compressed;
}

struct net_device {
    char[IFNAMSIZ] name;

    hlist_node name_hlist;

    dev_ifalias  *ifalias;

    c_ulong mem_end;
    c_ulong mem_start;
    c_ulong base_addr;
    int irq;


    c_ulong		state;

    list_head	dev_list;
    list_head	napi_list;
    list_head	unreg_list;
    list_head	close_list;
    list_head	ptype_all;
    list_head	ptype_specific;

    adj_list_alias adj_list;

    netdev_features_t	features;
    netdev_features_t	hw_features;
    netdev_features_t	wanted_features;
    netdev_features_t	vlan_features;
    netdev_features_t	hw_enc_features;
    netdev_features_t	mpls_features;
    netdev_features_t	gso_partial_features;

    int ifindex;
    int group;

    net_device_stats stats;

    atomic_long_t rx_dropped;
    atomic_long_t tx_dropped;
    atomic_long_t rx_nohandler;

    atomic_t carrier_up_count;
    atomic_t carrier_down_count;

    version(CONFIG_WIRELESS_EXT) {
        const iw_handler_def *wireless_handlers;
        iw_public_data	*wireless_data;
    }

    const(net_device_ops) * netdev_ops;
    const(ethtool_ops_alias) *ethtool_ops;

    version(CONFIG_NET_SWITCHDEV) {
        const switchdev_ops *switchdev_ops;
    }

    version(CONFIG_NET_L3_MASTER_DEV) {
        const l3mdev_ops	*l3mdev_ops;
    }

    version(CONFIG_IPV6) {
        const ndisc_ops_alias *ndisc_ops;
    }

    version(CONFIG_XFRM_OFFLOAD) {
        const xfrmdev_ops *xfrmdev_ops;
    }

    version(CONFIG_TLS_DEVICE) {
        const tlsdev_ops *tlsdev_ops;
    }

    const header_ops_alias *header_ops;

    uint		flags;
    uint		priv_flags;

    ushort		gflags;
    ushort		padded;

    ubyte operstate;
    ubyte link_mode;

    ubyte if_port;
    ubyte dma;

    uint		mtu;
    uint		min_mtu;
    uint		max_mtu;
    ushort		type;
    ushort		hard_header_len;
    ubyte min_header_len;

    ushort		needed_headroom;
    ushort		needed_tailroom;

    ubyte[MAX_ADDR_LEN] perm_addr;
    ubyte addr_assign_type;
    ubyte addr_len;

    ushort		neigh_priv_len;
    ushort          dev_id;
    ushort          dev_port;

    spinlock_t		addr_list_lock;

    ubyte name_assign_type;
    bool			uc_promisc;

    netdev_hw_addr_list uc;
    netdev_hw_addr_list mc;
    netdev_hw_addr_list dev_addrs;

    version(CONFIG_SYSFS) {
        kset		*queues_kset;
    }

    uint		promiscuity;
    uint		allmulti;

    version(CONFIG_VLAN_8021Q) {
        vlan_info *vlan_info;
    }

    version(CONFIG_NET_DSA) {
        dsa_port		*dsa_ptr;
    }

    version(CONFIG_TIPC) {
        tipc_bearer *tipc_ptr;
    }

    version(CONFIG_IRDA) {
        void *atalk_ptr;
    }
    else {
        version(CONFIG_ATALK) {
            void *atalk_ptr;
        }
    }

    in_device *ip_ptr;

    version(CONFIG_DECNET) {
        dn_dev *dn_ptr;
    }

    inet6_dev *ip6_ptr;

    version(CONFIG_AX25) {
        void *ax25_ptr;
    }

    wireless_dev	*ieee80211_ptr;
    wpan_dev		*ieee802154_ptr;

    version(CONFIG_MPLS_ROUTING) {
        mpls_dev *mpls_ptr;
    }

    ubyte *dev_addr;

    netdev_rx_queue *_rx;
    uint		num_rx_queues;
    uint		real_num_rx_queues;

    bpf_prog *xdp_prog;
    c_ulong gro_flush_timeout;
    rx_handler_func_t *rx_handler;
    void *rx_handler_data;

    version(CONFIG_NET_CLS_ACT) {
        mini_Qdisc *miniq_ingress;
    }

    netdev_queue *ingress_queue;

    version(CONFIG_NETFILTER_INGRESS) {
        nf_hook_entries *nf_hooks_ingress;
    }

    ubyte[MAX_ADDR_LEN] broadcast;

    version(CONFIG_RFS_ACCEL) {
        cpu_rmap		*rx_cpu_rmap;
    }

    hlist_node	index_hlist;

    mixin(____cacheline_aligned_in_smp ~ "netdev_queue *_tx;");
    //netdev_queue *_tx;

    uint		num_tx_queues;
    uint		real_num_tx_queues;
    Qdisc		*qdisc;

    version(CONFIG_NET_SCHED) {
        hlist_head[1 << 4] qdisc_hash;
    }

    uint tx_queue_len;
    spinlock_t tx_global_lock;
    int watchdog_timeo;

    version(CONFIG_XPS) {
        xps_dev_maps *xps_cpus_map;
        xps_dev_maps *xps_rxqs_map;
    }

    version(CONFIG_NET_CLS_ACT) {
        mini_Qdisc *miniq_egress;
    }

    timer_list	watchdog_timer;

    int *pcpu_refcnt;
    list_head	todo_list;

    list_head	link_watch_list;

    mixin(bitfields!(reg_state_alias, "reg_state", 8));

    bool dismantle;

    mixin(bitfields!(
          rtnl_link_state_alias, "rtnl_link_state", 16
            ));

    bool needs_free_netdev;
    void function(net_device *dev) priv_destructor;

    version(CONFIG_NETPOLL) {
        netpoll_info *npinfo;
    }

    possible_net_t			nd_net;

    union {
        void *ml_priv;
        pcpu_lstats *lstats;
        pcpu_sw_netstats *tstats;
        pcpu_dstats *dstats;
        pcpu_vstats *vstats;
    }

    version(CONFIG_GARP) {
        garp_port *garp_port;
    }
    version(CONFIG_MRP) {
        mrp_port *mrp_port;
    }

    device dev;
    const attribute_group*[4] sysfs_groups;
    const(attribute_group) *sysfs_rx_queue_group;

    const rtnl_link_ops_alias *rtnl_link_ops;

    uint gso_max_size;
    ushort gso_max_segs;

    version(CONFIG_DCB) {
        const dcbnl_rtnl_ops *dcbnl_ops;
    }

    short num_tc;
    netdev_tc_txq[TC_MAX_QUEUE] tc_to_txq;
    ubyte[TC_BITMASK + 1] prio_tc_map;

    version(CONFIG_FCOE) {
        uint fcoe_ddp_xid;
    }

    version(CONFIG_CGROUP_NET_PRIO) {
        netprio_map *priomap;
    }

    phy_device	*phydev;
    sfp_bus_alias		*sfp_bus;
    lock_class_key	*qdisc_tx_busylock;
    lock_class_key	*qdisc_running_key;
    bool proto_down;

    mixin(bitfields!(
            uint, "wol_enabled", 1,
            uint, "", 7
         ));
}



struct bpf_prog_offload_ops;
struct xdp_umem;

struct xsk {
    xdp_umem *umem; /* out for query*/
    ushort queue_id; /* in for query */
}

enum bpf_netdev_command {
	/* Set or clear a bpf program used in the earliest stages of packet
	 * rx. The prog will have been loaded as BPF_PROG_TYPE_XDP. The callee
	 * is responsible for calling bpf_prog_put on any old progs that are
	 * stored. In case of error, the callee need not release the new prog
	 * reference, but on success it takes ownership and must bpf_prog_put
	 * when it is no longer used.
	 */
	XDP_SETUP_PROG,
	XDP_SETUP_PROG_HW,
	XDP_QUERY_PROG,
	XDP_QUERY_PROG_HW,
	/* BPF program for offload callbacks, invoked at program load time. */
	BPF_OFFLOAD_VERIFIER_PREP,
	BPF_OFFLOAD_TRANSLATE,
	BPF_OFFLOAD_DESTROY,
	BPF_OFFLOAD_MAP_ALLOC,
	BPF_OFFLOAD_MAP_FREE,
	XDP_QUERY_XSK_UMEM,
	XDP_SETUP_XSK_UMEM,
};
struct bpf_offloaded_map;

enum NETLINK_MAX_COOKIE_LEN = 20;

struct nlattr {
    ushort nla_len;
    ushort nla_type;
}

struct netlink_ext_ack {
    const char *_msg;
    const nlattr *bad_attr;
    ubyte[NETLINK_MAX_COOKIE_LEN] cookie;
    ubyte cookie_len;
}


struct netdev_bpf {
    bpf_netdev_command command;
    union {
        /* XDP_SETUP_PROG */
        struct {
            uint flags;
            bpf_prog *prog;
            netlink_ext_ack *extack;
        };
        /* XDP_QUERY_PROG, XDP_QUERY_PROG_HW */
        struct {
            uint prog_id;
            /* flags with which program was installed */
            uint prog_flags;
        };
        /* BPF_OFFLOAD_VERIFIER_PREP */
        struct {
            bpf_prog *prog_1;
            const bpf_prog_offload_ops *ops; /* callee set */
        };
        /* BPF_OFFLOAD_TRANSLATE, BPF_OFFLOAD_DESTROY */
        struct {
            bpf_prog *prog_2;
        };
        /* BPF_OFFLOAD_MAP_ALLOC, BPF_OFFLOAD_MAP_FREE */
        struct {
            bpf_offloaded_map *offmap;
        };
        /* XDP_QUERY_XSK_UMEM, XDP_SETUP_XSK_UMEM */
        xsk xsk_struct;
    };
};


pragma(msg, "sizenetdev: ", netdev_bpf.sizeof);



enum gogu{
	NETIF_F_SG_BIT,			/* Scatter/gather IO. */
	NETIF_F_IP_CSUM_BIT,		/* Can checksum TCP/UDP over IPv4. */
	__UNUSED_NETIF_F_1,
	NETIF_F_HW_CSUM_BIT,		/* Can checksum all the packets. */
	NETIF_F_IPV6_CSUM_BIT,		/* Can checksum TCP/UDP over IPV6 */
	NETIF_F_HIGHDMA_BIT,		/* Can DMA to high memory. */
	NETIF_F_FRAGLIST_BIT,		/* Scatter/gather IO. */
	NETIF_F_HW_VLAN_CTAG_TX_BIT,	/* Transmit VLAN CTAG HW acceleration */
	NETIF_F_HW_VLAN_CTAG_RX_BIT,	/* Receive VLAN CTAG HW acceleration */
	NETIF_F_HW_VLAN_CTAG_FILTER_BIT,/* Receive filtering on VLAN CTAGs */
	NETIF_F_VLAN_CHALLENGED_BIT,	/* Device cannot handle VLAN packets */
	NETIF_F_GSO_BIT,		/* Enable software GSO. */
	NETIF_F_LLTX_BIT,		/* LockLess TX - deprecated. Please */
					/* do not use LLTX in new drivers */
	NETIF_F_NETNS_LOCAL_BIT,	/* Does not change network namespaces */
	NETIF_F_GRO_BIT,		/* Generic receive offload */
	NETIF_F_LRO_BIT,		/* large receive offload */

	/**/NETIF_F_GSO_SHIFT,		/* keep the order of SKB_GSO_* bits */
	NETIF_F_TSO_BIT			/* ... TCPv4 segmentation */
		= NETIF_F_GSO_SHIFT,
	NETIF_F_GSO_ROBUST_BIT,		/* ... ->SKB_GSO_DODGY */
	NETIF_F_TSO_ECN_BIT,		/* ... TCP ECN support */
	NETIF_F_TSO_MANGLEID_BIT,	/* ... IPV4 ID mangling allowed */
	NETIF_F_TSO6_BIT,		/* ... TCPv6 segmentation */
	NETIF_F_FSO_BIT,		/* ... FCoE segmentation */
	NETIF_F_GSO_GRE_BIT,		/* ... GRE with TSO */
	NETIF_F_GSO_GRE_CSUM_BIT,	/* ... GRE with csum with TSO */
	NETIF_F_GSO_IPXIP4_BIT,		/* ... IP4 or IP6 over IP4 with TSO */
	NETIF_F_GSO_IPXIP6_BIT,		/* ... IP4 or IP6 over IP6 with TSO */
	NETIF_F_GSO_UDP_TUNNEL_BIT,	/* ... UDP TUNNEL with TSO */
	NETIF_F_GSO_UDP_TUNNEL_CSUM_BIT,/* ... UDP TUNNEL with TSO & CSUM */
	NETIF_F_GSO_PARTIAL_BIT,	/* ... Only segment inner-most L4
					 *     in hardware and all other
					 *     headers in software.
					 */
	NETIF_F_GSO_TUNNEL_REMCSUM_BIT, /* ... TUNNEL with TSO & REMCSUM */
	NETIF_F_GSO_SCTP_BIT,		/* ... SCTP fragmentation */
	NETIF_F_GSO_ESP_BIT,		/* ... ESP with TSO */
	NETIF_F_GSO_UDP_BIT,		/* ... UFO, deprecated except tuntap */
	NETIF_F_GSO_UDP_L4_BIT,		/* ... UDP payload GSO (not UFO) */
	/**/NETIF_F_GSO_LAST =		/* last bit, see GSO_MASK */
		NETIF_F_GSO_UDP_L4_BIT,

	NETIF_F_FCOE_CRC_BIT,		/* FCoE CRC32 */
	NETIF_F_SCTP_CRC_BIT,		/* SCTP checksum offload */
	NETIF_F_FCOE_MTU_BIT,		/* Supports max FCoE MTU, 2158 bytes*/
	NETIF_F_NTUPLE_BIT,		/* N-tuple filters supported */
	NETIF_F_RXHASH_BIT,		/* Receive hashing offload */
	NETIF_F_RXCSUM_BIT,		/* Receive checksumming offload */
	NETIF_F_NOCACHE_COPY_BIT,	/* Use no-cache copyfromuser */
	NETIF_F_LOOPBACK_BIT,		/* Enable loopback */
	NETIF_F_RXFCS_BIT,		/* Append FCS to skb pkt data */
	NETIF_F_RXALL_BIT,		/* Receive errored frames too */
	NETIF_F_HW_VLAN_STAG_TX_BIT,	/* Transmit VLAN STAG HW acceleration */
	NETIF_F_HW_VLAN_STAG_RX_BIT,	/* Receive VLAN STAG HW acceleration */
	NETIF_F_HW_VLAN_STAG_FILTER_BIT,/* Receive filtering on VLAN STAGs */
	NETIF_F_HW_L2FW_DOFFLOAD_BIT,	/* Allow L2 Forwarding in Hardware */

	NETIF_F_HW_TC_BIT,		/* Offload TC infrastructure */
	NETIF_F_HW_ESP_BIT,		/* Hardware ESP transformation offload */
	NETIF_F_HW_ESP_TX_CSUM_BIT,	/* ESP with TX checksum offload */
	NETIF_F_RX_UDP_TUNNEL_PORT_BIT, /* Offload of RX port for UDP tunnels */
	NETIF_F_HW_TLS_TX_BIT,		/* Hardware TLS TX offload */
	NETIF_F_HW_TLS_RX_BIT,		/* Hardware TLS RX offload */

	NETIF_F_GRO_HW_BIT,		/* Hardware Generic receive offload */
	NETIF_F_HW_TLS_RECORD_BIT,	/* Offload TLS record */

	/*
	 * Add your fresh new feature above and remember to update
	 * netdev_features_strings[] in net/core/ethtool.c and maybe
	 * some feature mask #defines below. Please also describe it
	 * in Documentation/networking/netdev-features.txt.
	 */

	/**/NETDEV_FEATURE_COUNT
};


enum netdev_priv_flags {
	IFF_802_1Q_VLAN			= 1<<0,
	IFF_EBRIDGE			= 1<<1,
	IFF_BONDING			= 1<<2,
	IFF_ISATAP			= 1<<3,
	IFF_WAN_HDLC			= 1<<4,
	IFF_XMIT_DST_RELEASE		= 1<<5,
	IFF_DONT_BRIDGE			= 1<<6,
	IFF_DISABLE_NETPOLL		= 1<<7,
	IFF_MACVLAN_PORT		= 1<<8,
	IFF_BRIDGE_PORT			= 1<<9,
	IFF_OVS_DATAPATH		= 1<<10,
	IFF_TX_SKB_SHARING		= 1<<11,
	IFF_UNICAST_FLT			= 1<<12,
	IFF_TEAM_PORT			= 1<<13,
	IFF_SUPP_NOFCS			= 1<<14,
	IFF_LIVE_ADDR_CHANGE		= 1<<15,
	IFF_MACVLAN			= 1<<16,
	IFF_XMIT_DST_RELEASE_PERM	= 1<<17,
	IFF_L3MDEV_MASTER		= 1<<18,
	IFF_NO_QUEUE			= 1<<19,
	IFF_OPENVSWITCH			= 1<<20,
	IFF_L3MDEV_SLAVE		= 1<<21,
	IFF_TEAM			= 1<<22,
	IFF_RXFH_CONFIGURED		= 1<<23,
	IFF_PHONY_HEADROOM		= 1<<24,
	IFF_MACSEC			= 1<<25,
	IFF_NO_RX_HANDLER		= 1<<26,
	IFF_FAILOVER			= 1<<27,
	IFF_FAILOVER_SLAVE		= 1<<28,
};
