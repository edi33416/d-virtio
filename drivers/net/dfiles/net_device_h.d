import core.stdc.config : c_ulong;
import std.bitmanip : bitfields;
import list_head_h;
import mutex_h : atomic_long_t;
import spinlock_types_h : atomic_t, spinlock_t;
import device_h : device, timer_list;
import cache_h;
import uapi_h;
import link_state_h : reg_state_alias, rtnl_link_state_alias;

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
struct bpf_prog;
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

    const net_device_ops *netdev_ops;
    const ethtool_ops_alias *ethtool_ops;

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
    const attribute_group *sysfs_rx_queue_group;

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
