import core.stdc.config : c_ulong;

import mutex_h : BITS_PER_LONG;
import net_device_h : net_device;
import napi_struct_h : rb_node, ktime_t;
import list_head_h : list_head;
import kobject_h : refcount_t;

import std.bitmanip : bitfields;

struct sock;
struct sec_path;
struct nf_bridge_info;


static if (BITS_PER_LONG > 32)
    enum NET_SKBUFF_DATA_USES_OFFSET = 1;

static if (is(typeof(NET_SKBUFF_DATA_USES_OFFSET)))
    alias sk_buff_data_t = uint;
else
    // unsigned char
    alias sk_buff_data_t = ubyte*;

version(CONFIG_CPU_BIG_ENDIAN) {
    enum __BIG_ENDIAN = 4321;
    enum __BYTE_ORDER = __BIG_ENDIAN;
}
else
{
    enum __LITTLE_ENDIAN = 1234;
    enum __BYTE_ORDER = __LITTLE_ENDIAN;
}



static if (__BYTE_ORDER == __LITTLE_ENDIAN)
    enum __LITTLE_ENDIAN_BITFIELD;
else static if (__BYTE_ORDER == __BIG_ENDIAN)
    enum __BIG_ENDIAN_BITFIELD;
else
    static assert(0, "sorry, weird endianness on this box");



struct sk_buff {
    union {
        struct {
            sk_buff		*next;
            sk_buff		*prev;

            union {
                net_device	*dev;
                c_ulong		dev_scratch;
            }
        }
        rb_node		rbnode; /* used in netem, ip4 defrag, and tcp stack */
        list_head	list;
    }

    union {
        sock		*sk;
        int			ip_defrag_offset;
    }

    union {
        ktime_t		tstamp;
        ulong		skb_mstamp;
    }
    /*
     * This is the control buffer. It is free to use for every
     * layer. Please put your private variables there. If you
     * want to keep them across layers you have to do a skb_clone()
     * first. This is owned by whoever has the skb queued ATM.
     */
    align(8) char[48] cb;

    union {
        struct {
            c_ulong	_skb_refdst;
            void function(sk_buff *skb)destructor;
        }
        list_head	tcp_tsorted_anchor;
    }

    version (CONFIG_XFRM)
    {
        sec_path	*sp;
    }
    version (CONFIG_NF_CONNTRACK)
    {
        c_ulong		 _nfct;
    }
    else version(CONFIG_NF_CONNTRACK_MODULE)
    {
        c_ulong _nfct;
    }

//#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
    version(CONFIG_BRIDGE_NETFILTER) {
        nf_bridge_info	*nf_bridge;
    }
    uint len;
    uint data_len;
    ushort mac_len;
    ushort hdr_len;

    /* Following fields are _not_ copied in __copy_skb_header()
     * Note that queue_mapping is here mostly to fill a hole.
     */
    ushort queue_mapping;

/* if you move cloned around you also must adapt those constants */
    static if (is(typeof(__BIG_ENDIAN_BITFIELD)))
        enum CLONED_MASK = 1 << 7;
    else
        enum CLONED_MASK = 1;

    static private pragma(inline, true)
    size_t CLONED_OFFSET()
    {
        return sk_buff.__cloned_offset.offsetof;
    }

    ubyte[0] __cloned_offset;

    mixin(bitfields!(
        ubyte,  "cloned", 1,
        ubyte,  "nohdr", 1,
        ubyte,  "fclone", 2,
        ubyte,  "peeked", 1,
        ubyte,  "head_frag", 1,
        ubyte,  "xmit_more", 1,
        ubyte,  "pfmemalloc", 1
                ));

    /* fields enclosed in headers_start/headers_end are copied
     * using a single memcpy() in __copy_skb_header()
     */
    /* private: */
    uint[0] headers_start;
    /* public: */

    /* if you move pkt_type around you also must adapt those constants */
    static if (is(typeof(__BIG_ENDIAN_BITFIELD)))
        enum PKT_TYPE_MAX = 7 << 5;
    else
        enum PKT_TYPE_MAX = 7;

    static private pragma(inline, true)
    size_t PKT_TYPE_OFFSET()
    {
        return sk_buff.__pkt_type_offset.offsetof;
    }

    ubyte[0] __pkt_type_offset;

    static private string getBitFields() {
        static string evalVersion(string versionSwitch, string str)()
        {
            mixin(q{version(} ~ versionSwitch ~ q{)
                    return str;
                    else
                    return "";
                    });
        }

        static int evalVersionBitsSize()
        {
            int sz = 8;
            int rem = 16 - sz;

            version(CONFIG_IPV6_NDISC_NODETYPE)
            {
                sz += 2;
            }
            version(CONFIG_NET_SWITCHDEV)
            {
                sz += 2;
            }
            version(CONFIG_NET_CLS_ACT)
            {
                sz += 4;
            }
            version(CONFIG_TLS_DEVICE)
            {
                sz += 1;
            }
            return rem - sz % 8;
        }
        enum emptyBitsSize = evalVersionBitsSize();

        enum s = q{
            mixin(bitfields!(
                //ubyte, "pkt_type", 3,
                //ubyte, "ignore_df", 1,
                //ubyte, "nf_trace", 1,
                //ubyte, "ip_summed", 2,
                //ubyte, "ooo_okay", 1,

                //ubyte, "l4_hash", 1,
                //ubyte, "sw_hash", 1,
                //ubyte, "wifi_acked_valid", 1,
                //ubyte, "wifi_acked", 1,
                //ubyte, "no_fcs", 1,
                //[> Indicates the inner headers are valid in the skbuff. <]
                //ubyte, "encapsulation", 1,
                //ubyte, "encap_hdr_csum", 1,
                //ubyte, "csum_valid", 1,

                ubyte, "csum_complete_sw", 1,
                ubyte, "csum_level", 2,
                ubyte, "csum_not_inet", 1,
                ubyte, "dst_pending_confirm", 1,
                } ~ evalVersion!("CONFIG_IPV6_NDISC_NODETYPE",
                                 q{
                                   ubyte, "ndisc_nodetype", 2,
                                 })
                ~ q{
                ubyte, "ipvs_property", 1,
                ubyte, "inner_protocol_type", 1,
                ubyte, "remcsum_offload", 1,
                } ~ evalVersion!("CONFIG_NET_SWITCHDEV",
                                 q{
                                   ubyte, "offload_fwd_mark", 1,
                                   ubyte, "offload_mr_fwd_mark", 1,
                                 })
                ~ evalVersion!("CONFIG_NET_CLS_ACT",
                               q{
                                 ubyte, "tc_skip_classify", 1,
                                 ubyte, "tc_at_ingress", 1,
                                 ubyte, "tc_redirected", 1,
                                 ubyte, "tc_from_ingress", 1,
                               })
                ~ evalVersion!("CONFIG_TLS_DEVICE",
                               q{
                                 ubyte, "decrypted", 1,
                               })
                ~ q{ubyte, "", } ~ emptyBitsSize.stringof ~ q{
            ));
        };

        return s;
    }

    mixin(bitfields!(
        ubyte, "pkt_type", 3,
        ubyte, "ignore_df", 1,
        ubyte, "nf_trace", 1,
        ubyte, "ip_summed", 2,
        ubyte, "ooo_okay", 1,

        ubyte, "l4_hash", 1,
        ubyte, "sw_hash", 1,
        ubyte, "wifi_acked_valid", 1,
        ubyte, "wifi_acked", 1,
        ubyte, "no_fcs", 1,
        /* Indicates the inner headers are valid in the skbuff. */
        ubyte, "encapsulation", 1,
        ubyte, "encap_hdr_csum", 1,
        ubyte, "csum_valid", 1,
        ));
    mixin(getBitFields());


    version(CONFIG_NET_SCHED)
    {
        ushort			tc_index;	/* traffic control index */
    }

    union {
        uint csum;
        struct {
            ushort csum_start;
            ushort csum_offset;
        }
    }

    uint			priority;
    int			skb_iif;
    uint			hash;
    ushort vlan_proto;
    ushort			vlan_tci;

    version(CONFIG_NET_RX_BUSY_POLL)
    {
        union {
            uint	napi_id;
            uint	sender_cpu;
        }
    }
    else version(CONFIG_XPS)
    {
        union {
            uint	napi_id;
            uint	sender_cpu;
        }

    }
    version(CONFIG_NETWORK_SECMARK)
    {
        uint		secmark;
    }

    union {
        uint		mark;
        uint		reserved_tailroom;
    }

    union {
        ushort		inner_protocol;
        ubyte		inner_ipproto;
    };

    ushort			inner_transport_header;
    ushort			inner_network_header;
    ushort			inner_mac_header;

    ushort			protocol;
    ushort			transport_header;
    ushort			network_header;
    ushort			mac_header;

    /* private: */
    uint[0] headers_end;
    /* public: */

    /* These elements must be at the end, see alloc_skb() for details.  */
    sk_buff_data_t		tail;
    sk_buff_data_t		end;

    ubyte *head;
    ubyte *data;

    uint truesize;
    refcount_t		users;
}
