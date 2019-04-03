import core.stdc.config : c_ulong, c_long;

static if(is(typeof(__GLIBC__)))
{
    enum isDefined(alias e) = is(typeof(e));

    static if(is(typeof(_NET_IF_H)) && is(typeof(__USE_MISC))) {
        enum __UAPI_DEF_IF_IFNAMSIZ = 0;
    }
    else {
        enum __UAPI_DEF_IF_IFNAMSIZ = 1;
    }

}
else
{
    static if (!is(typeof(__UAPI_DEF_IF_IFNAMSIZ)))
        enum __UAPI_DEF_IF_IFNAMSIZ = 1;


}

static if(is(typeof(__UAPI_DEF_IF_IFNAMSIZ)))
{
    enum IFNAMSIZ = 16;
}

struct ethtool_ringparam {
    uint	cmd;
    uint	rx_max_pending;
    uint	rx_mini_max_pending;
    uint	rx_jumbo_max_pending;
    uint	tx_max_pending;
    uint	rx_pending;
    uint	rx_mini_pending;
    uint	rx_jumbo_pending;
    uint	tx_pending;
};
enum ETHTOOL_FWVERS_LEN = 32;
enum ETHTOOL_BUSINFO_LEN = 32;
enum ETHTOOL_EROMVERS_LEN = 32;

struct ethtool_drvinfo {
    uint cmd;
    char[32]	driver;
    char[32]	d_alias_version;
    char[ETHTOOL_FWVERS_LEN]	fw_version;
    char[ETHTOOL_BUSINFO_LEN]	bus_info;
    char[ETHTOOL_EROMVERS_LEN]	erom_version;
    char[12]	reserved2;
    uint	n_priv_flags;
    uint	n_stats;
    uint	testinfo_len;
    uint	eedump_len;
    uint	regdump_len;
}

struct ethtool_channels {
	uint	cmd;
	uint	max_rx;
	uint	max_tx;
	uint	max_other;
	uint	max_combined;
	uint	rx_count;
	uint	tx_count;
	uint	other_count;
	uint	combined_count;
}

struct ethtool_stats {
	uint cmd;
	uint n_stats;
	ulong[0] data;
}

auto BITS_PER_TYPE(T)() {
    return T.sizeof * 8;
}

int __KERNEL_DIV_ROUND_UP(int n, int d) {
    return (n + d - 1) / (d);
}

struct ethtool_link_ksettings {
    ethtool_link_settings base;
    link_modes link;
}

pragma(msg, "sizeof ethtool_link_ksettings: ", ethtool_link_ksettings.sizeof);

struct link_modes {
	c_ulong[__KERNEL_DIV_ROUND_UP(__ETHTOOL_LINK_MODE_MASK_NBITS, c_long.sizeof * 8)] supported;
	c_ulong[__KERNEL_DIV_ROUND_UP(__ETHTOOL_LINK_MODE_MASK_NBITS, c_long.sizeof * 8)] advertising;
	c_ulong[__KERNEL_DIV_ROUND_UP(__ETHTOOL_LINK_MODE_MASK_NBITS, c_long.sizeof * 8)] lp_advertising;
}

pragma(msg, "sizeof link_modes:", link_modes.sizeof);

enum __ETHTOOL_LINK_MODE_MASK_NBITS = (ethtool_link_mode_bit_indices.__ETHTOOL_LINK_MODE_LAST + 1);

struct ethtool_link_settings {
	uint	cmd;
	uint	speed;
	ubyte	duplex;
	ubyte	port;
	ubyte	phy_address;
	ubyte	autoneg;
	ubyte	mdio_support;
	ubyte	eth_tp_mdix;
	ubyte	eth_tp_mdix_ctrl;
	ubyte	link_mode_masks_nwords;
	ubyte	transceiver;
	ubyte[3]	reserved1;
	uint[7]	reserved;
	uint[0]	link_mode_masks;
	/* layout of link_mode_masks fields:
	 * __u32 map_supported[link_mode_masks_nwords];
	 * __u32 map_advertising[link_mode_masks_nwords];
	 * __u32 map_lp_advertising[link_mode_masks_nwords];
	 */
}

pragma(msg, "sizeof ethtool_link_settings: ", ethtool_link_settings.sizeof);

enum ethtool_link_mode_bit_indices {
	ETHTOOL_LINK_MODE_10baseT_Half_BIT	= 0,
	ETHTOOL_LINK_MODE_10baseT_Full_BIT	= 1,
	ETHTOOL_LINK_MODE_100baseT_Half_BIT	= 2,
	ETHTOOL_LINK_MODE_100baseT_Full_BIT	= 3,
	ETHTOOL_LINK_MODE_1000baseT_Half_BIT	= 4,
	ETHTOOL_LINK_MODE_1000baseT_Full_BIT	= 5,
	ETHTOOL_LINK_MODE_Autoneg_BIT		= 6,
	ETHTOOL_LINK_MODE_TP_BIT		= 7,
	ETHTOOL_LINK_MODE_AUI_BIT		= 8,
	ETHTOOL_LINK_MODE_MII_BIT		= 9,
	ETHTOOL_LINK_MODE_FIBRE_BIT		= 10,
	ETHTOOL_LINK_MODE_BNC_BIT		= 11,
	ETHTOOL_LINK_MODE_10000baseT_Full_BIT	= 12,
	ETHTOOL_LINK_MODE_Pause_BIT		= 13,
	ETHTOOL_LINK_MODE_Asym_Pause_BIT	= 14,
	ETHTOOL_LINK_MODE_2500baseX_Full_BIT	= 15,
	ETHTOOL_LINK_MODE_Backplane_BIT		= 16,
	ETHTOOL_LINK_MODE_1000baseKX_Full_BIT	= 17,
	ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT	= 18,
	ETHTOOL_LINK_MODE_10000baseKR_Full_BIT	= 19,
	ETHTOOL_LINK_MODE_10000baseR_FEC_BIT	= 20,
	ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT = 21,
	ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT	= 22,
	ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT	= 23,
	ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT	= 24,
	ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT	= 25,
	ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT	= 26,
	ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT	= 27,
	ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT	= 28,
	ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT	= 29,
	ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT	= 30,
	ETHTOOL_LINK_MODE_25000baseCR_Full_BIT	= 31,
	ETHTOOL_LINK_MODE_25000baseKR_Full_BIT	= 32,
	ETHTOOL_LINK_MODE_25000baseSR_Full_BIT	= 33,
	ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT	= 34,
	ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT	= 35,
	ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT	= 36,
	ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT	= 37,
	ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT	= 38,
	ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT	= 39,
	ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT		= 40,
	ETHTOOL_LINK_MODE_1000baseX_Full_BIT	= 41,
	ETHTOOL_LINK_MODE_10000baseCR_Full_BIT	= 42,
	ETHTOOL_LINK_MODE_10000baseSR_Full_BIT	= 43,
	ETHTOOL_LINK_MODE_10000baseLR_Full_BIT	= 44,
	ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT	= 45,
	ETHTOOL_LINK_MODE_10000baseER_Full_BIT	= 46,
	ETHTOOL_LINK_MODE_2500baseT_Full_BIT	= 47,
	ETHTOOL_LINK_MODE_5000baseT_Full_BIT	= 48,

	ETHTOOL_LINK_MODE_FEC_NONE_BIT	= 49,
	ETHTOOL_LINK_MODE_FEC_RS_BIT	= 50,
	ETHTOOL_LINK_MODE_FEC_BASER_BIT	= 51,

	/* Last allowed bit for __ETHTOOL_LINK_MODE_LEGACY_MASK is bit
	 * 31. Please do NOT define any SUPPORTED_* or ADVERTISED_*
	 * macro for bits > 31. The only way to use indices > 31 is to
	 * use the new ETHTOOL_GLINKSETTINGS/ETHTOOL_SLINKSETTINGS API.
	 */

	__ETHTOOL_LINK_MODE_LAST
	  = ETHTOOL_LINK_MODE_FEC_BASER_BIT,
};



enum ethtool_stringset {
	ETH_SS_TEST		= 0,
	ETH_SS_STATS,
	ETH_SS_PRIV_FLAGS,
	ETH_SS_NTUPLE_FILTERS,
	ETH_SS_FEATURES,
	ETH_SS_RSS_HASH_FUNCS,
	ETH_SS_TUNABLES,
	ETH_SS_PHY_STATS,
	ETH_SS_PHY_TUNABLES,
};
