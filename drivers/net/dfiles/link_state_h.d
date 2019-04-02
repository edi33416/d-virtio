enum rtnl_link_state_alias {
    RTNL_LINK_INITIALIZED,
    RTNL_LINK_INITIALIZING,
}

enum reg_state_alias {
    NETREG_UNINITIALIZED=0,
    NETREG_REGISTERED,
    NETREG_UNREGISTERING,
    NETREG_UNREGISTERED,
    NETREG_RELEASED,
    NETREG_DUMMY,
}



struct rtnl_link_stats64 {
    ulong	rx_packets;		/* total packets received	*/
    ulong	tx_packets;		/* total packets transmitted	*/
    ulong	rx_bytes;		/* total bytes received 	*/
    ulong	tx_bytes;		/* total bytes transmitted	*/
    ulong	rx_errors;		/* bad packets received		*/
    ulong	tx_errors;		/* packet transmit problems	*/
    ulong	rx_dropped;		/* no space in linux buffers	*/
    ulong	tx_dropped;		/* no space available in linux	*/
    ulong	multicast;		/* multicast packets received	*/
    ulong	collisions;

    ulong	rx_length_errors;
    ulong	rx_over_errors;		/* receiver ring buff overflow	*/
    ulong	rx_crc_errors;		/* recved pkt with crc error	*/
    ulong	rx_frame_errors;	/* recv'd frame alignment error */
    ulong	rx_fifo_errors;		/* recv'r fifo overrun		*/
    ulong	rx_missed_errors;	/* receiver missed packet	*/

    ulong	tx_aborted_errors;
    ulong	tx_carrier_errors;
    ulong	tx_fifo_errors;
    ulong	tx_heartbeat_errors;
    ulong	tx_window_errors;

    ulong	rx_compressed;
    ulong	tx_compressed;

    ulong	rx_nohandler;		/* dropped, no handler found	*/
};
