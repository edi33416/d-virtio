import core.stdc.config : c_ulong;
import virtio_h : virtio_device, virtqueue;
import net_device_h : net_device;
import send_queue_h : send_queue;
import receive_queue_h : receive_queue;
import list_head_h : hlist_node;
import control_buf_h : control_buf;
import kobject_h : delayed_work;
import device_h : work_struct;

struct dstruct_failover;

struct dlang_virtnet_info {
    send_queue[] sq;
    receive_queue[] rq;
    virtnet_info* vi;
    ubyte[0] tmp;
}


struct virtnet_info {
    virtio_device *vdev;
    virtqueue *cvq;
    net_device *dev;
    send_queue *sq;
    receive_queue *rq;

    uint status;

    /* Max # of queue pairs supported by the device */
    ushort max_queue_pairs;

    /* # of queue pairs currently used by the driver */
    ushort curr_queue_pairs;

    /* # of XDP queue pairs currently used by the driver */
    ushort xdp_queue_pairs;

    /* I like... big packets and I cannot lie! */
    bool big_packets;

    /* Host will merge rx buffers for big packets (shake it! shake it!) */
    bool mergeable_rx_bufs;

    /* Has control virtqueue */
    bool has_cvq;

    /* Host can handle any s/g split between our header and packet data */
    bool any_header_sg;

    /* Packet virtio header size */
    ubyte hdr_len;

    /* Work struct for refilling if we run low on memory. */
    delayed_work refill;

    /* Work struct for config space updates */
    work_struct config_work;

    /* Does the affinity hint is set for virtqueues? */
    bool affinity_hint_set;

    /* CPU hotplug instances for online & dead */
    hlist_node node;
    hlist_node node_dead;

    control_buf *ctrl;

    /* Ethtool settings */
    ubyte duplex;
    uint speed;

    c_ulong guest_offloads;

    /* failover when STANDBY feature enabled */
    dstruct_failover *failover;
}
