
align(1) struct virtio_net_ctrl_hdr {
    ubyte d_alias_class;
    ubyte cmd;
}

struct virtio_net_ctrl_mq {
    ushort virtqueue_pairs;
}

struct control_buf {
    virtio_net_ctrl_hdr hdr;
    ubyte status;
    virtio_net_ctrl_mq mq;
    ubyte promisc;
    ubyte allmulti;
    ushort vid;
    ulong offloads;
}
