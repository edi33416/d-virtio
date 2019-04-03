import list_head_h;
import mod_devicetable_h;
import spinlock_types_h : spinlock_t;
import device_h : device;

struct cpumask;
struct vq_callback_t;
struct vringh_config_ops;
struct irq_affinity;

struct virtio_config_ops {
    void function(virtio_device *vdev, uint offset,
            void *buf, uint len) get;
    void function(virtio_device *vdev, uint offset,
            const void *buf, uint len) set;
    uint function(virtio_device *vdev) generation;
    ubyte function(virtio_device *vdev) get_status;
    void function(virtio_device *vdev, ubyte status) set_status;
    void function(virtio_device *vdev) reset;
    int function(virtio_device *, uint nvqs,
            virtqueue*[] vqs, vq_callback_t*[] callbacks,
            const(char *)[] names, const bool *ctx,
            irq_affinity *desc) find_vqs;
    void function(virtio_device *) del_vqs;
    ulong function(virtio_device *vdev) get_features;
    int function(virtio_device *vdev) finalize_features;
    const char * function(virtio_device *vdev) bus_name;
    int function(virtqueue *vq, const cpumask *cpu_mask) set_vq_affinity;
    const cpumask * function(virtio_device *vdev, int index) get_vq_affinity;
}

struct virtio_device {
    int index;
    bool failed;
    bool config_enabled;
    bool config_change_pending;
    spinlock_t config_lock;
    device dev;
    virtio_device_id id;
    const virtio_config_ops *config;
    const vringh_config_ops *vringh_config;
    list_head vqs;
    ulong features;
    void *priv;
}

struct virtqueue {
    list_head list;
    void function(virtqueue *vq) callback;
    const char *name;
    virtio_device *vdev;
    uint index;
    uint num_free;
    void *priv;
}

enum ETH_ALEN = 6;

align(1) struct virtio_net_config {
	/* The config defining mac address (if VIRTIO_NET_F_MAC) */
	ubyte[ETH_ALEN] mac;
	/* See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
	ushort status;
	/* Maximum number of each of transmit and receive queues;
	 * see VIRTIO_NET_F_MQ and VIRTIO_NET_CTRL_MQ.
	 * Legal values are between 1 and 0x8000
	 */
	ushort max_virtqueue_pairs;
	/* Default maximum transmit unit advice */
	ushort mtu;
	/*
	 * speed, in units of 1Mb. All values 0 to INT_MAX are legal.
	 * Any other value stands for unknown.
	 */
	uint speed;
	/*
	 * 0x00 - half duplex
	 * 0x01 - full duplex
	 * Any other value stands for unknown.
	 */
	ubyte duplex;
};



align(1) struct virtio_net_ctrl_mac {
    uint entries;
    //ubyte[ETH_ALEN][] macs; // Ce trebuia sa fie
    ubyte[0] macs;
}


pragma(msg, "size structura vietii:", virtio_net_ctrl_mac.sizeof);
